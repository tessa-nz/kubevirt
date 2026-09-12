/*
 * This file is part of the KubeVirt project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright The KubeVirt Authors.
 */

package protection

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"filippo.io/age"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"golang.org/x/sys/unix"
)

// These owner-hierarchy ranges are reserved only when Hibernation is used.
// A collision is an error: the implementation never evicts an unknown object.
const (
	keyHandleBase = 0x814b0000
	nvHandleBase  = 0x014b0000
	consumedBit   = 1
)

type TPMStore struct {
	open      func() (transport.TPMCloser, error)
	lockPath  string
	ownerAuth []byte
	lock      sync.Mutex
}

// NewTPMStore supports an injected transport for emulator tests. Production uses
// NewNodeTPMStore; no simulator or software key fallback is used there.
func NewTPMStore(open func() (transport.TPMCloser, error), lockPath string, ownerAuth []byte) *TPMStore {
	return &TPMStore{open: open, lockPath: lockPath, ownerAuth: bytes.Clone(ownerAuth)}
}

func NewNodeTPMStore(lockPath string) *TPMStore {
	return NewTPMStore(func() (transport.TPMCloser, error) {
		if err := RequireProtectedMemory(); err != nil {
			return nil, err
		}
		return linuxtpm.Open("/dev/tpmrm0")
	}, lockPath, nil)
}

type tpmAttempt struct {
	t         transport.TPM
	binding   []byte
	keyHandle tpm2.TPMHandle
	nvHandle  tpm2.TPMHandle
	ownerAuth []byte
}

// The node-shared flock serializes multi-command TPM transactions across
// overlapping virt-handler processes during a DaemonSet rollout. The TPM alone
// serializes commands, but that does not make read/consume/create atomic.
func (s *TPMStore) transaction(attempt Attempt, run func(*tpmAttempt) error) error {
	binding, err := attempt.binding()
	if err != nil {
		return err
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.lockPath), 0700); err != nil {
		return err
	}
	fd, err := unix.Open(s.lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("open hibernation TPM lock: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	t, err := s.open()
	if err != nil {
		return fmt.Errorf("open hibernation TPM: %w", err)
	}
	defer t.Close()
	slot := uint32(binary.BigEndian.Uint16(binding))
	return run(&tpmAttempt{t: t, binding: binding, keyHandle: tpm2.TPMHandle(keyHandleBase | slot), nvHandle: tpm2.TPMHandle(nvHandleBase | slot), ownerAuth: s.ownerAuth})
}

func (a *tpmAttempt) owner() tpm2.AuthHandle {
	return tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Auth(a.ownerAuth))}
}

func (a *tpmAttempt) keyPublic() (*tpm2.ReadPublicResponse, error) {
	rsp, err := (tpm2.ReadPublic{ObjectHandle: a.keyHandle}).Execute(a.t)
	if errors.Is(err, tpm2.TPMRCHandle) {
		return nil, ErrMissing
	}
	if err != nil {
		return nil, err
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	attrs := pub.ObjectAttributes
	if pub.Type != tpm2.TPMAlgKeyedHash || pub.NameAlg != tpm2.TPMAlgSHA256 ||
		!attrs.FixedTPM || !attrs.FixedParent || !attrs.UserWithAuth || !attrs.NoDA ||
		attrs.Decrypt || attrs.SignEncrypt || !bytes.Equal(pub.AuthPolicy.Buffer, a.binding) {
		return nil, ErrIdentity
	}
	return rsp, nil
}

func (a *tpmAttempt) nvPublic() (*tpm2.NVReadPublicResponse, error) {
	rsp, err := (tpm2.NVReadPublic{NVIndex: a.nvHandle}).Execute(a.t)
	if errors.Is(err, tpm2.TPMRCHandle) {
		return nil, ErrMissing
	}
	if err != nil {
		return nil, err
	}
	pub, err := rsp.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	attrs := pub.Attributes
	if pub.NameAlg != tpm2.TPMAlgSHA256 || pub.DataSize != 8 || attrs.NT != tpm2.TPMNTOrdinary || !attrs.WriteDefine || attrs.WriteSTClear ||
		!attrs.OwnerRead || !attrs.OwnerWrite || !attrs.NoDA || attrs.AuthRead || attrs.AuthWrite ||
		!bytes.Equal(pub.AuthPolicy.Buffer, a.binding) {
		return nil, ErrIdentity
	}
	return rsp, nil
}

func (a *tpmAttempt) consumed() (bool, error) {
	pub, err := a.nvPublic()
	if err != nil {
		return false, err
	}
	rsp, err := (tpm2.NVRead{AuthHandle: a.owner(), NVIndex: tpm2.NamedHandle{Handle: a.nvHandle, Name: pub.NVName}, Size: 8}).Execute(a.t)
	if errors.Is(err, tpm2.TPMRCNVUninitialized) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(rsp.Data.Buffer) != 8 {
		return false, fmt.Errorf("invalid hibernation TPM consumption record")
	}
	value := binary.BigEndian.Uint64(rsp.Data.Buffer)
	if value != 0 && value != consumedBit {
		return false, ErrIdentity
	}
	return value == consumedBit, nil
}

func (a *tpmAttempt) writeConsumption(value uint64) error {
	pub, err := a.nvPublic()
	if err != nil {
		return err
	}
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, value)
	_, err = (tpm2.NVWrite{AuthHandle: a.owner(), NVIndex: tpm2.NamedHandle{Handle: a.nvHandle, Name: pub.NVName}, Data: tpm2.TPM2BMaxNVBuffer{Buffer: data}}).Execute(a.t)
	return err
}

func (a *tpmAttempt) lockConsumption() error {
	pub, err := a.nvPublic()
	if err != nil {
		return err
	}
	contents, err := pub.NVPublic.Contents()
	if err != nil {
		return err
	}
	if contents.Attributes.WriteLocked {
		return nil
	}
	_, err = (tpm2.NVWriteLock{AuthHandle: a.owner(), NVIndex: tpm2.NamedHandle{Handle: a.nvHandle, Name: pub.NVName}}).Execute(a.t)
	return err
}

func (a *tpmAttempt) createNV() error {
	_, err := (tpm2.NVDefineSpace{
		AuthHandle: a.owner(),
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: a.nvHandle, NameAlg: tpm2.TPMAlgSHA256, DataSize: 8,
			AuthPolicy: tpm2.TPM2BDigest{Buffer: a.binding},
			Attributes: tpm2.TPMANV{NT: tpm2.TPMNTOrdinary, OwnerRead: true, OwnerWrite: true, NoDA: true, WriteDefine: true},
		}),
	}).Execute(a.t)
	if err != nil {
		return err
	}
	return a.writeConsumption(0)
}

// An ephemeral primary salts parameter-encrypted TPM sessions. No private
// parameter is sent in clear on the physical TPM bus, and no private blob is
// exported to disk. Both transient objects are flushed before the call returns.
func (a *tpmAttempt) salt() (*tpm2.CreatePrimaryResponse, func(), error) {
	rsp, err := (tpm2.CreatePrimary{PrimaryHandle: a.owner(), InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}).Execute(a.t)
	if err != nil {
		return nil, nil, err
	}
	return rsp, func() { _, _ = (tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}).Execute(a.t) }, nil
}

func (a *tpmAttempt) createKey() error {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	payload := append(bytes.Clone(a.binding), []byte(identity.String())...)
	defer clear(payload)
	salt, closeSalt, err := a.salt()
	if err != nil {
		return err
	}
	defer closeSalt()
	saltPublic, err := salt.OutPublic.Contents()
	if err != nil {
		return err
	}
	rsp, err := (tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
			tpm2.Auth(a.ownerAuth), tpm2.Salted(salt.ObjectHandle, *saltPublic), tpm2.AESEncryption(128, tpm2.EncryptIn))},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: payload}),
		}},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
			AuthPolicy:       tpm2.TPM2BDigest{Buffer: a.binding},
			ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, UserWithAuth: true, NoDA: true},
		}),
	}).Execute(a.t)
	if err != nil {
		return fmt.Errorf("seal hibernation identity: %w", err)
	}
	defer func() { _, _ = (tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}).Execute(a.t) }()
	_, err = (tpm2.EvictControl{Auth: a.owner(), ObjectHandle: tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name}, PersistentHandle: a.keyHandle}).Execute(a.t)
	return err
}

func (a *tpmAttempt) unseal() (*PrivateKey, error) {
	pub, err := a.keyPublic()
	if err != nil {
		return nil, err
	}
	salt, closeSalt, err := a.salt()
	if err != nil {
		return nil, err
	}
	defer closeSalt()
	saltPublic, err := salt.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	rsp, err := (tpm2.Unseal{ItemHandle: tpm2.AuthHandle{Handle: a.keyHandle, Name: pub.Name,
		Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Salted(salt.ObjectHandle, *saltPublic), tpm2.AESEncryption(128, tpm2.EncryptOut))}}).Execute(a.t)
	if err != nil {
		return nil, fmt.Errorf("unseal hibernation identity: %w", err)
	}
	defer clear(rsp.OutData.Buffer)
	if len(rsp.OutData.Buffer) <= sha256BindingSize || !bytes.Equal(rsp.OutData.Buffer[:sha256BindingSize], a.binding) {
		return nil, ErrIdentity
	}
	identity, err := age.ParseX25519Identity(string(rsp.OutData.Buffer[sha256BindingSize:]))
	if err != nil {
		return nil, fmt.Errorf("TPM contains an invalid hibernation identity")
	}
	return &PrivateKey{PublicKey: PublicKey{ID: hex.EncodeToString(pub.Name.Buffer), Recipient: identity.Recipient().String()}, Identity: bytes.Clone(rsp.OutData.Buffer[sha256BindingSize:])}, nil
}

const sha256BindingSize = 32

func (s *TPMStore) Create(attempt Attempt) (result PublicKey, err error) {
	err = s.transaction(attempt, func(a *tpmAttempt) error {
		_, keyErr := a.keyPublic()
		if keyErr != nil && !errors.Is(keyErr, ErrMissing) {
			return keyErr
		}
		_, nvErr := a.nvPublic()
		if errors.Is(nvErr, ErrMissing) {
			if keyErr == nil {
				return fmt.Errorf("hibernation key has lost its consumption record")
			}
			if err := a.createNV(); err != nil {
				return err
			}
		} else if nvErr != nil {
			return nvErr
		}
		consumed, err := a.consumed()
		if err != nil {
			return err
		}
		if consumed {
			return ErrConsumed
		}
		if errors.Is(keyErr, ErrMissing) {
			if err := a.createKey(); err != nil {
				return err
			}
		}
		key, err := a.unseal()
		if err != nil {
			return err
		}
		defer key.Close()
		result = key.PublicKey
		return nil
	})
	return result, err
}

func (s *TPMStore) Open(attempt Attempt) (result *PrivateKey, err error) {
	err = s.transaction(attempt, func(a *tpmAttempt) error {
		consumed, err := a.consumed()
		if err != nil {
			return err
		}
		if consumed {
			return ErrConsumed
		}
		result, err = a.unseal()
		return err
	})
	return result, err
}

func (s *TPMStore) Consume(attempt Attempt) (fresh bool, err error) {
	err = s.transaction(attempt, func(a *tpmAttempt) error {
		if _, err := a.keyPublic(); err != nil {
			return err
		}
		consumed, err := a.consumed()
		if err != nil {
			return err
		}
		if consumed {
			return a.lockConsumption()
		}
		if err := a.writeConsumption(consumedBit); err != nil {
			return err
		}
		if err := a.lockConsumption(); err != nil {
			return err
		}
		consumed, err = a.consumed()
		if err != nil {
			return err
		}
		if !consumed {
			return fmt.Errorf("TPM did not confirm consumption")
		}
		fresh = true
		return nil
	})
	return fresh, err
}

func (s *TPMStore) Destroy(attempt Attempt) error { return s.destroy(attempt, false) }
func (s *TPMStore) Abandon(attempt Attempt) error { return s.destroy(attempt, true) }

func (s *TPMStore) destroy(attempt Attempt, unconsumed bool) error {
	return s.transaction(attempt, func(a *tpmAttempt) error {
		pub, keyErr := a.keyPublic()
		if keyErr != nil && !errors.Is(keyErr, ErrMissing) {
			return keyErr
		}
		nv, nvErr := a.nvPublic()
		if keyErr != nil && errors.Is(nvErr, ErrMissing) {
			return nil
		}
		if nvErr != nil {
			return nvErr
		}
		consumed, err := a.consumed()
		if err != nil {
			return err
		}
		if !consumed && !unconsumed {
			return ErrUnconsumed
		}
		if consumed && unconsumed {
			return ErrConsumed
		}
		// Delete and read back the sealed object before removing its NV record.
		// A crash between these commands can never expose the private identity.
		if keyErr == nil {
			_, err := (tpm2.EvictControl{Auth: a.owner(), ObjectHandle: tpm2.NamedHandle{Handle: a.keyHandle, Name: pub.Name}, PersistentHandle: a.keyHandle}).Execute(a.t)
			if err != nil {
				return err
			}
		}
		if _, err := a.keyPublic(); !errors.Is(err, ErrMissing) {
			if err == nil {
				return fmt.Errorf("TPM still holds the hibernation key")
			}
			return err
		}
		_, err = (tpm2.NVUndefineSpace{AuthHandle: a.owner(), NVIndex: tpm2.NamedHandle{Handle: a.nvHandle, Name: nv.NVName}}).Execute(a.t)
		if err != nil {
			return err
		}
		if _, err := a.nvPublic(); !errors.Is(err, ErrMissing) {
			if err == nil {
				return fmt.Errorf("TPM still holds the consumption record")
			}
			return err
		}
		return nil
	})
}
