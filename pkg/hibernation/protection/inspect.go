// SPDX-License-Identifier: Apache-2.0
package protection

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

type AttemptStatus struct {
	KeyPresent bool `json:"keyPresent"`
	NVPresent  bool `json:"nvPresent"`
	Consumed   bool `json:"consumed"`
}

func (s *TPMStore) Inspect(attempt Attempt) (out AttemptStatus, err error) {
	err = s.transaction(attempt, func(a *tpmAttempt) error {
		_, e := a.keyPublic()
		out.KeyPresent = e == nil
		if e != nil && !errors.Is(e, ErrMissing) {
			return e
		}
		_, e = a.nvPublic()
		out.NVPresent = e == nil
		if e != nil && !errors.Is(e, ErrMissing) {
			return e
		}
		if out.KeyPresent && !out.NVPresent {
			return fmt.Errorf("key has lost consumption record")
		}
		if out.NVPresent {
			out.Consumed, e = a.consumed()
			return e
		}
		return nil
	})
	return
}

// ProviderIdentity uses the deterministic owner primary's public Name. Clearing
// or replacing the TPM changes the owner seed and therefore this identity.
func (s *TPMStore) ProviderIdentity() (id string, err error) {
	err = s.transaction(Attempt{VMUID: "provider-identity", ID: "provider-identity"}, func(a *tpmAttempt) error {
		salt, closeSalt, e := a.salt()
		if e != nil {
			return e
		}
		defer closeSalt()
		h := sha256.Sum256(salt.Name.Buffer)
		id = "tpm2-sha256-" + hex.EncodeToString(h[:])
		return nil
	})
	return
}

// CheckInventory detects hibernation handles with missing ownership metadata.
// Other applications' handle ranges are neither read nor altered.
func (s *TPMStore) CheckInventory(attempts []Attempt) error {
	expected := map[tpm2.TPMHandle]bool{}
	for _, attempt := range attempts {
		binding, e := attempt.binding()
		if e != nil {
			return e
		}
		slot := uint32(binary.BigEndian.Uint16(binding))
		for _, base := range []uint32{keyHandleBase, nvHandleBase} {
			handle := tpm2.TPMHandle(base | slot)
			if expected[handle] {
				return fmt.Errorf("colliding ownership metadata")
			}
			expected[handle] = true
		}
		if _, e = s.Inspect(attempt); e != nil {
			return e
		}
	}
	return s.transaction(Attempt{VMUID: "inventory", ID: "inventory"}, func(a *tpmAttempt) error {
		for _, base := range []uint32{keyHandleBase, nvHandleBase} {
			next := base
		scan:
			for {
				r, e := (tpm2.GetCapability{Capability: tpm2.TPMCapHandles, Property: next, PropertyCount: 64}).Execute(a.t)
				if e != nil {
					return e
				}
				hs, e := r.CapabilityData.Data.Handles()
				if e != nil {
					return e
				}
				for _, h := range hs.Handle {
					if uint32(h)&0xffff0000 != base {
						break scan
					}
					if !expected[h] {
						return fmt.Errorf("TPM hibernation object lacks ownership metadata: 0x%08x", h)
					}
					next = uint32(h) + 1
				}
				if !r.MoreData || len(hs.Handle) == 0 {
					break
				}
			}
		}
		return nil
	})
}

// PersistentCapacity reports the TPM's currently available persistent slots.
func (s *TPMStore) PersistentCapacity() (available uint32, err error) {
	err = s.transaction(Attempt{VMUID: "capacity", ID: "capacity"}, func(a *tpmAttempt) error {
		result, e := (tpm2.GetCapability{Capability: tpm2.TPMCapTPMProperties, Property: uint32(tpm2.TPMPTHRPersistentAvail), PropertyCount: 1}).Execute(a.t)
		if e != nil {
			return e
		}
		props, e := result.CapabilityData.Data.TPMProperties()
		if e != nil {
			return e
		}
		for _, p := range props.TPMProperty {
			if p.Property == tpm2.TPMPTHRPersistentAvail {
				available = p.Value
				return nil
			}
		}
		return fmt.Errorf("TPM persistent capacity unavailable")
	})
	return
}
