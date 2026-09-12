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

// Package protection keeps hibernation keys and single-use state outside the
// state PVC, and prevents libvirt from reading mutable or unauthenticated data.
package protection

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

const Provider = "tpm2-persistent-age-x25519-v1"

var (
	ErrMissing    = errors.New("hibernation key is absent")
	ErrConsumed   = errors.New("hibernation attempt is already consumed")
	ErrUnconsumed = errors.New("refusing to destroy an unconsumed hibernation key")
	ErrIdentity   = errors.New("TPM object does not belong to this hibernation attempt")
)

type Attempt struct {
	VMUID string
	ID    string
}

func (a Attempt) binding() ([]byte, error) {
	if a.VMUID == "" || a.ID == "" || len(a.VMUID) > 128 || len(a.ID) > 128 {
		return nil, fmt.Errorf("VM UID and bounded attempt identity are required")
	}
	for _, value := range []string{a.VMUID, a.ID} {
		for _, char := range value {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return nil, fmt.Errorf("invalid hibernation identity")
			}
		}
	}
	sum := sha256.Sum256([]byte("kubevirt hibernation key v1\x00" + a.VMUID + "\x00" + a.ID))
	return sum[:], nil
}

type PublicKey struct {
	ID        string
	Recipient string
}

type PrivateKey struct {
	PublicKey
	Identity []byte `json:"-"`
}

// String prevents incidental formatting of a key from disclosing its identity.
func (k PrivateKey) String() string   { return "hibernation private key [redacted]" }
func (k PrivateKey) GoString() string { return k.String() }

func (k *PrivateKey) Close() {
	clear(k.Identity)
	k.Identity = nil
}
