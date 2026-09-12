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
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"filippo.io/age"
)

func fixtureKey(t *testing.T) *PrivateKey {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	key := &PrivateKey{PublicKey: PublicKey{ID: "test-key", Recipient: identity.Recipient().String()}, Identity: []byte(identity.String())}
	t.Cleanup(key.Close)
	return key
}

func TestAuthenticatedImagesRejectTamperingAndTruncation(t *testing.T) {
	key := fixtureKey(t)
	plaintext := bytes.Repeat([]byte("disposable secret guest page\x00"), 10000)
	var cipher bytes.Buffer
	info, err := EncryptImage(bytes.NewReader(plaintext), &cipher, key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var recovered bytes.Buffer
	if err := DecryptImage(bytes.NewReader(cipher.Bytes()), &recovered, key, info); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, recovered.Bytes()) {
		t.Fatal("image round trip changed plaintext")
	}
	for _, position := range []int{0, 32, cipher.Len() / 2, cipher.Len() - 1} {
		tampered := bytes.Clone(cipher.Bytes())
		tampered[position] ^= 0x80
		if err := DecryptImage(bytes.NewReader(tampered), &bytes.Buffer{}, key, info); err == nil {
			t.Fatalf("tamper at %d accepted", position)
		}
	}
	for _, size := range []int{0, 10, 65536, cipher.Len() - 1} {
		if err := DecryptImage(bytes.NewReader(cipher.Bytes()[:size]), &bytes.Buffer{}, key, info); err == nil {
			t.Fatalf("truncation to %d accepted", size)
		}
	}
	appended := append(bytes.Clone(cipher.Bytes()), byte(0))
	if err := DecryptImage(bytes.NewReader(appended), &bytes.Buffer{}, key, info); err == nil {
		t.Fatal("appended ciphertext accepted")
	}
	wrong := fixtureKey(t)
	if err := DecryptImage(bytes.NewReader(cipher.Bytes()), &bytes.Buffer{}, wrong, info); err == nil {
		t.Fatal("another attempt's key was accepted")
	}
}

func TestPublicRecipientCannotReplaceTheAnchoredArtifact(t *testing.T) {
	key := fixtureKey(t)
	var original, forged bytes.Buffer
	info, err := EncryptImage(bytes.NewReader([]byte("original guest memory")), &original, key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// A PVC reader knows the public recipient and can encrypt its own file.
	// Stream authentication alone is not an integrity anchor for this case.
	if _, err := EncryptImage(bytes.NewReader([]byte("injected guest memory")), &forged, key.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := DecryptImage(bytes.NewReader(forged.Bytes()), &bytes.Buffer{}, key, info); err == nil {
		t.Fatal("public-key ciphertext replacement was accepted")
	}
	changed := info
	changed.PlaintextSize++
	if err := DecryptImage(bytes.NewReader(original.Bytes()), &bytes.Buffer{}, key, changed); err == nil {
		t.Fatal("incorrect plaintext bound accepted")
	}
	digest := sha256.Sum256([]byte("wrong"))
	changed = info
	changed.PlaintextSHA256 = hex.EncodeToString(digest[:])
	if err := DecryptImage(bytes.NewReader(original.Bytes()), &bytes.Buffer{}, key, changed); err == nil {
		t.Fatal("incorrect plaintext digest accepted")
	}
}
