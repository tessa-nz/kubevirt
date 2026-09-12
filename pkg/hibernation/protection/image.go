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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"

	"filippo.io/age"
)

type ImageInfo struct {
	CiphertextSHA256 string
	CiphertextSize   int64
	PlaintextSHA256  string
	PlaintextSize    int64
}

type countingWriter struct {
	writer io.Writer
	size   int64
}

func (w *countingWriter) Write(data []byte) (int, error) {
	n, err := w.writer.Write(data)
	w.size += int64(n)
	return n, err
}

// EncryptImage writes the standard age authenticated file format. Only the
// public recipient is needed by the saving launcher; its private identity
// remains in the node TPM until a restore is requested.
func EncryptImage(source io.Reader, destination io.Writer, key PublicKey) (ImageInfo, error) {
	var result ImageInfo
	recipient, err := age.ParseX25519Recipient(key.Recipient)
	if err != nil {
		return result, fmt.Errorf("invalid hibernation encryption recipient")
	}
	cipherHash, plainHash := sha256.New(), sha256.New()
	cipher := &countingWriter{writer: io.MultiWriter(destination, cipherHash)}
	writer, err := age.Encrypt(cipher, recipient)
	if err != nil {
		return result, fmt.Errorf("initialize hibernation encryption: %w", err)
	}
	plainSize, err := io.Copy(writer, io.TeeReader(source, plainHash))
	if err != nil {
		return result, fmt.Errorf("encrypt hibernation image: %w", err)
	}
	if err := writer.Close(); err != nil {
		return result, fmt.Errorf("finish hibernation encryption: %w", err)
	}
	result.CiphertextSHA256 = hex.EncodeToString(cipherHash.Sum(nil))
	result.CiphertextSize = cipher.size
	result.PlaintextSHA256 = hex.EncodeToString(plainHash.Sum(nil))
	result.PlaintextSize = plainSize
	return result, nil
}

// DecryptImage authenticates the complete stream, bounds both lengths, and
// checks the externally anchored digests. The destination must be private,
// unswappable staging and must not be read by libvirt unless this call succeeds.
// The caller discards the destination on every error, including late truncation.
func DecryptImage(source io.Reader, destination io.Writer, key *PrivateKey, expected ImageInfo) error {
	if expected.CiphertextSize <= 0 || expected.PlaintextSize <= 0 || expected.CiphertextSize == math.MaxInt64 || expected.PlaintextSize == math.MaxInt64 {
		return fmt.Errorf("invalid hibernation image lengths")
	}
	for _, value := range []string{expected.CiphertextSHA256, expected.PlaintextSHA256} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("invalid hibernation image digest")
		}
	}
	identity, err := age.ParseX25519Identity(string(key.Identity))
	if err != nil {
		return fmt.Errorf("invalid hibernation decryption identity")
	}
	if identity.Recipient().String() != key.Recipient {
		return fmt.Errorf("hibernation recipient does not match its TPM identity")
	}
	cipherHash, plainHash := sha256.New(), sha256.New()
	cipherCounter := &countingWriter{writer: cipherHash}
	cipher := io.TeeReader(io.LimitReader(source, expected.CiphertextSize+1), cipherCounter)
	reader, err := age.Decrypt(cipher, identity)
	if err != nil {
		return fmt.Errorf("authenticate hibernation image header: %w", err)
	}
	plainSize, err := io.Copy(io.MultiWriter(destination, plainHash), io.LimitReader(reader, expected.PlaintextSize+1))
	if err != nil {
		return fmt.Errorf("authenticate hibernation image: %w", err)
	}
	if plainSize != expected.PlaintextSize {
		return fmt.Errorf("hibernation plaintext length mismatch")
	}
	// Account for any trailing input even if a format reader buffers ahead or
	// stops after its final chunk. Appended data is not part of this artifact.
	if _, err := io.Copy(io.Discard, cipher); err != nil {
		return err
	}
	if cipherCounter.size != expected.CiphertextSize || hex.EncodeToString(cipherHash.Sum(nil)) != expected.CiphertextSHA256 {
		return fmt.Errorf("hibernation ciphertext does not match the committed artifact")
	}
	if hex.EncodeToString(plainHash.Sum(nil)) != expected.PlaintextSHA256 {
		return fmt.Errorf("hibernation plaintext does not match the committed artifact")
	}
	return nil
}
