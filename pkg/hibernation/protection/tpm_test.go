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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// These tests use only Microsoft's in-process TPM emulator. They never open
// /dev/tpm*, issue TPM_Clear to a device, or create hardware persistent objects.
type emulatorTransport struct {
	mu   sync.Mutex
	t    transport.TPM
	drop tpm2.TPMCC
}

func (e *emulatorTransport) Send(command []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rsp, err := e.t.Send(command)
	if err == nil && e.drop != 0 && tpm2.TPMCC(binary.BigEndian.Uint32(command[6:10])) == e.drop {
		e.drop = 0
		return nil, io.ErrUnexpectedEOF
	}
	return rsp, err
}
func (*emulatorTransport) Close() error { return nil }

func testTPM(t *testing.T) (*TPMStore, *simulator.Simulator, *emulatorTransport) {
	t.Helper()
	sim, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sim.Close(); err != nil {
			t.Error(err)
		}
	})
	link := &emulatorTransport{t: transport.FromReadWriter(sim)}
	store := NewTPMStore(func() (transport.TPMCloser, error) { return link, nil }, filepath.Join(t.TempDir(), "node-tpm.lock"), nil)
	return store, sim, link
}

func TestTPMKeySurvivesRebootAndIsIrrecoverableAfterErasure(t *testing.T) {
	store, sim, _ := testTPM(t)
	attempt := Attempt{VMUID: "vm-one", ID: "attempt-one"}
	public, err := store.Create(attempt)
	if err != nil {
		t.Fatal(err)
	}
	again, err := store.Create(attempt)
	if err != nil || public != again {
		t.Fatalf("creation is not idempotent: %v", err)
	}
	plaintext := bytes.Repeat([]byte("disposable guest memory\x00"), 10000)
	var ciphertext bytes.Buffer
	recipient, err := age.ParseX25519Recipient(public.Recipient)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext.Bytes(), []byte("disposable guest memory")) {
		t.Fatal("ciphertext contains plaintext")
	}
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	key, err := store.Open(attempt)
	if err != nil {
		t.Fatal(err)
	}
	if key.PublicKey != public {
		t.Fatal("key identity changed after reboot")
	}
	if strings.Contains(fmt.Sprint(*key), string(key.Identity)) {
		t.Fatal("key formatting leaks its identity")
	}
	identity, err := age.ParseX25519Identity(string(key.Identity))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext.Bytes()), identity)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("encrypted reboot round trip failed: %v", err)
	}
	key.Close()
	if err := store.Destroy(attempt); !errors.Is(err, ErrUnconsumed) {
		t.Fatalf("unconsumed key was not protected: %v", err)
	}
	fresh, err := store.Consume(attempt)
	if err != nil || !fresh {
		t.Fatalf("consumption failed: %v", err)
	}
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(attempt); !errors.Is(err, ErrConsumed) {
		t.Fatalf("consumed artifact became replayable after reboot: %v", err)
	}
	if err := store.transaction(attempt, func(a *tpmAttempt) error {
		public, err := a.nvPublic()
		if err != nil {
			return err
		}
		_, err = (tpm2.NVWrite{AuthHandle: a.owner(), NVIndex: tpm2.NamedHandle{Handle: a.nvHandle, Name: public.NVName}, Data: tpm2.TPM2BMaxNVBuffer{Buffer: make([]byte, 8)}}).Execute(a.t)
		if !errors.Is(err, tpm2.TPMRCNVLocked) {
			return fmt.Errorf("consumed NV was writable after reboot: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if fresh, err := store.Consume(attempt); err != nil || fresh {
		t.Fatalf("consumption was repeated: %v", err)
	}
	if err := store.Abandon(attempt); !errors.Is(err, ErrConsumed) {
		t.Fatalf("save-rejection cleanup accepted a consumed key: %v", err)
	}
	if err := store.Destroy(attempt); err != nil {
		t.Fatal(err)
	}
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(attempt); !errors.Is(err, ErrMissing) {
		t.Fatalf("key was accessible after verified erasure and reboot: %v", err)
	}
	if err := store.Destroy(attempt); err != nil {
		t.Fatalf("erasure retry failed: %v", err)
	}
}

func TestTPMInterruptedConsumptionAndErasureFailClosed(t *testing.T) {
	store, sim, link := testTPM(t)
	attempt := Attempt{VMUID: "vm-one", ID: "interrupted"}
	if _, err := store.Create(attempt); err != nil {
		t.Fatal(err)
	}
	link.drop = tpm2.TPMCCNVWrite
	if fresh, err := store.Consume(attempt); err == nil || fresh {
		t.Fatal("lost consumption response was treated as a new successful commit")
	}
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(attempt); !errors.Is(err, ErrConsumed) {
		t.Fatalf("lost response allowed replay: %v", err)
	}
	if fresh, err := store.Consume(attempt); err != nil || fresh {
		t.Fatalf("retry did not recognize consumption: %v", err)
	}
	link.drop = tpm2.TPMCCEvictControl
	if err := store.Destroy(attempt); err == nil {
		t.Fatal("lost erasure response was not surfaced")
	}
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := store.Destroy(attempt); err != nil {
		t.Fatalf("partial erasure did not recover: %v", err)
	}
	if _, err := store.Open(attempt); !errors.Is(err, ErrMissing) {
		t.Fatalf("erased key remains accessible: %v", err)
	}
}

func TestTPMLostWriteLockResponseRemainsConsumedAfterReboot(t *testing.T) {
	store, sim, link := testTPM(t)
	attempt := Attempt{VMUID: "vm", ID: "lost-lock"}
	if _, err := store.Create(attempt); err != nil {
		t.Fatal(err)
	}
	link.drop = tpm2.TPMCCNVWriteLock
	if fresh, err := store.Consume(attempt); err == nil || fresh {
		t.Fatal("uncertain lock acknowledged as fresh")
	}
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(attempt); !errors.Is(err, ErrConsumed) {
		t.Fatalf("replay after lost lock acknowledgement: %v", err)
	}
	if fresh, err := store.Consume(attempt); err != nil || fresh {
		t.Fatalf("retry incorrectly permits unpause: %v", err)
	}
}

func TestTPMTransactionsSerializeAcrossHandlerInstances(t *testing.T) {
	store, _, link := testTPM(t)
	other := NewTPMStore(func() (transport.TPMCloser, error) { return link, nil }, store.lockPath, nil)
	attempt := Attempt{VMUID: "vm-one", ID: "concurrent"}
	if _, err := store.Create(attempt); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for _, candidate := range []*TPMStore{store, other} {
		wg.Add(1)
		go func(s *TPMStore) {
			defer wg.Done()
			fresh, err := s.Consume(attempt)
			if err != nil {
				t.Error(err)
			}
			results <- fresh
		}(candidate)
	}
	wg.Wait()
	close(results)
	freshCount := 0
	for fresh := range results {
		if fresh {
			freshCount++
		}
	}
	if freshCount != 1 {
		t.Fatalf("expected one commit, got %d", freshCount)
	}
}

func TestTPMCollisionDoesNotAlterAnotherAttempt(t *testing.T) {
	store, _, _ := testTPM(t)
	original := Attempt{VMUID: "vm-one", ID: "original"}
	binding, _ := original.binding()
	want := binary.BigEndian.Uint16(binding)
	var collision Attempt
	for index := 0; ; index++ {
		candidate := Attempt{VMUID: "vm-two", ID: fmt.Sprintf("candidate-%d", index)}
		candidateBinding, _ := candidate.binding()
		if binary.BigEndian.Uint16(candidateBinding) == want {
			collision = candidate
			break
		}
	}
	public, err := store.Create(original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(collision); !errors.Is(err, ErrIdentity) {
		t.Fatalf("collision accepted: %v", err)
	}
	if err := store.Abandon(collision); !errors.Is(err, ErrIdentity) {
		t.Fatalf("foreign-object erasure accepted: %v", err)
	}
	key, err := store.Open(original)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	if key.PublicKey != public {
		t.Fatal("collision changed the original key")
	}
}

func TestMemoryProtectionRequiresHardSwapBoundary(t *testing.T) {
	for _, test := range []struct {
		name     string
		files    map[string]string
		accepted bool
	}{
		{"host-no-swap", map[string]string{"/proc/swaps": "Filename\tType\tSize\tUsed\tPriority\n"}, true},
		{"swappable", map[string]string{"/proc/swaps": "Filename\n/dev/swap partition 1024 0 -2\n", "/proc/self/cgroup": "0::/pod\n", "/sys/fs/cgroup/pod/memory.swap.max": "max"}, false},
		{"cgroup-no-swap", map[string]string{"/proc/self/cgroup": "0::/pod\n", "/sys/fs/cgroup/pod/memory.swap.max": "0"}, true},
		{"inherited-no-swap", map[string]string{"/proc/self/cgroup": "0::/pod/container\n", "/sys/fs/cgroup/pod/memory.swap.max": "0"}, true},
		{"missing-evidence", map[string]string{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := checkNoSwap(func(path string) ([]byte, error) {
				if value, ok := test.files[path]; ok {
					return []byte(value), nil
				}
				return nil, os.ErrNotExist
			})
			if (err == nil) != test.accepted {
				t.Fatalf("unexpected swap boundary result: %v", err)
			}
		})
	}
}
