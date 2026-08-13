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

package hibernation

import "testing"

func compatibleMetadata() Metadata {
	return Metadata{
		VMUID: "vm", EffectiveSpecHash: "spec", DomainXMLHash: "domain",
		PVCIdentities: map[string]string{"state": "uid"}, NodeName: "node",
		CPUModel: "cpu", CPUFeatures: "features", HostKernelRelease: "kernel-a",
		KVMFingerprint: "kvm", Microcode: "ucode", KubeVirtVersion: "kv",
		QEMUVersion: "qemu", LibvirtVersion: "libvirt",
	}
}

func TestValidateCompatibility(t *testing.T) {
	saved := compatibleMetadata()
	current := compatibleMetadata()
	if err := ValidateCompatibility(saved, current, CompatibilityOptions{}); err != nil {
		t.Fatalf("expected compatible metadata: %v", err)
	}

	current.PVCIdentities["state"] = "substituted"
	if err := ValidateCompatibility(saved, current, CompatibilityOptions{}); err == nil {
		t.Fatal("expected substituted PVC to be rejected")
	}
}

func TestKernelMismatchRequiresExplicitOverride(t *testing.T) {
	saved := compatibleMetadata()
	current := compatibleMetadata()
	current.HostKernelRelease = "kernel-b"
	current.KVMFingerprint = "kvm-b"
	if err := ValidateCompatibility(saved, current, CompatibilityOptions{}); err == nil {
		t.Fatal("expected kernel mismatch to be rejected")
	}
	if err := ValidateCompatibility(saved, current, CompatibilityOptions{AllowKernelMismatch: true}); err != nil {
		t.Fatalf("expected lab-only kernel override to admit validation: %v", err)
	}
}

func TestTerminalStates(t *testing.T) {
	for _, state := range []string{StateSaveIncomplete, StateResumeRejected, StateRestoreCommitLost} {
		if !IsTerminal(state) {
			t.Fatalf("expected %s to be terminal", state)
		}
	}
	if IsTerminal(StateHibernated) {
		t.Fatal("hibernated must remain resumable")
	}
}

func TestOnlyRestoreStatesAdoptAnEmptyDomainUID(t *testing.T) {
	for _, state := range []string{StateRestoring, StateRestoredPaused, StateRestoreCommittedPaused, StateRunningAwaitingVerification} {
		if !CanAdoptEmptyDomainUID(state) {
			t.Fatalf("expected %s to permit empty domain UID adoption", state)
		}
	}
	for _, state := range []string{"", StateRunning, StateSaving, StateHibernated, StateResumeRejected} {
		if CanAdoptEmptyDomainUID(state) {
			t.Fatalf("state %s must not permit empty domain UID adoption", state)
		}
	}
}
