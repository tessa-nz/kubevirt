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

func TestKernelQualificationIsDirectionalAndKeepsOtherCompatibilityChecks(t *testing.T) {
	saved, current := compatibleMetadata(), compatibleMetadata()
	q := &KernelQualification{VMUID: "vm", NodeUID: "node-uid", SourceKernel: "kernel-a", TargetKernel: "kernel-b"}
	saved.KernelQualification, current.KernelQualification = q, q
	current.HostKernelRelease, current.KVMFingerprint = "kernel-b", "new-kvm"
	if !KernelQualificationAllows(saved, current) || ValidateCompatibility(saved, current, CompatibilityOptions{}) != nil {
		t.Fatal("explicit directional qualification rejected")
	}
	for name, mutate := range map[string]func(*Metadata){
		"other kernel":            func(m *Metadata) { m.HostKernelRelease = "kernel-c" },
		"other VM":                func(m *Metadata) { m.VMUID = "other" },
		"other node":              func(m *Metadata) { m.NodeName = "other" },
		"other CPU":               func(m *Metadata) { m.CPUFeatures = "other" },
		"other microcode":         func(m *Metadata) { m.Microcode = "other" },
		"other QEMU":              func(m *Metadata) { m.QEMUVersion = "other" },
		"other libvirt":           func(m *Metadata) { m.LibvirtVersion = "other" },
		"other release":           func(m *Metadata) { m.KubeVirtVersion = "other" },
		"withdrawn qualification": func(m *Metadata) { m.KernelQualification = nil },
		"replaced node UID":       func(m *Metadata) { x := *q; x.NodeUID = "other"; m.KernelQualification = &x },
	} {
		t.Run(name, func(t *testing.T) {
			changed := current
			mutate(&changed)
			if ValidateCompatibility(saved, changed, CompatibilityOptions{}) == nil {
				t.Fatal("unqualified compatibility change accepted")
			}
		})
	}
	if KernelQualificationAllows(current, saved) {
		t.Fatal("qualification authorized reverse direction")
	}
	// Rolling back before consumption keeps the original strict same-kernel path.
	current = saved
	if ValidateCompatibility(saved, current, CompatibilityOptions{}) != nil {
		t.Fatal("same-kernel rollback rejected")
	}
	saved.KernelQualification, current.KernelQualification = nil, nil
	current.HostKernelRelease = "kernel-b"
	if ValidateCompatibility(saved, current, CompatibilityOptions{}) == nil {
		t.Fatal("default kernel rejection changed")
	}
}

func TestKernelQualificationIsCoveredByArtifactIntegrity(t *testing.T) {
	m := compatibleMetadata()
	m.KernelQualification = &KernelQualification{VMUID: "vm", NodeUID: "node", SourceKernel: "kernel-a", TargetKernel: "kernel-b"}
	before, _ := ArtifactDigest(m)
	for _, field := range []string{"VMUID", "NodeUID", "SourceKernel", "TargetKernel"} {
		x := *m.KernelQualification
		switch field {
		case "VMUID":
			x.VMUID = "other"
		case "NodeUID":
			x.NodeUID = "other"
		case "SourceKernel":
			x.SourceKernel = "other"
		case "TargetKernel":
			x.TargetKernel = "other"
		}
		changed := m
		changed.KernelQualification = &x
		after, _ := ArtifactDigest(changed)
		if before == after {
			t.Fatalf("%s is outside artifact integrity", field)
		}
	}
	m.KernelQualification.TargetKernel = "*"
	if m.KernelQualification.Valid() {
		t.Fatal("wildcard kernel qualification accepted")
	}
}
