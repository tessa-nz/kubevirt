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

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	StatePVCAnnotation               = "hibernation.kubevirt.io/state-pvc"
	RequestAnnotation                = "hibernation.kubevirt.io/request"
	StateAnnotation                  = "hibernation.kubevirt.io/state"
	AttemptAnnotation                = "hibernation.kubevirt.io/attempt"
	VMUIDAnnotation                  = "hibernation.kubevirt.io/vm-uid"
	SpecHashAnnotation               = "hibernation.kubevirt.io/spec-hash"
	PVCIdentitiesAnnotation          = "hibernation.kubevirt.io/pvc-identities"
	ErrorAnnotation                  = "hibernation.kubevirt.io/error"
	LabAllowKernelMismatchAnnotation = "hibernation.kubevirt.io/lab-compatibility-override"
	LabFailBeforeConsumeAnnotation   = "hibernation.kubevirt.io/lab-fail-before-consume"
	LabFailAfterConsumeAnnotation    = "hibernation.kubevirt.io/lab-fail-after-consume"

	StateMountPath     = "/var/run/kubevirt-private/hibernation"
	StateVolumeName    = "hibernation-state"
	SaveInProgressPath = "/var/run/kubevirt-private/hibernation-save-in-progress"

	RequestSave          = "save"
	RequestRestorePaused = "restore-paused"
	RequestCommitUnpause = "commit-unpause"
	RequestErase         = "erase"
	RequestHibernate     = "hibernate"
	RequestResume        = "resume"
	RequestFinalize      = "finalize"

	StateRunning                     = "Running"
	StateSaving                      = "Saving"
	StateHibernated                  = "Hibernated"
	StateRestoring                   = "Restoring"
	StateRestoredPaused              = "RestoredPaused"
	StateRestoreCommittedPaused      = "RestoreCommittedPaused"
	StateRunningAwaitingVerification = "RunningAwaitingVerification"
	StateSaveIncomplete              = "SaveIncomplete"
	StateResumeRejected              = "ResumeRejected"
	StateRestoreCommitLost           = "RestoreCommitLost"

	VMIConditionType = "KubeVirtHibernation"
)

type Metadata struct {
	FormatVersion       int               `json:"formatVersion"`
	Completed           bool              `json:"completed"`
	Consumed            bool              `json:"consumed"`
	AttemptID           string            `json:"attemptID"`
	VMUID               string            `json:"vmUID"`
	SourceVMIUID        string            `json:"sourceVMIUID"`
	EffectiveSpecHash   string            `json:"effectiveSpecHash"`
	DomainXMLHash       string            `json:"domainXMLHash"`
	StateSHA256         string            `json:"stateSHA256"`
	StateSize           int64             `json:"stateSize"`
	PVCIdentities       map[string]string `json:"pvcIdentities"`
	NodeName            string            `json:"nodeName"`
	CPUModel            string            `json:"cpuModel"`
	CPUFeatures         string            `json:"cpuFeatures"`
	HostKernelRelease   string            `json:"hostKernelRelease"`
	KVMFingerprint      string            `json:"kvmFingerprint"`
	Microcode           string            `json:"microcode"`
	KubeVirtVersion     string            `json:"kubeVirtVersion"`
	QEMUVersion         string            `json:"qemuVersion"`
	LibvirtVersion      string            `json:"libvirtVersion"`
	CreatedAt           string            `json:"createdAt"`
	CompletedAt         string            `json:"completedAt"`
	ConsumedAt          string            `json:"consumedAt,omitempty"`
	ErasedAt            string            `json:"erasedAt,omitempty"`
	ValidatedKernelPair string            `json:"validatedKernelPair,omitempty"`
	OverrideAttempted   bool              `json:"compatibilityOverrideAttempted,omitempty"`
	OverrideKernel      string            `json:"compatibilityOverrideKernel,omitempty"`
	OverrideKVM         string            `json:"compatibilityOverrideKVM,omitempty"`
}

type CompatibilityOptions struct {
	AllowKernelMismatch bool
}

func Hash(value interface{}) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func HashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func ValidateCompatibility(saved, current Metadata, options CompatibilityOptions) error {
	checks := []struct {
		name    string
		saved   string
		current string
	}{
		{"vm UID", saved.VMUID, current.VMUID},
		{"effective spec", saved.EffectiveSpecHash, current.EffectiveSpecHash},
		{"PVC identities", mustHash(saved.PVCIdentities), mustHash(current.PVCIdentities)},
		{"node", saved.NodeName, current.NodeName},
		{"CPU model", saved.CPUModel, current.CPUModel},
		{"CPU features", saved.CPUFeatures, current.CPUFeatures},
		{"microcode", saved.Microcode, current.Microcode},
		{"KubeVirt build", saved.KubeVirtVersion, current.KubeVirtVersion},
		{"QEMU build", saved.QEMUVersion, current.QEMUVersion},
		{"libvirt build", saved.LibvirtVersion, current.LibvirtVersion},
	}
	if !options.AllowKernelMismatch {
		checks = append(checks, struct {
			name    string
			saved   string
			current string
		}{"KVM capabilities", saved.KVMFingerprint, current.KVMFingerprint})
		checks = append(checks, struct {
			name    string
			saved   string
			current string
		}{"host kernel", saved.HostKernelRelease, current.HostKernelRelease})
	}
	for _, check := range checks {
		if check.saved == "" || check.current == "" || check.saved != check.current {
			return fmt.Errorf("incompatible %s: saved=%q current=%q", check.name, check.saved, check.current)
		}
	}
	return nil
}

func IsTerminal(state string) bool {
	switch state {
	case StateSaveIncomplete, StateResumeRejected, StateRestoreCommitLost:
		return true
	default:
		return false
	}
}

func CanAdoptEmptyDomainUID(state string) bool {
	switch state {
	case StateRestoring, StateRestoredPaused, StateRestoreCommittedPaused, StateRunningAwaitingVerification:
		return true
	default:
		return false
	}
}

func mustHash(value interface{}) string {
	hash, err := Hash(value)
	if err != nil {
		return ""
	}
	return hash
}
