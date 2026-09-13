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

package virtwrap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"libvirt.org/go/libvirt"
	"libvirt.org/go/libvirtxml"

	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/version"

	cmdv1 "kubevirt.io/kubevirt/pkg/handler-launcher-com/cmd/v1"
	"kubevirt.io/kubevirt/pkg/hibernation"
	"kubevirt.io/kubevirt/pkg/hibernation/protection"
	"kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/api"
	"kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/cli"
	"kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/converter"
	domainerrors "kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/errors"
)

const hibernationMetadataFile = "metadata.json"

const (
	kvmGetAPIVersion   = 0xae00
	kvmCheckExtension  = 0xae03
	kvmCapabilityLimit = 256
)

func (l *LibvirtDomainManager) HibernateVMI(vmi *v1.VirtualMachineInstance, action cmdv1.HibernationAction, statePath string, allowKernelMismatch bool, protectionContext *cmdv1.HibernationProtection) (*cmdv1.HibernationResponse, error) {
	l.domainModifyLock.Lock()
	defer l.domainModifyLock.Unlock()

	l.hibernationContext = protectionContext
	defer func() {
		if protectionContext != nil {
			clear(protectionContext.PrivateIdentity)
			protectionContext.PrivateIdentity = nil
		}
		l.hibernationContext = nil
	}()
	if protectionContext == nil || protectionContext.Provider != protection.Provider {
		return nil, fmt.Errorf("TPM state protection is required")
	}

	if err := validateStatePath(statePath); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		return nil, err
	}

	var metadata *hibernation.Metadata
	var phase string
	var err error
	switch action {
	case cmdv1.HibernationAction_HIBERNATION_ACTION_SAVE:
		metadata, phase, err = l.saveVMI(vmi, statePath)
	case cmdv1.HibernationAction_HIBERNATION_ACTION_RESTORE_PAUSED:
		metadata, phase, err = l.restoreVMI(vmi, statePath, allowKernelMismatch)
	case cmdv1.HibernationAction_HIBERNATION_ACTION_COMMIT_UNPAUSE:
		metadata, phase, err = l.commitAndUnpauseVMI(vmi, statePath)
	case cmdv1.HibernationAction_HIBERNATION_ACTION_ERASE:
		if annotation(vmi, hibernation.RequestAnnotation) == hibernation.RequestDiscard {
			metadata, phase, err = l.discardVMI(vmi, statePath)
		} else {
			metadata, phase, err = l.eraseVMI(vmi, statePath)
		}
	default:
		err = fmt.Errorf("unsupported hibernation action %s", action.String())
	}
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	return &cmdv1.HibernationResponse{
		Response:     &cmdv1.Response{Success: true},
		Phase:        phase,
		MetadataJson: payload,
	}, nil
}

func (l *LibvirtDomainManager) saveVMI(vmi *v1.VirtualMachineInstance, statePath string) (*hibernation.Metadata, string, error) {
	key, err := l.hibernationPublicKey()
	if err != nil {
		return nil, "", l.rejectSave(vmi, err)
	}
	if existing, err := readHibernationMetadata(statePath); err == nil {
		if existing.Completed && !existing.Consumed && existing.AttemptID == annotation(vmi, hibernation.AttemptAnnotation) {
			digest, err := hibernation.ArtifactDigest(*existing)
			if err != nil {
				return nil, "", err
			}
			if readTrimmed(hibernation.SaveInProgressPath) == digest && existing.ProtectionKeyID == key.ID && existing.ProtectionRecipient == key.Recipient && existing.FormatVersion == 2 {
				return existing, hibernation.StateHibernated, nil
			}
			// A publication whose final marker write failed can only be recovered
			// from the private completed stage, never from the mutable PVC.
		} else if existing.ErasedAt == "" {
			return nil, "", l.rejectSave(vmi, fmt.Errorf("state path contains another active artifact"))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	stage, err := hibernationStage(vmi)
	if err != nil {
		return nil, "", l.rejectSave(vmi, err)
	}
	metadata, err := readHibernationMetadata(stage)
	if err == nil {
		if metadata.AttemptID != annotation(vmi, hibernation.AttemptAnnotation) || metadata.VMUID != annotation(vmi, hibernation.VMUIDAnnotation) || metadata.ProtectionKeyID != key.ID || metadata.ProtectionRecipient != key.Recipient {
			return nil, "", fmt.Errorf("private save stage belongs to another attempt or key")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	} else {
		if err := requireEmptyStateSlot(statePath); err != nil {
			return nil, "", l.rejectSave(vmi, err)
		}
		if _, err := os.Lstat(statePath + ".partial"); !errors.Is(err, os.ErrNotExist) {
			return nil, "", l.rejectSave(vmi, fmt.Errorf("unpublished state already exists"))
		}
		if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
			return nil, "", fmt.Errorf("private image lacks its original save descriptor")
		}
		metadata, err = l.currentMetadata(vmi)
		if err != nil {
			return nil, "", err
		}
		metadata.ProtectionProvider, metadata.ProtectionKeyID, metadata.ProtectionRecipient = protection.Provider, key.ID, key.Recipient
		metadata.SourceVMIUID = string(vmi.UID)
		metadata.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		// Persist the private descriptor before stopping QEMU. Its completed save
		// image can be recovered after a lost response or any later XML/I/O error.
		if err := writeHibernationMetadata(stage, metadata); err != nil {
			return nil, "", err
		}
	}
	if !metadata.Completed {
		if err := l.completeHibernationStage(vmi, stage, metadata); err != nil {
			return nil, "", err
		}
	} else {
		hash, size, err := checksumFile(stage)
		if err != nil {
			return nil, "", err
		}
		if hash != metadata.PlaintextSHA256 || size != metadata.PlaintextSize {
			return nil, "", fmt.Errorf("private save stage changed")
		}
	}
	if err := publishEncryptedHibernation(stage, statePath, key, metadata); err != nil {
		return nil, "", err
	}
	digest, err := hibernation.ArtifactDigest(*metadata)
	if err != nil {
		return nil, "", err
	}
	if err := writeDurableFile(hibernation.SaveInProgressPath, []byte(digest)); err != nil {
		return nil, "", err
	}
	// Removing plaintext is best effort here: the disposable source pod's
	// private tmpfs disappears after the controller anchors this receipt.
	_ = os.Remove(stage)
	_ = os.Remove(metadataPath(stage))
	return metadata, hibernation.StateHibernated, nil
}

func (l *LibvirtDomainManager) rejectSave(vmi *v1.VirtualMachineInstance, cause error) error {
	domain, err := l.virConn.LookupDomainByName(api.VMINamespaceKeyFunc(vmi))
	if domainerrors.IsNotFound(err) {
		return hibernation.Reject(hibernation.StateSaveIncomplete, cause)
	}
	if err != nil {
		return fmt.Errorf("save outcome unknown: %w", err)
	}
	defer domain.Free()
	state, _, err := domain.GetState()
	if err != nil {
		return fmt.Errorf("save outcome unknown: %w", err)
	}
	if state == libvirt.DOMAIN_RUNNING {
		return hibernation.Reject(hibernation.StateSaveRejected, cause)
	}
	if cli.IsDown(state) {
		return hibernation.Reject(hibernation.StateSaveIncomplete, cause)
	}
	return fmt.Errorf("save outcome unknown while domain state is %d: %w", state, cause)
}

func (l *LibvirtDomainManager) restoreVMI(vmi *v1.VirtualMachineInstance, statePath string, allowKernelMismatch bool) (*hibernation.Metadata, string, error) {
	allowKernelMismatch = allowKernelMismatch && hibernation.LabEnabled
	metadata, err := readHibernationMetadata(statePath)
	if err != nil {
		return nil, "", err
	}
	if err := validateArtifactDigest(vmi, metadata); err != nil {
		return nil, "", hibernation.Reject(hibernation.StateResumeRejected, err)
	}
	if !metadata.Completed {
		return nil, "", hibernation.Reject(hibernation.StateResumeRejected, fmt.Errorf("incomplete save artifact"))
	}
	if metadata.Consumed {
		return nil, "", hibernation.Reject(hibernation.StateResumeRejected, fmt.Errorf("save artifact was already consumed at %s", metadata.ConsumedAt))
	}
	if metadata.AttemptID != annotation(vmi, hibernation.AttemptAnnotation) {
		return nil, "", hibernation.Reject(hibernation.StateResumeRejected, fmt.Errorf("attempt identity mismatch"))
	}
	if metadata.SourceVMIUID == "" || vmi.UID == "" {
		return nil, "", hibernation.Reject(hibernation.StateResumeRejected, fmt.Errorf("source and destination VMI identities are required"))
	}
	privatePath, err := l.decryptHibernation(vmi, statePath, metadata)
	if err != nil {
		return nil, "", hibernation.Reject(hibernation.StateResumeRejected, err)
	}
	defer os.Remove(privatePath)
	savedXML, err := l.virConn.DomainSaveImageGetXMLDesc(privatePath, 0)
	if err != nil {
		return nil, "", err
	}
	if hibernation.HashBytes([]byte(savedXML)) != metadata.DomainXMLHash {
		return nil, "", hibernation.Reject(hibernation.StateResumeRejected, fmt.Errorf("saved domain XML does not match committed metadata"))
	}
	current, err := l.currentMetadata(vmi)
	if err != nil {
		return nil, "", err
	}
	compatibilityMismatch := metadata.HostKernelRelease != current.HostKernelRelease || metadata.KVMFingerprint != current.KVMFingerprint
	overrideRequested := allowKernelMismatch && compatibilityMismatch
	if err := hibernation.ValidateCompatibility(*metadata, *current, hibernation.CompatibilityOptions{AllowKernelMismatch: overrideRequested}); err != nil {
		return nil, "", hibernation.Reject(hibernation.StateResumeRejected, err)
	}
	kernelPair := ""
	if overrideRequested {
		kernelPair = fmt.Sprintf("%s[%s] -> %s[%s]", metadata.HostKernelRelease, metadata.KVMFingerprint, current.HostKernelRelease, current.KVMFingerprint)
	}
	// Notifications and ListAllDomains replace libvirt XML metadata with this
	// cache. Initialize it before restore can emit an event, including retries
	// that recover an already-restored paused domain.
	l.metadataCache.UID.Set(vmi.UID)
	l.metadataCache.GracePeriod.Set(
		api.GracePeriodMetadata{DeletionGracePeriodSeconds: converter.GracePeriodSeconds(vmi)},
	)
	if domain, lookupErr := l.virConn.LookupDomainByName(api.VMINamespaceKeyFunc(vmi)); lookupErr == nil {
		defer domain.Free()
		state, _, stateErr := domain.GetState()
		if stateErr != nil {
			return nil, "", stateErr
		}
		if cli.IsPaused(state) {
			if kernelPair != "" && metadata.ValidatedKernelPair != kernelPair {
				metadata.ValidatedKernelPair = kernelPair
				if err := writeHibernationMetadata(statePath, metadata); err != nil {
					return nil, "", err
				}
			}
			return metadata, hibernation.StateRestoredPaused, nil
		}
		return nil, "", hibernation.Reject(hibernation.StateResumeRejected, fmt.Errorf("domain already exists in non-paused state"))
	} else if !domainerrors.IsNotFound(lookupErr) {
		return nil, "", lookupErr
	}
	if overrideRequested {
		if metadata.OverrideAttempted {
			return nil, "", hibernation.Reject(hibernation.StateResumeRejected, fmt.Errorf("lab compatibility override was already attempted for this artifact"))
		}
		metadata.OverrideAttempted = true
		metadata.OverrideKernel = current.HostKernelRelease
		metadata.OverrideKVM = current.KVMFingerprint
		if err := writeHibernationMetadata(statePath, metadata); err != nil {
			return nil, "", err
		}
	}
	restoreXML := strings.ReplaceAll(savedXML, metadata.SourceVMIUID, string(vmi.UID))
	restoreXML, err = setDomainKubeVirtUID(restoreXML, string(vmi.UID))
	if err != nil {
		return nil, "", err
	}
	if err := l.virConn.DomainRestoreFlags(privatePath, restoreXML, libvirt.DOMAIN_SAVE_PAUSED); err != nil {
		// A lost libvirt response can accompany a successful paused restore.
		// Only a confirmed absent domain proves a rejected restore.
		if domain, lookupErr := l.virConn.LookupDomainByName(api.VMINamespaceKeyFunc(vmi)); lookupErr == nil {
			domain.Free()
		} else if domainerrors.IsNotFound(lookupErr) {
			return nil, "", hibernation.Reject(hibernation.StateResumeRejected, err)
		}
		return nil, "", err
	}
	if kernelPair != "" {
		metadata.ValidatedKernelPair = kernelPair
		if err := writeHibernationMetadata(statePath, metadata); err != nil {
			return nil, "", err
		}
	}
	return metadata, hibernation.StateRestoredPaused, nil
}

func ejectTransientCloudInitMedia(domainXML string) (string, error) {
	domain := &libvirtxml.Domain{}
	if err := domain.Unmarshal(domainXML); err != nil {
		return "", fmt.Errorf("parse saved domain XML: %w", err)
	}
	if domain.Devices == nil {
		return domainXML, nil
	}
	changed := false
	for index := range domain.Devices.Disks {
		disk := &domain.Devices.Disks[index]
		if disk.Device != "cdrom" || disk.Source == nil || disk.Source.File == nil {
			continue
		}
		if strings.Contains(disk.Source.File.File, "/cloud-init-data/") {
			disk.Source = nil
			changed = true
		}
	}
	if !changed {
		return domainXML, nil
	}
	updated, err := domain.Marshal()
	if err != nil {
		return "", fmt.Errorf("marshal saved domain XML: %w", err)
	}
	return updated, nil
}

func setDomainKubeVirtUID(domainXML, uid string) (string, error) {
	for _, empty := range []string{"<uid/>", "<uid />"} {
		if strings.Contains(domainXML, empty) {
			return strings.Replace(domainXML, empty, "<uid>"+uid+"</uid>", 1), nil
		}
	}
	const open = "<uid>"
	const close = "</uid>"
	start := strings.Index(domainXML, open)
	if start < 0 {
		return "", fmt.Errorf("saved domain XML has no KubeVirt UID metadata")
	}
	valueStart := start + len(open)
	end := strings.Index(domainXML[valueStart:], close)
	if end < 0 {
		return "", fmt.Errorf("saved domain XML has incomplete KubeVirt UID metadata")
	}
	end += valueStart
	return domainXML[:valueStart] + uid + domainXML[end:], nil
}

func (l *LibvirtDomainManager) commitAndUnpauseVMI(vmi *v1.VirtualMachineInstance, statePath string) (*hibernation.Metadata, string, error) {
	if l.hibernationContext == nil || !l.hibernationContext.ConsumptionCommitted {
		return nil, "", fmt.Errorf("TPM consumption must be committed before unpause")
	}
	metadata, err := readHibernationMetadata(statePath)
	if err != nil {
		return nil, "", err
	}
	if err := validateArtifactDigest(vmi, metadata); err != nil {
		return nil, "", hibernation.Reject(hibernation.StateRestoreCommitLost, err)
	}
	domain, err := l.virConn.LookupDomainByName(api.VMINamespaceKeyFunc(vmi))
	if err != nil {
		if domainerrors.IsNotFound(err) {
			return nil, "", hibernation.Reject(hibernation.StateRestoreCommitLost, fmt.Errorf("consumed attempt has no domain"))
		}
		return nil, "", err
	}
	defer domain.Free()
	state, _, err := domain.GetState()
	if err != nil {
		return nil, "", err
	}
	if state == libvirt.DOMAIN_RUNNING {
		metadata.Consumed = true
		if metadata.ConsumedAt == "" {
			metadata.ConsumedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		if err := writeHibernationMetadata(statePath, metadata); err != nil {
			return nil, "", err
		}
		return metadata, hibernation.StateRunningAwaitingVerification, nil
	}
	if !l.hibernationContext.FreshConsumption || !cli.IsPaused(state) || metadata.Consumed {
		return nil, "", hibernation.Reject(hibernation.StateRestoreCommitLost, fmt.Errorf("cannot unpause an attempt after uncertain or repeated consumption"))
	}
	metadata.Consumed = true
	metadata.ConsumedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := writeHibernationMetadata(statePath, metadata); err != nil {
		return nil, "", err
	}
	if hibernation.LabEnabled && annotation(vmi, hibernation.LabFailAfterConsumeAnnotation) == metadata.AttemptID {
		return nil, "", hibernation.Reject(hibernation.StateRestoreCommitLost, fmt.Errorf("injected failure after TPM consumption before unpause"))
	}
	if err := domain.Resume(); err != nil {
		return nil, "", fmt.Errorf("consumption committed; unpause outcome unknown: %w", err)
	}
	return metadata, hibernation.StateRunningAwaitingVerification, nil
}

func (l *LibvirtDomainManager) eraseVMI(vmi *v1.VirtualMachineInstance, statePath string) (*hibernation.Metadata, string, error) {
	if l.hibernationContext == nil || !l.hibernationContext.KeyErased {
		return nil, "", fmt.Errorf("TPM key erasure must be verified before finalization")
	}
	// Key deletion is the erasure boundary. A damaged or deleted PVC metadata
	// file cannot invalidate that fact; retain only a nonsecret completion record.
	metadata, err := readHibernationMetadata(statePath)
	if err != nil || metadata.AttemptID != annotation(vmi, hibernation.AttemptAnnotation) {
		metadata = &hibernation.Metadata{FormatVersion: 2, AttemptID: annotation(vmi, hibernation.AttemptAnnotation), VMUID: annotation(vmi, hibernation.VMUIDAnnotation), Consumed: true}
	}
	if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	metadata.ErasedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := writeHibernationMetadata(statePath, metadata); err != nil {
		return nil, "", err
	}
	return metadata, hibernation.StateRunning, nil
}

func (l *LibvirtDomainManager) discardVMI(vmi *v1.VirtualMachineInstance, statePath string) (*hibernation.Metadata, string, error) {
	if annotation(vmi, hibernation.StateAnnotation) != hibernation.StateDiscarding || l.hibernationContext == nil || !l.hibernationContext.KeyErased {
		return nil, "", fmt.Errorf("discard requires a cleanup-only attempt and verified TPM key erasure")
	}
	domain, err := l.virConn.LookupDomainByName(api.VMINamespaceKeyFunc(vmi))
	if err == nil {
		domain.Free()
		return nil, "", fmt.Errorf("discard refuses an existing domain")
	}
	if !domainerrors.IsNotFound(err) {
		return nil, "", err
	}
	// The exclusively reserved state PVC has one slot. Interrupted publication
	// can leave ciphertext and metadata temporary files without a valid manifest.
	entries, err := os.ReadDir(filepath.Dir(statePath))
	if err != nil {
		return nil, "", err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == filepath.Base(statePath) || name == filepath.Base(statePath)+".partial" || strings.HasPrefix(name, ".encrypted-state-") || strings.HasPrefix(name, ".hibernation-") {
			if entry.IsDir() {
				return nil, "", fmt.Errorf("unexpected directory in hibernation state slot: %s", name)
			}
			if err := os.Remove(filepath.Join(filepath.Dir(statePath), name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, "", err
			}
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	metadata := &hibernation.Metadata{FormatVersion: 2, VMUID: annotation(vmi, hibernation.VMUIDAnnotation), AttemptID: annotation(vmi, hibernation.AttemptAnnotation), ErasedAt: now, DiscardedAt: now}
	if err := writeHibernationMetadata(statePath, metadata); err != nil {
		return nil, "", err
	}
	return metadata, hibernation.StateDiscarded, nil
}

func (l *LibvirtDomainManager) currentMetadata(vmi *v1.VirtualMachineInstance) (*hibernation.Metadata, error) {
	specHash, err := hibernation.Hash(vmi.Spec)
	if err != nil {
		return nil, err
	}
	pvcIdentities := map[string]string{}
	if value := annotation(vmi, hibernation.PVCIdentitiesAnnotation); value != "" {
		if err := json.Unmarshal([]byte(value), &pvcIdentities); err != nil {
			return nil, fmt.Errorf("invalid PVC identity annotation: %w", err)
		}
	}
	if len(pvcIdentities) == 0 {
		return nil, fmt.Errorf("PVC identities are required")
	}
	qemuVersion, err := l.virConn.GetQemuVersion()
	if err != nil {
		return nil, err
	}
	libvirtVersion, err := l.virConn.GetLibVersion()
	if err != nil {
		return nil, err
	}
	kernel := readTrimmed("/proc/sys/kernel/osrelease")
	cpuInfo := readTrimmed("/proc/cpuinfo")
	kvmFingerprint, err := currentKVMFingerprint()
	if err != nil {
		return nil, err
	}
	build := version.Get()
	cpuModel := ""
	if vmi.Spec.Domain.CPU != nil {
		cpuModel = vmi.Spec.Domain.CPU.Model
	}
	if cpuModel == "" {
		cpuModel = firstCPUInfoValue(cpuInfo, "model name")
	}
	microcode := firstCPUInfoValue(cpuInfo, "microcode")
	if microcode == "" {
		microcode = "unavailable"
	}
	attemptID := annotation(vmi, hibernation.AttemptAnnotation)
	vmUID := annotation(vmi, hibernation.VMUIDAnnotation)
	if attemptID == "" || vmUID == "" {
		return nil, fmt.Errorf("attempt ID and VM UID annotations are required")
	}
	return &hibernation.Metadata{
		FormatVersion:     2,
		AttemptID:         attemptID,
		VMUID:             vmUID,
		EffectiveSpecHash: specHash,
		PVCIdentities:     pvcIdentities,
		NodeName:          vmi.Status.NodeName,
		CPUModel:          cpuModel,
		CPUFeatures:       hibernation.HashBytes([]byte(stableCPUFingerprint(cpuInfo))),
		HostKernelRelease: kernel,
		KVMFingerprint:    kvmFingerprint,
		Microcode:         microcode,
		KubeVirtVersion:   build.GitVersion + "+" + build.GitCommit,
		QEMUVersion:       qemuVersion,
		LibvirtVersion:    fmt.Sprintf("%d", libvirtVersion),
	}, nil
}

func currentKVMFingerprint() (string, error) {
	kvmDevice, err := os.Open("/dev/kvm")
	if err != nil {
		return "", fmt.Errorf("open /dev/kvm for capability fingerprint: %w", err)
	}
	defer kvmDevice.Close()

	var fingerprint strings.Builder
	apiVersion, _, errno := syscall.Syscall(syscall.SYS_IOCTL, kvmDevice.Fd(), kvmGetAPIVersion, 0)
	if errno != 0 {
		return "", fmt.Errorf("query KVM API version: %w", errno)
	}
	fmt.Fprintf(&fingerprint, "api=%d\n", apiVersion)
	for capability := uintptr(0); capability < kvmCapabilityLimit; capability++ {
		value, _, errno := syscall.Syscall(syscall.SYS_IOCTL, kvmDevice.Fd(), kvmCheckExtension, capability)
		if errno != 0 {
			return "", fmt.Errorf("query KVM capability %d: %w", capability, errno)
		}
		if value != 0 {
			fmt.Fprintf(&fingerprint, "capability[%d]=%d\n", capability, value)
		}
	}

	kvmParameters, _ := filepath.Glob("/sys/module/kvm*/parameters/*")
	for _, path := range kvmParameters {
		fmt.Fprintf(&fingerprint, "%s=%s\n", path, readTrimmed(path))
	}
	return hibernation.HashBytes([]byte(fingerprint.String())), nil
}

func validateStatePath(path string) error {
	clean := filepath.Clean(path)
	expected := filepath.Join(hibernation.StateMountPath, "state.save")
	if clean != expected || !filepath.IsAbs(clean) {
		return fmt.Errorf("hibernation state path must be %s", expected)
	}
	return nil
}

func annotation(vmi *v1.VirtualMachineInstance, key string) string {
	if vmi == nil || vmi.Annotations == nil {
		return ""
	}
	return vmi.Annotations[key]
}

func metadataPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), hibernationMetadataFile)
}

func requireEmptyStateSlot(statePath string) error {
	if _, err := os.Stat(statePath); err == nil {
		return fmt.Errorf("%s: state artifact exists without committed metadata", hibernation.StateSaveIncomplete)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func readHibernationMetadata(statePath string) (*hibernation.Metadata, error) {
	payload, err := readBoundedRegularFile(metadataPath(statePath), 1<<20)
	if err != nil {
		return nil, err
	}
	metadata := &hibernation.Metadata{}
	if err := json.Unmarshal(payload, metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

func writeHibernationMetadata(statePath string, metadata *hibernation.Metadata) error {
	payload, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return writeDurableFile(metadataPath(statePath), payload)
}

func writeDurableFile(target string, payload []byte) error {
	file, err := os.CreateTemp(filepath.Dir(target), ".hibernation-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(append(payload, '\n')); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), target); err != nil {
		return err
	}
	return syncPath(filepath.Dir(target))
}

func validateArtifactDigest(vmi *v1.VirtualMachineInstance, metadata *hibernation.Metadata) error {
	expected := annotation(vmi, hibernation.ArtifactDigestAnnotation)
	if expected == "" {
		return fmt.Errorf("restore requires a controller-recorded artifact digest")
	}
	actual, err := hibernation.ArtifactDigest(*metadata)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("artifact metadata does not match the controller-recorded digest")
	}
	return nil
}

func syncPath(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func checksumFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hasher := newHashWriter()
	size, err := io.Copy(hasher, file)
	if err != nil {
		return "", 0, err
	}
	return hasher.Sum(), size, nil
}

type hashWriter struct{ digest hash.Hash }

func newHashWriter() *hashWriter {
	return &hashWriter{digest: sha256.New()}
}
func (h *hashWriter) Write(p []byte) (int, error) { return h.digest.Write(p) }
func (h *hashWriter) Sum() string                 { return hex.EncodeToString(h.digest.Sum(nil)) }

func readTrimmed(path string) string {
	payload, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(payload))
}

func firstCPUInfoValue(cpuInfo, key string) string {
	for _, line := range strings.Split(cpuInfo, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == key {
			return strings.TrimSpace(parts[1])
		}
	}
	return runtime.GOARCH
}

func stableCPUFingerprint(cpuInfo string) string {
	allowed := map[string]bool{
		"vendor_id": true, "cpu family": true, "model": true, "model name": true,
		"stepping": true, "microcode": true, "flags": true, "Features": true,
	}
	var stable strings.Builder
	for _, line := range strings.Split(cpuInfo, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || !allowed[strings.TrimSpace(parts[0])] {
			continue
		}
		stable.WriteString(strings.TrimSpace(parts[0]))
		stable.WriteByte('=')
		stable.WriteString(strings.TrimSpace(parts[1]))
		stable.WriteByte('\n')
	}
	return stable.String()
}

// Called under domainModifyLock, also catching an RPC queued before the VMI
// received its hibernation annotations. A successful save keeps this marker
// until source-pod deletion; the restored VMI starts with protected annotations.
func rejectHibernationMutation(vmi *v1.VirtualMachineInstance) error {
	if hibernation.Active(vmi.Annotations) || annotation(vmi, hibernation.StateAnnotation) == hibernation.StateDiscarded {
		return fmt.Errorf("lifecycle operation conflicts with an active hibernation attempt")
	}
	if _, err := os.Stat(hibernation.SaveInProgressPath); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("lifecycle operation blocked while the save marker exists or cannot be checked")
	}
	return nil
}
