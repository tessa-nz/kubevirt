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
	"time"

	"libvirt.org/go/libvirt"
	"libvirt.org/go/libvirtxml"

	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/version"

	cmdv1 "kubevirt.io/kubevirt/pkg/handler-launcher-com/cmd/v1"
	"kubevirt.io/kubevirt/pkg/hibernation"
	"kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/api"
	"kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/cli"
	domainerrors "kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/errors"
)

const hibernationMetadataFile = "metadata.json"

func (l *LibvirtDomainManager) HibernateVMI(vmi *v1.VirtualMachineInstance, action cmdv1.HibernationAction, statePath string, allowKernelMismatch bool) (*cmdv1.HibernationResponse, error) {
	l.domainModifyLock.Lock()
	defer l.domainModifyLock.Unlock()

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
		metadata, phase, err = l.eraseVMI(vmi, statePath)
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
	if existing, err := readHibernationMetadata(statePath); err == nil {
		if existing.Completed && !existing.Consumed && existing.AttemptID == annotation(vmi, hibernation.AttemptAnnotation) {
			return existing, hibernation.StateHibernated, nil
		}
		if existing.ErasedAt == "" {
			return nil, "", fmt.Errorf("state path already contains attempt %q (completed=%t consumed=%t)", existing.AttemptID, existing.Completed, existing.Consumed)
		}
		if err := os.Rename(metadataPath(statePath), filepath.Join(filepath.Dir(statePath), "metadata."+existing.AttemptID+".json")); err != nil {
			return nil, "", err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	} else if err := requireEmptyStateSlot(statePath); err != nil {
		return nil, "", err
	}
	if _, err := os.Stat(statePath + ".partial"); err == nil {
		return nil, "", fmt.Errorf("%s: partial save already exists", hibernation.StateSaveIncomplete)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}

	metadata, err := l.currentMetadata(vmi)
	if err != nil {
		return nil, "", err
	}
	domainName := api.VMINamespaceKeyFunc(vmi)
	domain, err := l.virConn.LookupDomainByName(domainName)
	if err != nil {
		return nil, "", err
	}
	defer domain.Free()
	state, _, err := domain.GetState()
	if err != nil {
		return nil, "", err
	}
	if cli.IsDown(state) {
		return nil, "", fmt.Errorf("cannot save inactive domain")
	}
	metadata.SourceVMIUID = string(vmi.UID)
	metadata.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := os.WriteFile(hibernation.SaveInProgressPath, []byte(metadata.AttemptID), 0600); err != nil {
		return nil, "", err
	}
	defer os.Remove(hibernation.SaveInProgressPath)

	partial := statePath + ".partial"
	if err := domain.SaveFlags(partial, "", libvirt.DOMAIN_SAVE_PAUSED); err != nil {
		return nil, "", err
	}
	savedXML, err := l.virConn.DomainSaveImageGetXMLDesc(partial, 0)
	if err != nil {
		return nil, "", err
	}
	savedXML, err = ejectTransientCloudInitMedia(savedXML)
	if err != nil {
		return nil, "", err
	}
	savedXML, err = setDomainKubeVirtUID(savedXML, string(vmi.UID))
	if err != nil {
		return nil, "", err
	}
	if err := l.virConn.DomainSaveImageDefineXML(partial, savedXML, 0); err != nil {
		return nil, "", err
	}
	committedXML, err := l.virConn.DomainSaveImageGetXMLDesc(partial, 0)
	if err != nil {
		return nil, "", err
	}
	metadata.DomainXMLHash = hibernation.HashBytes([]byte(committedXML))
	checksum, size, err := checksumFile(partial)
	if err != nil {
		return nil, "", err
	}
	metadata.StateSHA256 = checksum
	metadata.StateSize = size
	metadata.Completed = true
	metadata.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := os.Rename(partial, statePath); err != nil {
		return nil, "", err
	}
	if err := syncPath(statePath); err != nil {
		return nil, "", err
	}
	if err := writeHibernationMetadata(statePath, metadata); err != nil {
		return nil, "", err
	}
	return metadata, hibernation.StateHibernated, nil
}

func (l *LibvirtDomainManager) restoreVMI(vmi *v1.VirtualMachineInstance, statePath string, allowKernelMismatch bool) (*hibernation.Metadata, string, error) {
	metadata, err := readHibernationMetadata(statePath)
	if err != nil {
		return nil, "", err
	}
	if !metadata.Completed {
		return nil, "", fmt.Errorf("incomplete save artifact")
	}
	if metadata.Consumed {
		return nil, "", fmt.Errorf("save artifact was already consumed at %s", metadata.ConsumedAt)
	}
	if metadata.AttemptID != annotation(vmi, hibernation.AttemptAnnotation) {
		return nil, "", fmt.Errorf("attempt identity mismatch")
	}
	if metadata.SourceVMIUID == "" || vmi.UID == "" {
		return nil, "", fmt.Errorf("source and destination VMI identities are required")
	}
	checksum, size, err := checksumFile(statePath)
	if err != nil {
		return nil, "", err
	}
	if checksum != metadata.StateSHA256 || size != metadata.StateSize {
		return nil, "", fmt.Errorf("state artifact checksum or size mismatch")
	}
	savedXML, err := l.virConn.DomainSaveImageGetXMLDesc(statePath, 0)
	if err != nil {
		return nil, "", err
	}
	if hibernation.HashBytes([]byte(savedXML)) != metadata.DomainXMLHash {
		return nil, "", fmt.Errorf("saved domain XML does not match committed metadata")
	}
	current, err := l.currentMetadata(vmi)
	if err != nil {
		return nil, "", err
	}
	compatibilityMismatch := metadata.HostKernelRelease != current.HostKernelRelease || metadata.KVMFingerprint != current.KVMFingerprint
	overrideRequested := allowKernelMismatch && compatibilityMismatch
	if err := hibernation.ValidateCompatibility(*metadata, *current, hibernation.CompatibilityOptions{AllowKernelMismatch: overrideRequested}); err != nil {
		return nil, "", err
	}
	kernelPair := ""
	if overrideRequested {
		kernelPair = fmt.Sprintf("%s[%s] -> %s[%s]", metadata.HostKernelRelease, metadata.KVMFingerprint, current.HostKernelRelease, current.KVMFingerprint)
	}
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
		return nil, "", fmt.Errorf("domain already exists in non-paused state")
	} else if !domainerrors.IsNotFound(lookupErr) {
		return nil, "", lookupErr
	}
	if overrideRequested {
		if metadata.OverrideAttempted {
			return nil, "", fmt.Errorf("lab compatibility override was already attempted for this artifact")
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
	if err := l.virConn.DomainRestoreFlags(statePath, restoreXML, libvirt.DOMAIN_SAVE_PAUSED); err != nil {
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
	metadata, err := readHibernationMetadata(statePath)
	if err != nil {
		return nil, "", err
	}
	if metadata.AttemptID != annotation(vmi, hibernation.AttemptAnnotation) {
		return nil, "", fmt.Errorf("attempt identity mismatch")
	}
	domain, err := l.virConn.LookupDomainByName(api.VMINamespaceKeyFunc(vmi))
	if err != nil {
		if metadata.Consumed {
			return nil, "", fmt.Errorf("%s: consumed artifact has no domain", hibernation.StateRestoreCommitLost)
		}
		return nil, "", err
	}
	defer domain.Free()
	state, _, err := domain.GetState()
	if err != nil {
		return nil, "", err
	}
	if metadata.Consumed {
		if state == libvirt.DOMAIN_RUNNING {
			return metadata, hibernation.StateRunningAwaitingVerification, nil
		}
		return nil, "", fmt.Errorf("%s: consumed artifact domain is not running", hibernation.StateRestoreCommitLost)
	}
	if !cli.IsPaused(state) {
		return nil, "", fmt.Errorf("restored domain must be paused before consumption")
	}
	if annotation(vmi, hibernation.LabFailBeforeConsumeAnnotation) == metadata.AttemptID {
		return nil, "", fmt.Errorf("%s: injected failure before consumed marker", hibernation.StateRestoreCommitLost)
	}
	metadata.Consumed = true
	metadata.ConsumedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := writeHibernationMetadata(statePath, metadata); err != nil {
		return nil, "", err
	}
	if annotation(vmi, hibernation.LabFailAfterConsumeAnnotation) == metadata.AttemptID {
		return nil, "", fmt.Errorf("%s: injected failure after consumed marker before unpause", hibernation.StateRestoreCommitLost)
	}
	if err := domain.Resume(); err != nil {
		return nil, "", fmt.Errorf("%s: consumption committed but unpause failed: %w", hibernation.StateRestoreCommitLost, err)
	}
	return metadata, hibernation.StateRunningAwaitingVerification, nil
}

func (l *LibvirtDomainManager) eraseVMI(vmi *v1.VirtualMachineInstance, statePath string) (*hibernation.Metadata, string, error) {
	metadata, err := readHibernationMetadata(statePath)
	if err != nil {
		return nil, "", err
	}
	if metadata.AttemptID != annotation(vmi, hibernation.AttemptAnnotation) {
		return nil, "", fmt.Errorf("attempt identity mismatch")
	}
	if !metadata.Consumed {
		return nil, "", fmt.Errorf("refusing to erase unconsumed artifact")
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
	kvmParameters, _ := filepath.Glob("/sys/module/kvm*/parameters/*")
	var kvm strings.Builder
	for _, path := range kvmParameters {
		kvm.WriteString(path)
		kvm.WriteByte('=')
		kvm.WriteString(readTrimmed(path))
		kvm.WriteByte('\n')
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
		FormatVersion:     1,
		AttemptID:         attemptID,
		VMUID:             vmUID,
		EffectiveSpecHash: specHash,
		PVCIdentities:     pvcIdentities,
		NodeName:          vmi.Status.NodeName,
		CPUModel:          cpuModel,
		CPUFeatures:       hibernation.HashBytes([]byte(stableCPUFingerprint(cpuInfo))),
		HostKernelRelease: kernel,
		KVMFingerprint:    hibernation.HashBytes([]byte(kvm.String())),
		Microcode:         microcode,
		KubeVirtVersion:   build.GitVersion + "+" + build.GitCommit,
		QEMUVersion:       qemuVersion,
		LibvirtVersion:    fmt.Sprintf("%d", libvirtVersion),
	}, nil
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
	payload, err := os.ReadFile(metadataPath(statePath))
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
	target := metadataPath(statePath)
	temporary := target + ".partial"
	if err := os.WriteFile(temporary, append(payload, '\n'), 0600); err != nil {
		return err
	}
	if err := syncPath(temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, target); err != nil {
		return err
	}
	return syncPath(filepath.Dir(target))
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
