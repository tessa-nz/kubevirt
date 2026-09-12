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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/api"
	"kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/cli"
	domainerrors "kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/errors"
	"libvirt.org/go/libvirt"

	"golang.org/x/sys/unix"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/kubevirt/pkg/hibernation"
	"kubevirt.io/kubevirt/pkg/hibernation/protection"
)

func (l *LibvirtDomainManager) hibernationPublicKey() (protection.PublicKey, error) {
	context := l.hibernationContext
	if context == nil || context.Provider != protection.Provider || context.KeyID == "" || context.Recipient == "" {
		return protection.PublicKey{}, fmt.Errorf("TPM encryption recipient is required")
	}
	return protection.PublicKey{ID: context.KeyID, Recipient: context.Recipient}, nil
}

func hibernationStage(vmi *v1.VirtualMachineInstance) (string, error) {
	if err := protection.RequireProtectedMemory(); err != nil {
		return "", err
	}
	if err := protection.RequireMemoryFilesystem(hibernation.StagingMountPath); err != nil {
		return "", err
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(hibernation.StagingMountPath, &stat); err != nil {
		return "", err
	}
	capacity := hibernation.StateCapacity(vmi)
	if uint64(stat.Bsize)*stat.Blocks < uint64(capacity.Value()) {
		return "", fmt.Errorf("private staging is smaller than the current guest save reservation")
	}
	attempt := annotation(vmi, hibernation.AttemptAnnotation)
	if attempt == "" || len(attempt) > 128 {
		return "", fmt.Errorf("bounded attempt identity is required")
	}
	for _, c := range attempt {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return "", fmt.Errorf("invalid attempt identity")
		}
	}
	directory := filepath.Join(hibernation.StagingMountPath, attempt)
	if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", fmt.Errorf("hibernation stage must be a private directory")
	}
	return filepath.Join(directory, "state.save"), nil
}

func openRegularFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("hibernation artifact must be a regular file")
	}
	return file, nil
}

func readBoundedRegularFile(path string, limit int64) ([]byte, error) {
	file, err := openRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("hibernation metadata exceeds its size limit")
	}
	return data, nil
}

func publishEncryptedHibernation(stage, statePath string, key protection.PublicKey, metadata *hibernation.Metadata) error {
	source, err := openRegularFile(stage)
	if err != nil {
		return err
	}
	defer source.Close()
	output, err := os.CreateTemp(filepath.Dir(statePath), ".encrypted-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(output.Name())
	defer output.Close()
	info, err := protection.EncryptImage(source, output, key)
	if err != nil {
		return err
	}
	if info.PlaintextSHA256 != metadata.PlaintextSHA256 || info.PlaintextSize != metadata.PlaintextSize {
		return fmt.Errorf("private stage changed during encryption")
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := os.Rename(output.Name(), statePath); err != nil {
		return err
	}
	if err := syncPath(filepath.Dir(statePath)); err != nil {
		return err
	}
	metadata.StateSHA256, metadata.StateSize = info.CiphertextSHA256, info.CiphertextSize
	return writeHibernationMetadata(statePath, metadata)
}

func (l *LibvirtDomainManager) decryptHibernation(vmi *v1.VirtualMachineInstance, statePath string, metadata *hibernation.Metadata) (string, error) {
	public, err := l.hibernationPublicKey()
	if err != nil {
		return "", err
	}
	if metadata.FormatVersion != 2 || metadata.ProtectionProvider != protection.Provider || metadata.ProtectionKeyID != public.ID || metadata.ProtectionRecipient != public.Recipient {
		return "", fmt.Errorf("artifact is not protected by this attempt's TPM key")
	}
	private := &protection.PrivateKey{PublicKey: public, Identity: l.hibernationContext.PrivateIdentity}
	if len(private.Identity) == 0 {
		return "", fmt.Errorf("TPM restore identity is required")
	}
	capacity := hibernation.StateCapacity(vmi)
	if metadata.PlaintextSize > capacity.Value() {
		return "", fmt.Errorf("saved image exceeds the private staging reservation")
	}
	stage, err := hibernationStage(vmi)
	if err != nil {
		return "", err
	}
	source, err := openRegularFile(statePath)
	if err != nil {
		return "", err
	}
	defer source.Close()
	file, err := os.CreateTemp(filepath.Dir(stage), "restore-*")
	if err != nil {
		return "", err
	}
	succeeded := false
	defer func() {
		file.Close()
		if !succeeded {
			os.Remove(file.Name())
		}
	}()
	expected := protection.ImageInfo{CiphertextSHA256: metadata.StateSHA256, CiphertextSize: metadata.StateSize, PlaintextSHA256: metadata.PlaintextSHA256, PlaintextSize: metadata.PlaintextSize}
	if err := protection.DecryptImage(source, file, private, expected); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	succeeded = true
	return file.Name(), nil
}

func (l *LibvirtDomainManager) completeHibernationStage(vmi *v1.VirtualMachineInstance, stage string, metadata *hibernation.Metadata) error {
	_, stageErr := os.Lstat(stage)
	if stageErr != nil && !errors.Is(stageErr, os.ErrNotExist) {
		return stageErr
	}
	if errors.Is(stageErr, os.ErrNotExist) {
		domain, err := l.virConn.LookupDomainByName(api.VMINamespaceKeyFunc(vmi))
		if err != nil {
			return err
		}
		defer domain.Free()
		state, _, err := domain.GetState()
		if err != nil {
			return err
		}
		if state != libvirt.DOMAIN_RUNNING {
			return fmt.Errorf("save requires the original running domain")
		}
		if err := writeDurableFile(hibernation.SaveInProgressPath, []byte(metadata.AttemptID)); err != nil {
			return err
		}
		if err := domain.SaveFlags(stage, "", libvirt.DOMAIN_SAVE_PAUSED); err != nil {
			rejection := l.rejectSave(vmi, err)
			if hibernation.RejectionPhase(rejection) == hibernation.StateSaveRejected {
				_ = os.Remove(stage)
				_ = os.Remove(metadataPath(stage))
				_ = os.Remove(hibernation.SaveInProgressPath)
				return rejection
			}
			// Libvirt may have completed the save despite a lost acknowledgement.
			// Keep the private descriptor and let the next retry inspect its image.
			return fmt.Errorf("save outcome requires private-image recovery: %w", err)
		}
	} else {
		if readTrimmed(hibernation.SaveInProgressPath) != metadata.AttemptID {
			return fmt.Errorf("private save image has no matching in-progress attempt")
		}
		domain, err := l.virConn.LookupDomainByName(api.VMINamespaceKeyFunc(vmi))
		if err == nil {
			defer domain.Free()
			state, _, err := domain.GetState()
			if err != nil {
				return err
			}
			if !cli.IsDown(state) {
				return fmt.Errorf("cannot publish a saved image while its source domain is still active")
			}
		} else if !domainerrors.IsNotFound(err) {
			return err
		}
	}
	// Libvirt validates its completed-save header here (rejecting the partial
	// magic). Never interpret a nonempty file as proof that saving finished.
	savedXML, err := l.virConn.DomainSaveImageGetXMLDesc(stage, 0)
	if err != nil {
		return err
	}
	savedXML, err = ejectTransientCloudInitMedia(savedXML)
	if err != nil {
		return err
	}
	savedXML, err = setDomainKubeVirtUID(savedXML, string(vmi.UID))
	if err != nil {
		return err
	}
	if err := l.virConn.DomainSaveImageDefineXML(stage, savedXML, 0); err != nil {
		return err
	}
	committedXML, err := l.virConn.DomainSaveImageGetXMLDesc(stage, 0)
	if err != nil {
		return err
	}
	metadata.DomainXMLHash = hibernation.HashBytes([]byte(committedXML))
	metadata.PlaintextSHA256, metadata.PlaintextSize, err = checksumFile(stage)
	if err != nil {
		return err
	}
	metadata.Completed = true
	metadata.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return writeHibernationMetadata(stage, metadata)
}
