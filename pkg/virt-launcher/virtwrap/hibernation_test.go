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
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"libvirt.org/go/libvirt"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/hibernation"
	"kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/cli"
)

func TestValidateHibernationStatePath(t *testing.T) {
	expected := filepath.Join(hibernation.StateMountPath, "state.save")
	if err := validateStatePath(expected); err != nil {
		t.Fatalf("expected guarded state path: %v", err)
	}
	for _, path := range []string{"state.save", filepath.Join(hibernation.StateMountPath, "../escape"), "/tmp/state.save"} {
		if err := validateStatePath(path); err == nil {
			t.Fatalf("expected %q to be rejected", path)
		}
	}
}

func TestStateWithoutCommittedMetadataIsIncomplete(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.save")
	if err := os.WriteFile(statePath, []byte("unpublished"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireEmptyStateSlot(statePath); err == nil {
		t.Fatal("expected an unpublished state image to be rejected")
	}
}

func TestCPUFingerprintIgnoresDynamicFrequency(t *testing.T) {
	first := "vendor_id: GenuineIntel\nmodel: 1\nflags: a b\ncpu MHz: 1200\n"
	second := "vendor_id: GenuineIntel\nmodel: 1\nflags: a b\ncpu MHz: 4400\n"
	if stableCPUFingerprint(first) != stableCPUFingerprint(second) {
		t.Fatal("dynamic CPU frequency changed the compatibility fingerprint")
	}
}

func TestHibernationLifecycleIsTransactionalAndIdempotent(t *testing.T) {
	ctrl := gomock.NewController(t)
	connection := cli.NewMockConnection(ctrl)
	domain := cli.NewMockVirDomain(ctrl)
	manager := &LibvirtDomainManager{virConn: connection}
	vmi := &v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "tracer",
			UID:       "source-vmi",
			Annotations: map[string]string{
				hibernation.AttemptAnnotation:       "attempt-1",
				hibernation.VMUIDAnnotation:         "vm-uid",
				hibernation.PVCIdentitiesAnnotation: `{"state":"pvc-uid/pv-name"}`,
			},
		},
		Status: v1.VirtualMachineInstanceStatus{NodeName: "node-a"},
	}
	statePath := filepath.Join(t.TempDir(), "state.save")
	domainXML := "<domain><name>default_tracer</name><metadata><kubevirt><uid>source-vmi</uid></kubevirt></metadata><channel path=\"source-vmi/socket\"/></domain>"

	connection.EXPECT().GetQemuVersion().Return("qemu", nil).Times(2)
	connection.EXPECT().GetLibVersion().Return(uint32(1000), nil).Times(2)
	connection.EXPECT().LookupDomainByName("default_tracer").Return(domain, nil)
	domain.EXPECT().GetState().Return(libvirt.DOMAIN_RUNNING, 0, nil)
	domain.EXPECT().SaveFlags(statePath+".partial", "", libvirt.DOMAIN_SAVE_PAUSED).
		DoAndReturn(func(path, _ string, _ libvirt.DomainSaveRestoreFlags) error {
			return os.WriteFile(path, []byte("saved-memory"), 0600)
		})
	connection.EXPECT().DomainSaveImageGetXMLDesc(statePath+".partial", libvirt.DomainSaveImageXMLFlags(0)).Return(domainXML, nil)
	connection.EXPECT().DomainSaveImageDefineXML(statePath+".partial", domainXML, libvirt.DomainSaveRestoreFlags(0)).Return(nil)
	domain.EXPECT().Free().Return(nil)

	metadata, phase, err := manager.saveVMI(vmi, statePath)
	if err != nil || phase != hibernation.StateHibernated || !metadata.Completed || metadata.Consumed {
		t.Fatalf("unexpected save result phase=%q metadata=%+v err=%v", phase, metadata, err)
	}
	if _, phase, err = manager.saveVMI(vmi, statePath); err != nil || phase != hibernation.StateHibernated {
		t.Fatalf("idempotent save failed: phase=%q err=%v", phase, err)
	}

	committedMetadata := *metadata
	metadata.DomainXMLHash = hibernation.HashBytes([]byte("substituted-domain"))
	if err := writeHibernationMetadata(statePath, metadata); err != nil {
		t.Fatal(err)
	}
	connection.EXPECT().DomainSaveImageGetXMLDesc(statePath, libvirt.DomainSaveImageXMLFlags(0)).Return(domainXML, nil)
	if _, _, err := manager.restoreVMI(vmi, statePath, false); err == nil {
		t.Fatal("restore accepted a substituted saved-domain definition")
	}
	if err := writeHibernationMetadata(statePath, &committedMetadata); err != nil {
		t.Fatal(err)
	}

	vmi.UID = "destination-vmi"
	connection.EXPECT().DomainSaveImageGetXMLDesc(statePath, libvirt.DomainSaveImageXMLFlags(0)).Return(domainXML, nil)
	connection.EXPECT().LookupDomainByName("default_tracer").Return(nil, libvirt.Error{Code: libvirt.ERR_NO_DOMAIN})
	restoreXML := "<domain><name>default_tracer</name><metadata><kubevirt><uid>destination-vmi</uid></kubevirt></metadata><channel path=\"destination-vmi/socket\"/></domain>"
	connection.EXPECT().DomainRestoreFlags(statePath, restoreXML, libvirt.DOMAIN_SAVE_PAUSED).Return(nil)
	metadata, phase, err = manager.restoreVMI(vmi, statePath, false)
	if err != nil || phase != hibernation.StateRestoredPaused || metadata.Consumed {
		t.Fatalf("unexpected restore result phase=%q metadata=%+v err=%v", phase, metadata, err)
	}

	connection.EXPECT().LookupDomainByName("default_tracer").Return(domain, nil)
	domain.EXPECT().GetState().Return(libvirt.DOMAIN_PAUSED, 0, nil)
	domain.EXPECT().Resume().Return(nil)
	domain.EXPECT().Free().Return(nil)
	metadata, phase, err = manager.commitAndUnpauseVMI(vmi, statePath)
	if err != nil || phase != hibernation.StateRunningAwaitingVerification || !metadata.Consumed {
		t.Fatalf("unexpected commit result phase=%q metadata=%+v err=%v", phase, metadata, err)
	}

	metadata, phase, err = manager.eraseVMI(vmi, statePath)
	if err != nil || phase != hibernation.StateRunning || metadata.ErasedAt == "" {
		t.Fatalf("unexpected erase result phase=%q metadata=%+v err=%v", phase, metadata, err)
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state image remains after final erasure: %v", err)
	}
}

func TestSetDomainKubeVirtUID(t *testing.T) {
	xml := "<domain><metadata><kubevirt><uid/></kubevirt></metadata></domain>"
	updated, err := setDomainKubeVirtUID(xml, "destination-vmi")
	if err != nil {
		t.Fatal(err)
	}
	if updated != "<domain><metadata><kubevirt><uid>destination-vmi</uid></kubevirt></metadata></domain>" {
		t.Fatalf("unexpected domain metadata: %s", updated)
	}
}
