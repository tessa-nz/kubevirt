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
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"libvirt.org/go/libvirt"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/hibernation"
	"kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/cli"
)

func TestCommitRecoversLostUnpauseResponseWithoutReplay(t *testing.T) {
	ctrl := gomock.NewController(t)
	connection := cli.NewMockConnection(ctrl)
	domain := cli.NewMockVirDomain(ctrl)
	manager := &LibvirtDomainManager{virConn: connection}
	statePath := filepath.Join(t.TempDir(), "state.save")
	if err := writeHibernationMetadata(statePath, &hibernation.Metadata{AttemptID: "attempt-1"}); err != nil {
		t.Fatal(err)
	}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default", Name: "tracer",
		Annotations: map[string]string{hibernation.AttemptAnnotation: "attempt-1"},
	}}
	connection.EXPECT().LookupDomainByName("default_tracer").Return(domain, nil).Times(2)
	gomock.InOrder(
		domain.EXPECT().GetState().Return(libvirt.DOMAIN_PAUSED, 0, nil),
		domain.EXPECT().Resume().Return(context.DeadlineExceeded),
		domain.EXPECT().GetState().Return(libvirt.DOMAIN_RUNNING, 0, nil),
	)
	domain.EXPECT().Free().Return(nil).Times(2)
	if _, _, err := manager.commitAndUnpauseVMI(vmi, statePath); err == nil || hibernation.RejectionPhase(err) != "" {
		t.Fatalf("lost unpause response must remain an unknown outcome: %v", err)
	}
	metadata, phase, err := manager.commitAndUnpauseVMI(vmi, statePath)
	if err != nil || phase != hibernation.StateRunningAwaitingVerification || !metadata.Consumed {
		t.Fatalf("failed to recover the running domain: phase=%s err=%v", phase, err)
	}
}

func TestCommitDoesNotDestroyGuestAfterLookupTimeout(t *testing.T) {
	ctrl := gomock.NewController(t)
	connection := cli.NewMockConnection(ctrl)
	manager := &LibvirtDomainManager{virConn: connection}
	statePath := filepath.Join(t.TempDir(), "state.save")
	if err := writeHibernationMetadata(statePath, &hibernation.Metadata{AttemptID: "attempt-1", Consumed: true}); err != nil {
		t.Fatal(err)
	}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default", Name: "tracer",
		Annotations: map[string]string{hibernation.AttemptAnnotation: "attempt-1"},
	}}
	connection.EXPECT().LookupDomainByName("default_tracer").Return(nil, context.DeadlineExceeded)
	if _, _, err := manager.commitAndUnpauseVMI(vmi, statePath); !errors.Is(err, context.DeadlineExceeded) || hibernation.RejectionPhase(err) != "" {
		t.Fatalf("lookup timeout was treated as proof of a lost domain: %v", err)
	}
}

func TestSaveRejectionPreservesExistingRunningGuest(t *testing.T) {
	ctrl := gomock.NewController(t)
	connection := cli.NewMockConnection(ctrl)
	domain := cli.NewMockVirDomain(ctrl)
	manager := &LibvirtDomainManager{virConn: connection}
	statePath := filepath.Join(t.TempDir(), "state.save")
	if err := os.WriteFile(statePath+".partial", []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "tracer"}}
	connection.EXPECT().LookupDomainByName("default_tracer").Return(domain, nil)
	domain.EXPECT().GetState().Return(libvirt.DOMAIN_RUNNING, 0, nil)
	domain.EXPECT().Free().Return(nil)
	if _, _, err := manager.saveVMI(vmi, statePath); hibernation.RejectionPhase(err) != hibernation.StateSaveRejected {
		t.Fatalf("expected a non-destructive save rejection: %v", err)
	}
}

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
	committedDomainXML := "<domain>\n  <name>default_tracer</name><metadata><kubevirt><uid>source-vmi</uid></kubevirt></metadata><channel path=\"source-vmi/socket\"/>\n</domain>"

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
	connection.EXPECT().DomainSaveImageGetXMLDesc(statePath+".partial", libvirt.DomainSaveImageXMLFlags(0)).Return(committedDomainXML, nil)
	domain.EXPECT().Free().Return(nil)

	metadata, phase, err := manager.saveVMI(vmi, statePath)
	if err != nil || phase != hibernation.StateHibernated || !metadata.Completed || metadata.Consumed {
		t.Fatalf("unexpected save result phase=%q metadata=%+v err=%v", phase, metadata, err)
	}
	if metadata.DomainXMLHash != hibernation.HashBytes([]byte(committedDomainXML)) {
		t.Fatal("save metadata did not hash libvirt's committed domain XML")
	}
	if _, err := os.Stat(hibernation.SaveInProgressPath); err != nil {
		t.Fatalf("save marker was removed before the RPC response: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(hibernation.SaveInProgressPath) })
	if _, phase, err = manager.saveVMI(vmi, statePath); err != nil || phase != hibernation.StateHibernated {
		t.Fatalf("idempotent save failed: phase=%q err=%v", phase, err)
	}

	committedMetadata := *metadata
	vmi.Annotations[hibernation.ArtifactDigestAnnotation], err = hibernation.ArtifactDigest(committedMetadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata.DomainXMLHash = hibernation.HashBytes([]byte("substituted-domain"))
	if err := writeHibernationMetadata(statePath, metadata); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.restoreVMI(vmi, statePath, false); err == nil {
		t.Fatal("restore accepted a substituted saved-domain definition")
	}
	if err := writeHibernationMetadata(statePath, &committedMetadata); err != nil {
		t.Fatal(err)
	}

	vmi.UID = "destination-vmi"
	connection.EXPECT().DomainSaveImageGetXMLDesc(statePath, libvirt.DomainSaveImageXMLFlags(0)).Return(committedDomainXML, nil)
	connection.EXPECT().LookupDomainByName("default_tracer").Return(nil, libvirt.Error{Code: libvirt.ERR_NO_DOMAIN})
	restoreXML := strings.ReplaceAll(committedDomainXML, "source-vmi", "destination-vmi")
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

func TestEjectTransientCloudInitMedia(t *testing.T) {
	xml := `<domain><devices>` +
		`<disk type="file" device="disk"><source file="/persistent/root.img"/><target dev="vda"/></disk>` +
		`<disk type="file" device="cdrom"><source file="/var/run/kubevirt-ephemeral-disks/cloud-init-data/default/tracer/noCloud.iso"/><target dev="sda"/></disk>` +
		`</devices></domain>`
	updated, err := ejectTransientCloudInitMedia(xml)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(updated, "cloud-init-data") {
		t.Fatalf("transient cloud-init media remains in saved XML: %s", updated)
	}
	if !strings.Contains(updated, "/persistent/root.img") {
		t.Fatalf("persistent guest disk was removed: %s", updated)
	}
	if !strings.Contains(updated, `device="cdrom"`) {
		t.Fatalf("cloud-init CD-ROM device was removed instead of ejected: %s", updated)
	}
}

func TestCommitFailureBeforeConsumedMarkerIsTerminalAndUnconsumed(t *testing.T) {
	if !hibernation.LabEnabled {
		t.Skip("fault injection requires the hibernation_lab build tag")
	}
	ctrl := gomock.NewController(t)
	connection := cli.NewMockConnection(ctrl)
	domain := cli.NewMockVirDomain(ctrl)
	manager := &LibvirtDomainManager{virConn: connection}
	statePath := filepath.Join(t.TempDir(), "state.save")
	metadata := &hibernation.Metadata{AttemptID: "attempt-1"}
	if err := writeHibernationMetadata(statePath, metadata); err != nil {
		t.Fatal(err)
	}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "tracer",
		Annotations: map[string]string{
			hibernation.AttemptAnnotation:              "attempt-1",
			hibernation.LabFailBeforeConsumeAnnotation: "attempt-1",
		},
	}}
	connection.EXPECT().LookupDomainByName("default_tracer").Return(domain, nil)
	domain.EXPECT().GetState().Return(libvirt.DOMAIN_PAUSED, 0, nil)
	domain.EXPECT().Free().Return(nil)

	if _, _, err := manager.commitAndUnpauseVMI(vmi, statePath); hibernation.RejectionPhase(err) != hibernation.StateRestoreCommitLost {
		t.Fatalf("expected terminal injected failure before consumption, got %v", err)
	}
	committed, err := readHibernationMetadata(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if committed.Consumed {
		t.Fatal("failure before marker consumed the artifact")
	}
}

func TestCommitFailureAfterConsumedMarkerCannotReplay(t *testing.T) {
	if !hibernation.LabEnabled {
		t.Skip("fault injection requires the hibernation_lab build tag")
	}
	ctrl := gomock.NewController(t)
	connection := cli.NewMockConnection(ctrl)
	domain := cli.NewMockVirDomain(ctrl)
	manager := &LibvirtDomainManager{virConn: connection}
	statePath := filepath.Join(t.TempDir(), "state.save")
	metadata := &hibernation.Metadata{AttemptID: "attempt-1"}
	if err := writeHibernationMetadata(statePath, metadata); err != nil {
		t.Fatal(err)
	}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "tracer",
		Annotations: map[string]string{
			hibernation.AttemptAnnotation:             "attempt-1",
			hibernation.LabFailAfterConsumeAnnotation: "attempt-1",
		},
	}}
	first := connection.EXPECT().LookupDomainByName("default_tracer").Return(domain, nil)
	domain.EXPECT().GetState().After(first).Return(libvirt.DOMAIN_PAUSED, 0, nil)
	domain.EXPECT().Free().Return(nil)

	if _, _, err := manager.commitAndUnpauseVMI(vmi, statePath); hibernation.RejectionPhase(err) != hibernation.StateRestoreCommitLost {
		t.Fatalf("expected terminal injected failure after consumption, got %v", err)
	}
	committed, err := readHibernationMetadata(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !committed.Consumed {
		t.Fatal("failure after marker did not durably consume the artifact")
	}

	delete(vmi.Annotations, hibernation.LabFailAfterConsumeAnnotation)
	second := connection.EXPECT().LookupDomainByName("default_tracer").Return(domain, nil)
	domain.EXPECT().GetState().After(second).Return(libvirt.DOMAIN_PAUSED, 0, nil)
	domain.EXPECT().Free().Return(nil)
	if _, _, err := manager.commitAndUnpauseVMI(vmi, statePath); hibernation.RejectionPhase(err) != hibernation.StateRestoreCommitLost {
		t.Fatalf("consumed paused artifact was replayable: %v", err)
	}
}

func TestHibernationRejectsCoherentArtifactTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.save")
	original := hibernation.Metadata{Completed: true, AttemptID: "attempt", VMUID: "vm", StateSHA256: hibernation.HashBytes([]byte("original")), StateSize: 8}
	digest, err := hibernation.ArtifactDigest(original)
	if err != nil {
		t.Fatal(err)
	}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{hibernation.ArtifactDigestAnnotation: digest}}}
	// An attacker can replace both the RAM image and its neighboring checksum.
	// The controller's protected record still refers to the original save.
	payload := []byte("replacement RAM")
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	original.StateSHA256 = hibernation.HashBytes(payload)
	original.StateSize = int64(len(payload))
	if err := writeHibernationMetadata(path, &original); err != nil {
		t.Fatal(err)
	}
	manager := &LibvirtDomainManager{} // A rejection must occur before any libvirt call.
	if _, _, err := manager.restoreVMI(vmi, path, false); hibernation.RejectionPhase(err) != hibernation.StateResumeRejected {
		t.Fatalf("forged artifact accepted: %v", err)
	}
}

func TestHibernationProductionBuildIgnoresFaultAnnotations(t *testing.T) {
	if hibernation.LabEnabled {
		t.Skip("production build assertion")
	}
	ctrl := gomock.NewController(t)
	connection := cli.NewMockConnection(ctrl)
	domain := cli.NewMockVirDomain(ctrl)
	manager := &LibvirtDomainManager{virConn: connection}
	path := filepath.Join(t.TempDir(), "state.save")
	if err := writeHibernationMetadata(path, &hibernation.Metadata{AttemptID: "attempt"}); err != nil {
		t.Fatal(err)
	}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "tracer", Annotations: map[string]string{
		hibernation.AttemptAnnotation: "attempt", hibernation.LabFailBeforeConsumeAnnotation: "attempt", hibernation.LabFailAfterConsumeAnnotation: "attempt",
	}}}
	connection.EXPECT().LookupDomainByName("default_tracer").Return(domain, nil)
	domain.EXPECT().GetState().Return(libvirt.DOMAIN_PAUSED, 0, nil)
	domain.EXPECT().Resume().Return(nil)
	domain.EXPECT().Free().Return(nil)
	metadata, phase, err := manager.commitAndUnpauseVMI(vmi, path)
	if err != nil || !metadata.Consumed || phase != hibernation.StateRunningAwaitingVerification {
		t.Fatalf("lab annotations affected production operation: %s %v", phase, err)
	}
}

func TestHibernationBlocksLauncherLifecycleMutation(t *testing.T) {
	manager := &LibvirtDomainManager{} // No libvirt call is permitted.
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{hibernation.StateAnnotation: hibernation.StateRestoredPaused}}}
	for _, operation := range []struct {
		name string
		run  func(*v1.VirtualMachineInstance) error
	}{{"pause", manager.PauseVMI}, {"unpause", manager.UnpauseVMI}, {"reset", manager.ResetVMI}, {"softreboot", manager.SoftRebootVMI}, {"unfreeze", manager.UnfreezeVMI}} {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.run(vmi); err == nil {
				t.Fatal("active attempt allowed unrelated lifecycle mutation")
			}
		})
	}
	if err := manager.FreezeVMI(vmi, 30); err == nil {
		t.Fatal("active attempt allowed freeze")
	}
}
