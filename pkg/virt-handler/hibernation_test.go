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

package virthandler

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "kubevirt.io/api/core/v1"

	cmdv1 "kubevirt.io/kubevirt/pkg/handler-launcher-com/cmd/v1"
	"kubevirt.io/kubevirt/pkg/hibernation"
	cmdclient "kubevirt.io/kubevirt/pkg/virt-handler/cmd-client"
	"kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/api"
)

func TestSyncHibernationSaveIsDispatchedAndPublished(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := cmdclient.NewMockLauncherClient(ctrl)
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		hibernation.RequestAnnotation: hibernation.RequestSave,
		hibernation.AttemptAnnotation: "same-attempt",
		hibernation.VMUIDAnnotation:   "vm-uid",
	}}}
	client.EXPECT().HibernateVirtualMachine(vmi, cmdv1.HibernationAction_HIBERNATION_ACTION_SAVE, hibernation.StateMountPath+"/state.save", false).
		Return(hibernationResponse(t, vmi, hibernation.StateHibernated), nil)
	controller := &VirtualMachineController{}
	if err := controller.syncHibernation(client, vmi, hibernation.RequestSave); err != nil {
		t.Fatal(err)
	}
	if vmi.Annotations[hibernation.StateAnnotation] != hibernation.StateHibernated {
		t.Fatalf("unexpected state %q", vmi.Annotations[hibernation.StateAnnotation])
	}
	if _, exists := vmi.Annotations[hibernation.RequestAnnotation]; exists {
		t.Fatal("completed request must be cleared")
	}
}

func TestSyncHibernationCommitFailureIsTerminal(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := cmdclient.NewMockLauncherClient(ctrl)
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
	client.EXPECT().HibernateVirtualMachine(gomock.Any(), cmdv1.HibernationAction_HIBERNATION_ACTION_COMMIT_UNPAUSE, gomock.Any(), false).
		Return(&cmdv1.HibernationResponse{Response: &cmdv1.Response{Success: false}, Phase: hibernation.StateRestoreCommitLost}, errors.New("lost after consumed marker"))
	controller := &VirtualMachineController{}
	if err := controller.syncHibernation(client, vmi, hibernation.RequestCommitUnpause); err == nil {
		t.Fatal("expected commit failure")
	}
	if vmi.Annotations[hibernation.StateAnnotation] != hibernation.StateRestoreCommitLost {
		t.Fatalf("unexpected terminal state %q", vmi.Annotations[hibernation.StateAnnotation])
	}
}

func TestSyncHibernationRetriesUnknownOutcomesWithoutTerminalizing(t *testing.T) {
	for _, failure := range []error{context.DeadlineExceeded, status.Error(codes.Unavailable, "launcher connection lost"), errors.New("libvirt lookup timed out")} {
		for _, operation := range []struct {
			request, phase, completed string
			action                    cmdv1.HibernationAction
		}{
			{hibernation.RequestSave, hibernation.StateSaving, hibernation.StateHibernated, cmdv1.HibernationAction_HIBERNATION_ACTION_SAVE},
			{hibernation.RequestRestorePaused, hibernation.StateRestoring, hibernation.StateRestoredPaused, cmdv1.HibernationAction_HIBERNATION_ACTION_RESTORE_PAUSED},
			{hibernation.RequestCommitUnpause, hibernation.StateRestoreCommittedPaused, hibernation.StateRunningAwaitingVerification, cmdv1.HibernationAction_HIBERNATION_ACTION_COMMIT_UNPAUSE},
			{hibernation.RequestErase, hibernation.StateRunningAwaitingVerification, hibernation.StateRunning, cmdv1.HibernationAction_HIBERNATION_ACTION_ERASE},
		} {
			t.Run(operation.request+"/"+failure.Error(), func(t *testing.T) {
				ctrl := gomock.NewController(t)
				client := cmdclient.NewMockLauncherClient(ctrl)
				vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
					hibernation.RequestAnnotation: operation.request,
					hibernation.StateAnnotation:   operation.phase,
					hibernation.AttemptAnnotation: "same-attempt",
					hibernation.VMUIDAnnotation:   "vm-uid",
				}}}
				gomock.InOrder(
					client.EXPECT().HibernateVirtualMachine(vmi, operation.action, gomock.Any(), false).Return(nil, failure),
					client.EXPECT().HibernateVirtualMachine(vmi, operation.action, gomock.Any(), false).Return(hibernationResponse(t, vmi, operation.completed), nil),
				)
				controller := &VirtualMachineController{}
				if err := controller.syncHibernation(client, vmi, operation.request); err == nil {
					t.Fatal("unknown outcome must be retried")
				}
				if vmi.Annotations[hibernation.StateAnnotation] != operation.phase || vmi.Annotations[hibernation.RequestAnnotation] != operation.request || vmi.Annotations[hibernation.AttemptAnnotation] != "same-attempt" {
					t.Fatal("transport failure changed the lifecycle or attempt")
				}
				if err := controller.syncHibernation(client, vmi, operation.request); err != nil {
					t.Fatal(err)
				}
				if vmi.Annotations[hibernation.StateAnnotation] != operation.completed {
					t.Fatalf("retry did not recover: %q", vmi.Annotations[hibernation.StateAnnotation])
				}
			})
		}
	}
}

func hibernationResponse(t *testing.T, vmi *v1.VirtualMachineInstance, phase string) *cmdv1.HibernationResponse {
	t.Helper()
	metadata, err := json.Marshal(hibernation.Metadata{
		Completed: true,
		AttemptID: vmi.Annotations[hibernation.AttemptAnnotation],
		VMUID:     vmi.Annotations[hibernation.VMUIDAnnotation],
	})
	if err != nil {
		t.Fatal(err)
	}
	return &cmdv1.HibernationResponse{Response: &cmdv1.Response{Success: true}, Phase: phase, MetadataJson: metadata}
}

func TestSyncHibernationPublishesPausedRestoreBeforeCommitAndUnpause(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := cmdclient.NewMockLauncherClient(ctrl)
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
	client.EXPECT().HibernateVirtualMachine(vmi, cmdv1.HibernationAction_HIBERNATION_ACTION_RESTORE_PAUSED, hibernation.StateMountPath+"/state.save", false).
		Return(&cmdv1.HibernationResponse{Phase: hibernation.StateRestoredPaused}, nil)
	controller := &VirtualMachineController{}
	if err := controller.syncHibernation(client, vmi, hibernation.RequestRestorePaused); err != nil {
		t.Fatal(err)
	}
	if vmi.Annotations[hibernation.StateAnnotation] != hibernation.StateRestoredPaused {
		t.Fatalf("unexpected state %q", vmi.Annotations[hibernation.StateAnnotation])
	}
}

func TestSyncHibernationCommitsAndUnpausesOnlyAfterSeparateDispatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := cmdclient.NewMockLauncherClient(ctrl)
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
	client.EXPECT().HibernateVirtualMachine(vmi, cmdv1.HibernationAction_HIBERNATION_ACTION_COMMIT_UNPAUSE, hibernation.StateMountPath+"/state.save", false).
		Return(&cmdv1.HibernationResponse{Phase: hibernation.StateRunningAwaitingVerification}, nil)
	controller := &VirtualMachineController{}
	if err := controller.syncHibernation(client, vmi, hibernation.RequestCommitUnpause); err != nil {
		t.Fatal(err)
	}
	if vmi.Annotations[hibernation.StateAnnotation] != hibernation.StateRunningAwaitingVerification {
		t.Fatalf("unexpected state %q", vmi.Annotations[hibernation.StateAnnotation])
	}
}

func TestHibernationRequestBypassesPhaseOptimization(t *testing.T) {
	vmi := &v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			hibernation.RequestAnnotation: hibernation.RequestCommitUnpause,
		}},
		Status: v1.VirtualMachineInstanceStatus{Phase: v1.Scheduled},
	}
	if !shouldProcessVMIUpdate(vmi, v1.Running) {
		t.Fatal("commit-unpause must be processed while the restored VMI is still Scheduled")
	}
	delete(vmi.Annotations, hibernation.RequestAnnotation)
	if shouldProcessVMIUpdate(vmi, v1.Running) {
		t.Fatal("ordinary updates must retain the phase optimization")
	}
}

func TestHibernationRequestBypassesRestoredDomainMigrationGuard(t *testing.T) {
	vmi := &v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			hibernation.RequestAnnotation: hibernation.RequestCommitUnpause,
		}},
	}
	domain := &api.Domain{Status: api.DomainStatus{
		Status: api.Paused,
		Reason: api.ReasonPausedMigration,
	}}
	if shouldIgnoreInProgressMigration(vmi, domain) {
		t.Fatal("commit-unpause must not be mistaken for a live migration")
	}
	delete(vmi.Annotations, hibernation.RequestAnnotation)
	if !shouldIgnoreInProgressMigration(vmi, domain) {
		t.Fatal("ordinary paused migration must retain the migration guard")
	}
}
