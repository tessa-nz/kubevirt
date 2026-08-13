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
	"errors"
	"testing"

	"go.uber.org/mock/gomock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "kubevirt.io/api/core/v1"

	cmdv1 "kubevirt.io/kubevirt/pkg/handler-launcher-com/cmd/v1"
	"kubevirt.io/kubevirt/pkg/hibernation"
	cmdclient "kubevirt.io/kubevirt/pkg/virt-handler/cmd-client"
)

func TestSyncHibernationSaveIsDispatchedAndPublished(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := cmdclient.NewMockLauncherClient(ctrl)
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		hibernation.RequestAnnotation: hibernation.RequestSave,
	}}}
	client.EXPECT().HibernateVirtualMachine(vmi, cmdv1.HibernationAction_HIBERNATION_ACTION_SAVE, hibernation.StateMountPath+"/state.save", false).
		Return(&cmdv1.HibernationResponse{Phase: hibernation.StateHibernated}, nil)
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
		Return(nil, errors.New("lost after consumed marker"))
	controller := &VirtualMachineController{}
	if err := controller.syncHibernation(client, vmi, hibernation.RequestCommitUnpause); err == nil {
		t.Fatal("expected commit failure")
	}
	if vmi.Annotations[hibernation.StateAnnotation] != hibernation.StateRestoreCommitLost {
		t.Fatalf("unexpected terminal state %q", vmi.Annotations[hibernation.StateAnnotation])
	}
}

func TestSyncHibernationRestoresPausedBeforeCommitAndUnpause(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := cmdclient.NewMockLauncherClient(ctrl)
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
	first := client.EXPECT().HibernateVirtualMachine(vmi, cmdv1.HibernationAction_HIBERNATION_ACTION_RESTORE_PAUSED, hibernation.StateMountPath+"/state.save", false).
		Return(&cmdv1.HibernationResponse{Phase: hibernation.StateRestoredPaused}, nil)
	client.EXPECT().HibernateVirtualMachine(vmi, cmdv1.HibernationAction_HIBERNATION_ACTION_COMMIT_UNPAUSE, hibernation.StateMountPath+"/state.save", false).
		After(first).
		Return(&cmdv1.HibernationResponse{Phase: hibernation.StateRunningAwaitingVerification}, nil)
	controller := &VirtualMachineController{}
	if err := controller.syncHibernation(client, vmi, hibernation.RequestRestorePaused); err != nil {
		t.Fatal(err)
	}
	if vmi.Annotations[hibernation.StateAnnotation] != hibernation.StateRunningAwaitingVerification {
		t.Fatalf("unexpected state %q", vmi.Annotations[hibernation.StateAnnotation])
	}
}
