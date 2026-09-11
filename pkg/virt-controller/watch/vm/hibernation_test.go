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

package vm

import (
	"context"
	"encoding/json"
	"testing"

	"go.uber.org/mock/gomock"
	"kubevirt.io/client-go/kubecli"

	k8score "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/hibernation"
)

func TestAlwaysDoesNotColdStartHibernatedVM(t *testing.T) {
	controller := &Controller{}
	strategy := v1.RunStrategyAlways
	vm := &v1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{hibernation.StateAnnotation: hibernation.StateHibernated}},
		Spec:       v1.VirtualMachineSpec{RunStrategy: &strategy},
	}
	result, syncErr := controller.syncRunStrategy(vm, nil, strategy)
	if syncErr != nil {
		t.Fatal(syncErr)
	}
	if result != vm {
		t.Fatal("suppression should not create or replace the VM")
	}
}

func TestRestoreVMIStartsWithRestoreInsteadOfColdSync(t *testing.T) {
	strategy := v1.RunStrategyAlways
	vm := &v1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			hibernation.StatePVCAnnotation:             "state",
			hibernation.StateAnnotation:                hibernation.StateRestoring,
			hibernation.RequestAnnotation:              hibernation.RequestResume,
			hibernation.AttemptAnnotation:              "attempt",
			hibernation.VMUIDAnnotation:                "vm-uid",
			hibernation.PVCIdentitiesAnnotation:        `{"state":"pvc-uid/pv"}`,
			hibernation.LabFailBeforeConsumeAnnotation: "attempt",
			hibernation.LabFailAfterConsumeAnnotation:  "attempt",
		}},
		Spec: v1.VirtualMachineSpec{RunStrategy: &strategy, Template: &v1.VirtualMachineInstanceTemplateSpec{}},
	}
	vmi := SetupVMIFromVM(vm)
	if vmi.Annotations[hibernation.RequestAnnotation] != hibernation.RequestRestorePaused {
		t.Fatalf("expected restore-paused request, got %q", vmi.Annotations[hibernation.RequestAnnotation])
	}
	if vmi.Annotations[hibernation.StatePVCAnnotation] != "state" {
		t.Fatal("state PVC identity was not propagated before pod rendering")
	}
	if vmi.Annotations[hibernation.LabFailBeforeConsumeAnnotation] != "attempt" ||
		vmi.Annotations[hibernation.LabFailAfterConsumeAnnotation] != "attempt" {
		t.Fatal("lab consumed-marker fault injection was not propagated to the restore VMI")
	}
}

func TestRestoreRefreshesCurrentPVCIdentityBeforeLauncherCreation(t *testing.T) {
	volumeMode := k8score.PersistentVolumeFilesystem
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	if err := store.Add(&k8score.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "substitute", UID: types.UID("new-pvc-uid")},
		Spec: k8score.PersistentVolumeClaimSpec{
			VolumeMode: &volumeMode,
			VolumeName: "new-pv",
		},
	}); err != nil {
		t.Fatal(err)
	}
	controller := &Controller{pvcStore: store}
	vm := &v1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Annotations: map[string]string{
			hibernation.StateAnnotation:         hibernation.StateRestoring,
			hibernation.StatePVCAnnotation:      "substitute",
			hibernation.PVCIdentitiesAnnotation: `{"state":"old-pvc-uid/old-pv"}`,
		}},
		Spec: v1.VirtualMachineSpec{Template: &v1.VirtualMachineInstanceTemplateSpec{}},
	}
	vmi := SetupVMIFromVM(vm)
	if err := controller.refreshVMIHibernationPVCIdentities(vm, vmi); err != nil {
		t.Fatal(err)
	}
	identities := map[string]string{}
	if err := json.Unmarshal([]byte(vmi.Annotations[hibernation.PVCIdentitiesAnnotation]), &identities); err != nil {
		t.Fatal(err)
	}
	if identities["state"] != "new-pvc-uid/new-pv" {
		t.Fatalf("expected current substituted PVC identity, got %q", identities["state"])
	}
}

func TestHibernationOutcomeUsesMatchingHandlerCondition(t *testing.T) {
	vmi := &v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			hibernation.StateAnnotation: hibernation.StateHibernated,
		}},
		Status: v1.VirtualMachineInstanceStatus{Conditions: []v1.VirtualMachineInstanceCondition{{
			Type:    v1.VirtualMachineInstanceConditionType(hibernation.VMIConditionType),
			Status:  "True",
			Reason:  hibernation.StateHibernated,
			Message: "artifact committed",
		}}},
	}

	state, message := vmiHibernationOutcome(vmi)
	if state != hibernation.StateHibernated || message != "artifact committed" {
		t.Fatalf("unexpected persisted outcome %q %q", state, message)
	}
}

func TestSavingRetriesMissingVMIRequest(t *testing.T) {
	vm := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		hibernation.AttemptAnnotation: "attempt-1",
	}}}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
	if !needsSaveDispatch(vm, vmi) {
		t.Fatal("missing VMI save dispatch must be retried")
	}
	vmi.Annotations[hibernation.RequestAnnotation] = hibernation.RequestSave
	vmi.Annotations[hibernation.AttemptAnnotation] = "attempt-1"
	if needsSaveDispatch(vm, vmi) {
		t.Fatal("matching idempotent save dispatch must not be rewritten")
	}
}

func TestArtifactErasureRequiresExplicitFinalization(t *testing.T) {
	if shouldFinalizeHibernation(hibernation.RequestResume) {
		t.Fatal("generic resume must not erase the consumed recovery artifact")
	}
	if !shouldFinalizeHibernation(hibernation.RequestFinalize) {
		t.Fatal("explicit verified finalization must request erasure")
	}
}

func TestResumeRejectedIsRetryableOnlyByExplicitResume(t *testing.T) {
	if !retryRejectedRestore(hibernation.StateResumeRejected, hibernation.RequestResume, nil) {
		t.Fatal("an explicit retry must be able to prove the unconsumed artifact on its source kernel")
	}
	if retryRejectedRestore(hibernation.StateResumeRejected, "", nil) {
		t.Fatal("runStrategy must not retry a rejected restore automatically")
	}
	if retryRejectedRestore(hibernation.StateResumeRejected, hibernation.RequestResume, &v1.VirtualMachineInstance{}) {
		t.Fatal("a rejected restore with a remaining VMI must stay terminal")
	}
}

func TestHibernationAnchorsDigestBeforeSourceDeletion(t *testing.T) {
	for _, digest := range []string{"", "artifact-digest"} {
		t.Run(digest, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			client := kubecli.NewMockKubevirtClient(ctrl)
			vmClient := kubecli.NewMockVirtualMachineInterface(ctrl)
			controller := &Controller{clientset: client}
			vm := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "tracer", Annotations: map[string]string{hibernation.StateAnnotation: hibernation.StateSaving}}}
			vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{hibernation.StateAnnotation: hibernation.StateHibernated, hibernation.ArtifactDigestAnnotation: digest}}}
			if digest != "" {
				client.EXPECT().VirtualMachine("default").Return(vmClient)
				vmClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, updated *v1.VirtualMachine, _ metav1.UpdateOptions) (*v1.VirtualMachine, error) {
					if updated.Annotations[hibernation.ArtifactDigestAnnotation] != digest || updated.Annotations[hibernation.StateAnnotation] != hibernation.StateHibernated {
						t.Fatalf("source receipt not anchored: %+v", updated.Annotations)
					}
					return updated, nil
				})
			}
			// No VMI delete is expected before the durable VM update is observed.
			_, _, handled, err := controller.reconcileHibernation(vm, vmi)
			if !handled || (err == nil) != (digest != "") {
				t.Fatalf("handled=%v err=%v", handled, err)
			}
		})
	}
}

func TestHibernationSaveRejectionKeepsRunningVMI(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := kubecli.NewMockKubevirtClient(ctrl)
	vmClient := kubecli.NewMockVirtualMachineInterface(ctrl)
	vmiClient := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)
	controller := &Controller{clientset: client}
	vm := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "tracer", Annotations: map[string]string{hibernation.StateAnnotation: hibernation.StateSaving}}}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "tracer", Annotations: map[string]string{hibernation.StateAnnotation: hibernation.StateSaveRejected}}}
	client.EXPECT().VirtualMachineInstance("default").Return(vmiClient)
	vmiClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, updated *v1.VirtualMachineInstance, _ metav1.UpdateOptions) (*v1.VirtualMachineInstance, error) {
		if updated.Annotations[hibernation.StateAnnotation] != hibernation.StateRunning || updated.Annotations[hibernation.RequestAnnotation] != "" {
			t.Fatal("rejected save did not release the running VMI")
		}
		return updated, nil
	})
	client.EXPECT().VirtualMachine("default").Return(vmClient)
	vmClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, updated *v1.VirtualMachine, _ metav1.UpdateOptions) (*v1.VirtualMachine, error) {
		return updated, nil
	})
	_, _, _, err := controller.reconcileHibernation(vm, vmi)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHibernationIgnoresPriorAttemptOutcome(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := kubecli.NewMockKubevirtClient(ctrl)
	vmiClient := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)
	controller := &Controller{clientset: client}
	vm := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "tracer", Annotations: map[string]string{hibernation.StateAnnotation: hibernation.StateSaving, hibernation.AttemptAnnotation: "new", hibernation.PVCIdentitiesAnnotation: `{}`}}}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Annotations: map[string]string{hibernation.StateAnnotation: hibernation.StateSaveRejected, hibernation.AttemptAnnotation: "old"}}, Status: v1.VirtualMachineInstanceStatus{Conditions: []v1.VirtualMachineInstanceCondition{{Type: v1.VirtualMachineInstanceConditionType(hibernation.VMIConditionType), Reason: hibernation.StateSaveRejected}}}}
	client.EXPECT().VirtualMachineInstance("default").Return(vmiClient)
	vmiClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, updated *v1.VirtualMachineInstance, _ metav1.UpdateOptions) (*v1.VirtualMachineInstance, error) {
		if updated.Annotations[hibernation.AttemptAnnotation] != "new" || updated.Annotations[hibernation.RequestAnnotation] != hibernation.RequestSave || len(updated.Status.Conditions) != 0 {
			t.Fatalf("old outcome survived new dispatch: %+v", updated)
		}
		return updated, nil
	})
	_, _, _, err := controller.reconcileHibernation(vm, vmi)
	if err != nil {
		t.Fatal(err)
	}
	vmi.Annotations[hibernation.StateAnnotation] = hibernation.StateSaving
	if state, _ := vmiHibernationOutcome(vmi); state != hibernation.StateSaving {
		t.Fatalf("old condition superseded new state: %s", state)
	}
}
