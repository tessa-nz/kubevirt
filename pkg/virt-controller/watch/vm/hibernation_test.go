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
	"errors"
	"fmt"
	"testing"

	"go.uber.org/mock/gomock"
	"kubevirt.io/client-go/kubecli"

	k8score "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
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

func TestHibernationFinalVMIClosesInterruptedAttempt(t *testing.T) {
	cases := []struct {
		name, vmState, vmiState, request, outcome string
	}{
		{"save", hibernation.StateSaving, hibernation.StateSaving, hibernation.RequestHibernate, hibernation.StateSaveIncomplete},
		{"restore-before-commit", hibernation.StateRestoring, hibernation.StateRestoring, hibernation.RequestResume, hibernation.StateResumeRejected},
		{"restore-paused", hibernation.StateRestoring, hibernation.StateRestoredPaused, hibernation.RequestResume, hibernation.StateResumeRejected},
		{"restore-commit-requested", hibernation.StateRestoreCommittedPaused, hibernation.StateRestoreCommittedPaused, hibernation.RequestResume, hibernation.StateRestoreCommitLost},
		{"restore-consumed-receipt", hibernation.StateRestoring, hibernation.StateRunningAwaitingVerification, hibernation.RequestResume, hibernation.StateRestoreCommitLost},
		{"restore-running", hibernation.StateRunningAwaitingVerification, hibernation.StateRunningAwaitingVerification, hibernation.RequestResume, hibernation.StateRestoreCommitLost},
	}
	for _, tc := range cases {
		for _, phase := range []v1.VirtualMachineInstancePhase{v1.Failed, v1.Succeeded} {
			t.Run(tc.name+"/"+string(phase), func(t *testing.T) {
				ctrl := gomock.NewController(t)
				client := kubecli.NewMockKubevirtClient(ctrl)
				vmClient := kubecli.NewMockVirtualMachineInterface(ctrl)
				controller := &Controller{clientset: client}
				vm := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "tracer", Annotations: map[string]string{
					hibernation.StateAnnotation: tc.vmState, hibernation.RequestAnnotation: tc.request, hibernation.AttemptAnnotation: "attempt",
				}}}
				vmi := &v1.VirtualMachineInstance{
					ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "tracer", Annotations: map[string]string{
						hibernation.StateAnnotation: tc.vmiState, hibernation.AttemptAnnotation: "attempt",
					}},
					Status: v1.VirtualMachineInstanceStatus{Phase: phase},
				}
				if tc.vmState == hibernation.StateSaving {
					vmi.Annotations[hibernation.RequestAnnotation] = hibernation.RequestSave
				}
				client.EXPECT().VirtualMachine("default").Return(vmClient)
				vmClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, updated *v1.VirtualMachine, _ metav1.UpdateOptions) (*v1.VirtualMachine, error) {
					if updated.Annotations[hibernation.StateAnnotation] != tc.outcome || updated.Annotations[hibernation.RequestAnnotation] != "" || updated.Annotations[hibernation.ErrorAnnotation] == "" {
						t.Fatalf("dead VMI did not close the attempt: %+v", updated.Annotations)
					}
					return updated, nil
				})
				_, _, handled, err := controller.reconcileHibernation(vm, vmi)
				if !handled || err != nil {
					t.Fatalf("handled=%v err=%v", handled, err)
				}
			})
		}
	}
}

func TestHibernationFinalSavePreservesCompletedReceipt(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := kubecli.NewMockKubevirtClient(ctrl)
	vmClient := kubecli.NewMockVirtualMachineInterface(ctrl)
	controller := &Controller{clientset: client}
	vm := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "tracer", Annotations: map[string]string{
		hibernation.StateAnnotation: hibernation.StateSaving, hibernation.AttemptAnnotation: "attempt",
	}}}
	vmi := &v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			hibernation.StateAnnotation: hibernation.StateHibernated, hibernation.AttemptAnnotation: "attempt", hibernation.ArtifactDigestAnnotation: "artifact-digest",
		}},
		Status: v1.VirtualMachineInstanceStatus{Phase: v1.Succeeded},
	}
	client.EXPECT().VirtualMachine("default").Return(vmClient)
	vmClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, updated *v1.VirtualMachine, _ metav1.UpdateOptions) (*v1.VirtualMachine, error) {
		if updated.Annotations[hibernation.StateAnnotation] != hibernation.StateHibernated || updated.Annotations[hibernation.ArtifactDigestAnnotation] != "artifact-digest" {
			t.Fatalf("completed save receipt was lost: %+v", updated.Annotations)
		}
		return updated, nil
	})
	_, _, handled, err := controller.reconcileHibernation(vm, vmi)
	if !handled || err != nil {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
}

func TestHibernationFinalVMIPreservesCompletedFinalization(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := kubecli.NewMockKubevirtClient(ctrl)
	vmClient := kubecli.NewMockVirtualMachineInterface(ctrl)
	vmiClient := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)
	controller := &Controller{clientset: client}
	vm := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "tracer", Annotations: map[string]string{
		hibernation.StateAnnotation: hibernation.StateRunningAwaitingVerification, hibernation.RequestAnnotation: hibernation.RequestFinalize,
	}}}
	vmi := &v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "tracer", Annotations: map[string]string{
			hibernation.StateAnnotation: hibernation.StateRunning,
		}},
		Status: v1.VirtualMachineInstanceStatus{Phase: v1.Succeeded},
	}
	client.EXPECT().VirtualMachine("default").Return(vmClient)
	vmClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, updated *v1.VirtualMachine, _ metav1.UpdateOptions) (*v1.VirtualMachine, error) {
		if updated.Annotations[hibernation.StateAnnotation] != hibernation.StateRunning || updated.Annotations[hibernation.RequestAnnotation] != "" {
			t.Fatalf("completed finalization was lost: %+v", updated.Annotations)
		}
		return updated, nil
	})
	client.EXPECT().VirtualMachineInstance("default").Return(vmiClient)
	vmiClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).Return(vmi, nil)
	_, _, handled, err := controller.reconcileHibernation(vm, vmi)
	if !handled || err != nil {
		t.Fatalf("handled=%v err=%v", handled, err)
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

func TestHibernationRetriesPartiallyCompletedSaveRejection(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := kubecli.NewMockKubevirtClient(ctrl)
	vmClient := kubecli.NewMockVirtualMachineInterface(ctrl)
	vmiClient := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)
	controller := &Controller{clientset: client}
	vm := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "tracer", Annotations: map[string]string{hibernation.StateAnnotation: hibernation.StateSaving, hibernation.AttemptAnnotation: "same"}}}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Annotations: map[string]string{hibernation.StateAnnotation: hibernation.StateSaveRejected, hibernation.AttemptAnnotation: "same"}}}
	client.EXPECT().VirtualMachineInstance("default").Return(vmiClient)
	vmiClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, updated *v1.VirtualMachineInstance, _ metav1.UpdateOptions) (*v1.VirtualMachineInstance, error) {
		return updated, nil
	})
	client.EXPECT().VirtualMachine("default").Return(vmClient).Times(2)
	first := vmClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("VM update response lost"))
	vmClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).After(first).DoAndReturn(func(_ context.Context, updated *v1.VirtualMachine, _ metav1.UpdateOptions) (*v1.VirtualMachine, error) {
		return updated, nil
	})
	_, runningVMI, _, err := controller.reconcileHibernation(vm, vmi)
	if err == nil || runningVMI.Annotations[hibernation.StateAnnotation] != hibernation.StateRunning {
		t.Fatalf("first update did not reproduce partial cleanup: %v", err)
	}
	updated, _, _, err := controller.reconcileHibernation(vm, runningVMI)
	if err != nil || updated.Annotations[hibernation.StateAnnotation] != hibernation.StateRunning {
		t.Fatalf("cleanup retry remained stuck: %v", err)
	}
}

func TestDiscardStartsWithInertNodeBoundLauncher(t *testing.T) {
	vm := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Name: "tracer", Namespace: "default", Annotations: map[string]string{
		hibernation.StateAnnotation: hibernation.StateDiscarding, hibernation.RequestAnnotation: hibernation.RequestDiscard,
		hibernation.SourceNodeAnnotation: "source-node", hibernation.AttemptAnnotation: "attempt", hibernation.VMUIDAnnotation: "vm-uid",
	}}, Spec: v1.VirtualMachineSpec{Template: &v1.VirtualMachineInstanceTemplateSpec{}}}
	vm.Spec.Template.Spec.Domain.Resources.Requests = k8score.ResourceList{k8score.ResourceMemory: resource.MustParse("32Gi")}
	vm.Spec.Template.Spec.Volumes = []v1.Volume{{Name: "unavailable-root", VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{PersistentVolumeClaimVolumeSource: k8score.PersistentVolumeClaimVolumeSource{ClaimName: "missing-root"}}}}}
	vmi := SetupVMIFromVM(vm)
	if vmi.Annotations[hibernation.RequestAnnotation] != hibernation.RequestDiscard || vmi.Annotations[hibernation.StateAnnotation] != hibernation.StateDiscarding {
		t.Fatal("cleanup VMI can reach ordinary startup")
	}
	if len(vmi.Spec.Volumes) != 0 || len(vmi.Spec.Domain.Devices.Disks) != 0 || vmi.Spec.Domain.Resources.Requests.Memory().Value() != 128*1024*1024 || vmi.Spec.Domain.Devices.AutoattachPodInterface == nil || *vmi.Spec.Domain.Devices.AutoattachPodInterface {
		t.Fatal("cleanup inherited guest resources")
	}
	selector := vmi.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution
	if len(selector.NodeSelectorTerms) != 1 || len(selector.NodeSelectorTerms[0].MatchFields) != 1 || selector.NodeSelectorTerms[0].MatchFields[0].Values[0] != "source-node" {
		t.Fatal("cleanup can run on another node")
	}
	vm.Annotations[hibernation.StateAnnotation] = hibernation.StateDiscarded
	delete(vm.Annotations, hibernation.RequestAnnotation)
	vmi = SetupVMIFromVM(vm)
	if hibernation.Active(vmi.Annotations) || vmi.Annotations[hibernation.AttemptAnnotation] != "" {
		t.Fatal("explicit later cold boot inherited a discarded attempt")
	}
}

func TestDiscardHaltsOnlyAfterValidatingReservedOriginalPVC(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprintf("changed-pvc=%t", changed), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			client := kubecli.NewMockKubevirtClient(ctrl)
			vmClient := kubecli.NewMockVirtualMachineInterface(ctrl)
			store := cache.NewStore(cache.MetaNamespaceKeyFunc)
			uid := types.UID("pvc-uid")
			if changed {
				uid = "replacement-uid"
			}
			pvc := &k8score.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "state", Namespace: "default", UID: uid, Annotations: map[string]string{hibernation.VMUIDAnnotation: "vm-uid"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: v1.SchemeGroupVersion.String(), Kind: "VirtualMachine", Name: "tracer", UID: "vm-uid"}}}, Spec: k8score.PersistentVolumeClaimSpec{VolumeName: "pv"}}
			if err := store.Add(pvc); err != nil {
				t.Fatal(err)
			}
			strategy := v1.RunStrategyAlways
			vm := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Name: "tracer", Namespace: "default", UID: "vm-uid", Annotations: map[string]string{
				hibernation.StateAnnotation: hibernation.StateSaveIncomplete, hibernation.RequestAnnotation: hibernation.RequestDiscard,
				hibernation.AttemptAnnotation: "attempt", hibernation.VMUIDAnnotation: "vm-uid", hibernation.SourceNodeAnnotation: "source-node",
				hibernation.StatePVCAnnotation: "state", hibernation.PVCIdentitiesAnnotation: `{"state":"pvc-uid/pv"}`,
			}}, Spec: v1.VirtualMachineSpec{RunStrategy: &strategy, Template: &v1.VirtualMachineInstanceTemplateSpec{}}}
			if !changed {
				client.EXPECT().VirtualMachine("default").Return(vmClient)
				vmClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, updated *v1.VirtualMachine, _ metav1.UpdateOptions) (*v1.VirtualMachine, error) {
					if *updated.Spec.RunStrategy != v1.RunStrategyHalted || updated.Annotations[hibernation.StateAnnotation] != hibernation.StateDiscarding || updated.Annotations[hibernation.AttemptAnnotation] != "attempt" {
						t.Fatal("unsafe discard transition")
					}
					return updated, nil
				})
			}
			c := &Controller{clientset: client, pvcStore: store}
			_, _, handled, err := c.reconcileHibernation(vm, nil)
			if !handled || (err != nil) != changed {
				t.Fatalf("handled=%t err=%v", handled, err)
			}
		})
	}
}

func TestDiscardCompletionRetriesLostVMUpdate(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := kubecli.NewMockKubevirtClient(ctrl)
	vmClient := kubecli.NewMockVirtualMachineInterface(ctrl)
	vm := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Name: "tracer", Namespace: "default", UID: "vm-uid", Annotations: map[string]string{
		hibernation.StateAnnotation: hibernation.StateDiscarding, hibernation.RequestAnnotation: hibernation.RequestDiscard,
		hibernation.AttemptAnnotation: "attempt", hibernation.VMUIDAnnotation: "vm-uid", hibernation.SourceNodeAnnotation: "source-node",
	}}}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		hibernation.StateAnnotation: hibernation.StateDiscarded, hibernation.AttemptAnnotation: "attempt", hibernation.VMUIDAnnotation: "vm-uid", hibernation.SourceNodeAnnotation: "source-node",
	}}}
	client.EXPECT().VirtualMachine("default").Return(vmClient).Times(2)
	gomock.InOrder(
		vmClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, errors.New("lost update")),
		vmClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, updated *v1.VirtualMachine, _ metav1.UpdateOptions) (*v1.VirtualMachine, error) {
			return updated, nil
		}),
	)
	c := &Controller{clientset: client}
	if _, _, _, err := c.reconcileHibernation(vm, vmi); err == nil {
		t.Fatal("lost update was accepted")
	}
	result, _, _, err := c.reconcileHibernation(vm, vmi)
	if err != nil || result.Annotations[hibernation.StateAnnotation] != hibernation.StateDiscarded || result.Annotations[hibernation.RequestAnnotation] != "" {
		t.Fatalf("receipt lost: %v", err)
	}
}
