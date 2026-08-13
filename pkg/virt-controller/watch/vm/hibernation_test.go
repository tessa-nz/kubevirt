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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
			hibernation.StatePVCAnnotation:      "state",
			hibernation.StateAnnotation:         hibernation.StateRestoring,
			hibernation.RequestAnnotation:       hibernation.RequestResume,
			hibernation.AttemptAnnotation:       "attempt",
			hibernation.VMUIDAnnotation:         "vm-uid",
			hibernation.PVCIdentitiesAnnotation: `{"state":"pvc-uid/pv"}`,
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
}

func TestHibernationOutcomeUsesPersistedHandlerCondition(t *testing.T) {
	vmi := &v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			hibernation.StateAnnotation: hibernation.StateSaving,
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
