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
	"fmt"

	k8score "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"

	virtv1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/hibernation"
)

func (c *Controller) reconcileHibernation(vm *virtv1.VirtualMachine, vmi *virtv1.VirtualMachineInstance) (*virtv1.VirtualMachine, *virtv1.VirtualMachineInstance, bool, error) {
	if vm.Annotations == nil {
		vm.Annotations = map[string]string{}
	}
	request := vm.Annotations[hibernation.RequestAnnotation]
	state := vm.Annotations[hibernation.StateAnnotation]
	if request == "" && state == "" {
		return vm, vmi, false, nil
	}
	if retryRejectedRestore(state, request, vmi) {
		updated, err := c.updateVMHibernation(vm, hibernation.StateRestoring, request, vm.Annotations[hibernation.AttemptAnnotation], "")
		if err != nil {
			return vm, vmi, true, err
		}
		updated, err = c.startVMI(updated)
		return updated, vmi, true, err
	}

	if hibernation.IsTerminal(state) {
		if vmi != nil {
			updated, err := c.stopVMI(vm, vmi)
			return updated, vmi, true, err
		}
		return vm, vmi, true, nil
	}

	switch request {
	case "", hibernation.RequestHibernate:
		return c.reconcileHibernate(vm, vmi, request, state)
	case hibernation.RequestResume, hibernation.RequestFinalize:
		return c.reconcileResume(vm, vmi, state, request)
	default:
		return vm, vmi, true, fmt.Errorf("unsupported hibernation request %q", request)
	}
}

func retryRejectedRestore(state, request string, vmi *virtv1.VirtualMachineInstance) bool {
	return state == hibernation.StateResumeRejected && request == hibernation.RequestResume && vmi == nil
}

func (c *Controller) reconcileHibernate(vm *virtv1.VirtualMachine, vmi *virtv1.VirtualMachineInstance, request, state string) (*virtv1.VirtualMachine, *virtv1.VirtualMachineInstance, bool, error) {
	switch state {
	case hibernation.StateHibernated:
		if request != "" {
			var err error
			vm, err = c.updateVMHibernation(vm, hibernation.StateHibernated, "", "", "")
			if err != nil {
				return vm, vmi, true, err
			}
		}
		if vmi != nil {
			var err error
			vm, err = c.stopVMI(vm, vmi)
			return vm, vmi, true, err
		}
		return vm, vmi, true, nil
	case hibernation.StateSaving:
		if vmi == nil {
			updated, err := c.updateVMHibernation(vm, hibernation.StateSaveIncomplete, "", "", "launcher disappeared before save completion")
			return updated, vmi, true, err
		}
		if vmi.Annotations[hibernation.AttemptAnnotation] != vm.Annotations[hibernation.AttemptAnnotation] ||
			(vmi.Annotations[hibernation.StateAnnotation] == hibernation.StateSaving && needsSaveDispatch(vm, vmi)) {
			pvcIdentities := map[string]string{}
			if err := json.Unmarshal([]byte(vm.Annotations[hibernation.PVCIdentitiesAnnotation]), &pvcIdentities); err != nil {
				return vm, vmi, true, fmt.Errorf("invalid persisted PVC identities: %w", err)
			}
			updatedVMI, err := c.updateVMIHibernation(vmi, hibernation.RequestSave, hibernation.StateSaving, vm.Annotations[hibernation.AttemptAnnotation], vm, pvcIdentities)
			return vm, updatedVMI, true, err
		}
		vmiState, vmiMessage := vmiHibernationOutcome(vmi)
		if vmiState == hibernation.StateSaveRejected {
			// The launcher rejected the request before changing the running
			// domain. Preserve that guest; a failed save is not a stop request.
			updatedVMI, err := c.setVMIHibernationRequest(vmi, "", hibernation.StateRunning)
			if err != nil {
				return vm, vmi, true, err
			}
			updatedVM, err := c.updateVMHibernation(vm, hibernation.StateRunning, "", "", vmiMessage)
			return updatedVM, updatedVMI, true, err
		}
		if vmiState == hibernation.StateHibernated {
			digest := vmi.Annotations[hibernation.ArtifactDigestAnnotation]
			if digest == "" {
				return vm, vmi, true, fmt.Errorf("completed save is missing its launcher-reported artifact digest")
			}
			vm.Annotations[hibernation.ArtifactDigestAnnotation] = digest
			updated, err := c.updateVMHibernation(vm, hibernation.StateHibernated, "", "", "")
			return updated, vmi, true, err
		}
		if hibernation.IsTerminal(vmiState) {
			updated, err := c.updateVMHibernation(vm, vmiState, "", "", vmiMessage)
			return updated, vmi, true, err
		}

		return vm, vmi, true, nil
	case "", hibernation.StateRunning:
		if request == "" {
			return vm, vmi, false, nil
		}
		if vmi == nil {
			return vm, vmi, true, fmt.Errorf("cannot hibernate a VM without a VMI")
		}
		if vmi.Annotations[hibernation.StatePVCAnnotation] != vm.Annotations[hibernation.StatePVCAnnotation] {
			return vm, vmi, true, fmt.Errorf("state PVC was not mounted before launcher creation; a newly created launcher must include %s", hibernation.StatePVCAnnotation)
		}
		attempt := string(uuid.NewUUID())
		pvcIdentities, err := c.hibernationPVCIdentities(vm)
		if err != nil {
			return vm, vmi, true, err
		}
		pvcPayload, err := json.Marshal(pvcIdentities)
		if err != nil {
			return vm, vmi, true, err
		}
		vm.Annotations[hibernation.PVCIdentitiesAnnotation] = string(pvcPayload)
		vm.Annotations[hibernation.VMUIDAnnotation] = string(vm.UID)
		delete(vm.Annotations, hibernation.ArtifactDigestAnnotation)
		updatedVM, err := c.updateVMHibernation(vm, hibernation.StateSaving, request, attempt, "")
		if err != nil {
			return vm, vmi, true, err
		}
		updatedVMI, err := c.updateVMIHibernation(vmi, hibernation.RequestSave, hibernation.StateSaving, attempt, updatedVM, pvcIdentities)
		return updatedVM, updatedVMI, true, err
	default:
		return vm, vmi, true, fmt.Errorf("invalid state %q for hibernate", state)
	}
}

func (c *Controller) reconcileResume(vm *virtv1.VirtualMachine, vmi *virtv1.VirtualMachineInstance, state, request string) (*virtv1.VirtualMachine, *virtv1.VirtualMachineInstance, bool, error) {
	if state == hibernation.StateHibernated && vmi == nil {
		updated, err := c.updateVMHibernation(vm, hibernation.StateRestoring, hibernation.RequestResume, vm.Annotations[hibernation.AttemptAnnotation], "")
		if err != nil {
			return vm, vmi, true, err
		}
		updated, err = c.startVMI(updated)
		return updated, vmi, true, err
	}
	if vmi == nil {
		terminal := hibernation.StateResumeRejected
		if state == hibernation.StateRestoreCommittedPaused || state == hibernation.StateRunningAwaitingVerification {
			terminal = hibernation.StateRestoreCommitLost
		}
		updated, err := c.updateVMHibernation(vm, terminal, "", "", "restore launcher disappeared")
		return updated, vmi, true, err
	}

	vmiState, vmiMessage := vmiHibernationOutcome(vmi)
	if hibernation.IsTerminal(vmiState) {
		updated, err := c.updateVMHibernation(vm, vmiState, "", "", vmiMessage)
		return updated, vmi, true, err
	}
	switch vmiState {
	case hibernation.StateRestoredPaused:
		updatedVM, err := c.updateVMHibernation(vm, hibernation.StateRestoreCommittedPaused, hibernation.RequestResume, vm.Annotations[hibernation.AttemptAnnotation], "")
		if err != nil {
			return vm, vmi, true, err
		}
		updatedVMI, err := c.setVMIHibernationRequest(vmi, hibernation.RequestCommitUnpause, hibernation.StateRestoreCommittedPaused)
		return updatedVM, updatedVMI, true, err
	case hibernation.StateRunningAwaitingVerification:
		updatedVM, err := c.updateVMHibernation(vm, hibernation.StateRunningAwaitingVerification, request, vm.Annotations[hibernation.AttemptAnnotation], "")
		if err != nil {
			return vm, vmi, true, err
		}
		if shouldFinalizeHibernation(request) {
			ready := false
			for _, condition := range vmi.Status.Conditions {
				if condition.Type == virtv1.VirtualMachineInstanceReady && condition.Status == k8score.ConditionTrue {
					ready = true
				}
			}
			if !vmi.IsRunning() || !ready {
				return updatedVM, vmi, true, fmt.Errorf("finalization requires a running, Ready VMI")
			}
			updatedVMI, err := c.setVMIHibernationRequest(vmi, hibernation.RequestErase, hibernation.StateRunningAwaitingVerification)
			return updatedVM, updatedVMI, true, err
		}
		if vmi.Annotations[hibernation.RequestAnnotation] != "" {
			updatedVMI, err := c.setVMIHibernationRequest(vmi, "", hibernation.StateRunningAwaitingVerification)
			return updatedVM, updatedVMI, true, err
		}
		return updatedVM, vmi, true, nil
	case hibernation.StateRunning:
		updated, err := c.updateVMHibernation(vm, hibernation.StateRunning, "", "", "")
		if err != nil {
			return updated, vmi, true, err
		}
		updatedVMI, err := c.setVMIHibernationRequest(vmi, "", hibernation.StateRunning)
		return updated, updatedVMI, true, err
	case hibernation.StateRestoring, hibernation.StateRestoreCommittedPaused:
		return vm, vmi, true, nil
	default:
		return vm, vmi, true, fmt.Errorf("invalid VMI state %q while resuming", vmiState)
	}
}

func (c *Controller) updateVMHibernation(vm *virtv1.VirtualMachine, state, request, attempt, message string) (*virtv1.VirtualMachine, error) {
	copy := vm.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	setOrDelete(copy.Annotations, hibernation.StateAnnotation, state)
	setOrDelete(copy.Annotations, hibernation.RequestAnnotation, request)
	if attempt != "" {
		copy.Annotations[hibernation.AttemptAnnotation] = attempt
	}
	setOrDelete(copy.Annotations, hibernation.ErrorAnnotation, message)
	return c.clientset.VirtualMachine(copy.Namespace).Update(context.Background(), copy, metav1.UpdateOptions{})
}

func (c *Controller) updateVMIHibernation(vmi *virtv1.VirtualMachineInstance, request, state, attempt string, vm *virtv1.VirtualMachine, pvcIdentities map[string]string) (*virtv1.VirtualMachineInstance, error) {
	copy := vmi.DeepCopy()
	if copy.Annotations == nil {
		copy.Annotations = map[string]string{}
	}
	copy.Annotations[hibernation.StatePVCAnnotation] = vm.Annotations[hibernation.StatePVCAnnotation]
	copy.Annotations[hibernation.RequestAnnotation] = request
	copy.Annotations[hibernation.StateAnnotation] = state
	copy.Annotations[hibernation.AttemptAnnotation] = attempt
	copy.Annotations[hibernation.VMUIDAnnotation] = string(vm.UID)
	payload, err := json.Marshal(pvcIdentities)
	if err != nil {
		return vmi, err
	}
	copy.Annotations[hibernation.PVCIdentitiesAnnotation] = string(payload)
	if request == hibernation.RequestSave {
		delete(copy.Annotations, hibernation.ArtifactDigestAnnotation)
		conditions := copy.Status.Conditions[:0]
		for _, condition := range copy.Status.Conditions {
			if condition.Type != virtv1.VirtualMachineInstanceConditionType(hibernation.VMIConditionType) {
				conditions = append(conditions, condition)
			}
		}
		copy.Status.Conditions = conditions
	}
	return c.clientset.VirtualMachineInstance(copy.Namespace).Update(context.Background(), copy, metav1.UpdateOptions{})
}

func (c *Controller) setVMIHibernationRequest(vmi *virtv1.VirtualMachineInstance, request, state string) (*virtv1.VirtualMachineInstance, error) {
	copy := vmi.DeepCopy()
	copy.Annotations[hibernation.RequestAnnotation] = request
	copy.Annotations[hibernation.StateAnnotation] = state
	return c.clientset.VirtualMachineInstance(copy.Namespace).Update(context.Background(), copy, metav1.UpdateOptions{})
}

func (c *Controller) hibernationPVCIdentities(vm *virtv1.VirtualMachine) (map[string]string, error) {
	statePVC := vm.Annotations[hibernation.StatePVCAnnotation]
	if statePVC == "" {
		return nil, fmt.Errorf("%s annotation is required", hibernation.StatePVCAnnotation)
	}
	claims := map[string]string{"state": statePVC}
	for _, volume := range vm.Spec.Template.Spec.Volumes {
		if volume.PersistentVolumeClaim != nil {
			claims[volume.Name] = volume.PersistentVolumeClaim.ClaimName
		}
	}
	identities := make(map[string]string, len(claims))
	for name, claimName := range claims {
		obj, exists, err := c.pvcStore.GetByKey(vm.Namespace + "/" + claimName)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, fmt.Errorf("PVC %s/%s does not exist", vm.Namespace, claimName)
		}
		pvc, ok := obj.(*k8score.PersistentVolumeClaim)
		if !ok {
			return nil, fmt.Errorf("PVC cache entry has unexpected type %T", obj)
		}
		if name == "state" && pvc.Spec.VolumeMode != nil && *pvc.Spec.VolumeMode == k8score.PersistentVolumeBlock {
			return nil, fmt.Errorf("hibernation state PVC must use filesystem mode")
		}
		if pvc.UID == "" || pvc.Spec.VolumeName == "" {
			return nil, fmt.Errorf("PVC %s/%s has no durable identity", vm.Namespace, claimName)
		}
		identities[name] = string(pvc.UID) + "/" + pvc.Spec.VolumeName
	}
	return identities, nil
}

func (c *Controller) refreshVMIHibernationPVCIdentities(vm *virtv1.VirtualMachine, vmi *virtv1.VirtualMachineInstance) error {
	if vm.Annotations[hibernation.StateAnnotation] != hibernation.StateRestoring {
		return nil
	}
	identities, err := c.hibernationPVCIdentities(vm)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(identities)
	if err != nil {
		return err
	}
	vmi.Annotations[hibernation.PVCIdentitiesAnnotation] = string(payload)
	return nil
}

func setOrDelete(values map[string]string, key, value string) {
	if value == "" {
		delete(values, key)
		return
	}
	values[key] = value
}

func vmiHibernationOutcome(vmi *virtv1.VirtualMachineInstance) (string, string) {
	for _, condition := range vmi.Status.Conditions {
		if condition.Type == virtv1.VirtualMachineInstanceConditionType(hibernation.VMIConditionType) &&
			condition.Reason == vmi.Annotations[hibernation.StateAnnotation] {
			return condition.Reason, condition.Message
		}
	}
	return vmi.Annotations[hibernation.StateAnnotation], vmi.Annotations[hibernation.ErrorAnnotation]
}

func needsSaveDispatch(vm *virtv1.VirtualMachine, vmi *virtv1.VirtualMachineInstance) bool {
	return vmi.Annotations[hibernation.RequestAnnotation] != hibernation.RequestSave ||
		vmi.Annotations[hibernation.AttemptAnnotation] != vm.Annotations[hibernation.AttemptAnnotation]
}

func shouldFinalizeHibernation(request string) bool {
	return request == hibernation.RequestFinalize
}
