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

package rest

import (
	"context"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful/v3"
	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/hibernation"
)

const encryptedHibernationStorageAnnotation = "hibernation.kubevirt.io/encrypted-state"

func (app *SubresourceAPIApp) HibernateVMRequestHandler(request *restful.Request, response *restful.Response) {
	app.hibernationRequest(request, response, hibernation.RequestHibernate)
}

func (app *SubresourceAPIApp) ResumeVMRequestHandler(request *restful.Request, response *restful.Response) {
	app.hibernationRequest(request, response, hibernation.RequestResume)
}

func (app *SubresourceAPIApp) FinalizeHibernationVMRequestHandler(request *restful.Request, response *restful.Response) {
	app.hibernationRequest(request, response, hibernation.RequestFinalize)
}

func (app *SubresourceAPIApp) DiscardHibernationVMRequestHandler(request *restful.Request, response *restful.Response) {
	app.hibernationRequest(request, response, hibernation.RequestDiscard)
}

func (app *SubresourceAPIApp) hibernationRequest(request *restful.Request, response *restful.Response, operation string) {
	if !app.clusterConfig.HibernationEnabled() {
		writeError(errors.NewBadRequest("Hibernation feature gate is not enabled"), response)
		return
	}
	name, namespace := request.PathParameter("name"), request.PathParameter("namespace")
	vm, statusErr := app.fetchVirtualMachine(name, namespace)
	if statusErr != nil {
		writeError(statusErr, response)
		return
	}
	if vm.DeletionTimestamp != nil {
		writeError(errors.NewConflict(v1.Resource("virtualmachine"), name, fmt.Errorf("VM is being deleted")), response)
		return
	}
	options := &metav1.UpdateOptions{}
	var body interface{} = options
	discard := &v1.DiscardHibernationOptions{}
	if operation == hibernation.RequestDiscard {
		body = discard
	}
	if request.Request.Body != nil {
		if err := decodeBody(request, body); err != nil {
			writeError(err, response)
			return
		}
	}
	if operation == hibernation.RequestDiscard {
		options = &metav1.UpdateOptions{DryRun: discard.DryRun}
		if discard.AttemptID == "" || discard.AttemptID != vm.Annotations[hibernation.AttemptAnnotation] {
			writeError(errors.NewConflict(v1.Resource("virtualmachine"), name, fmt.Errorf("discard requires the current attemptID")), response)
			return
		}
	}
	vmi, err := app.virtCli.VirtualMachineInstance(namespace).Get(request.Request.Context(), name, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		writeError(errors.NewInternalError(err), response)
		return
	}
	if errors.IsNotFound(err) {
		vmi = nil
	}
	if err := validateHibernationRequest(vm, vmi, operation); err != nil {
		writeError(errors.NewConflict(v1.Resource("virtualmachine"), name, err), response)
		return
	}
	if operation == hibernation.RequestHibernate {
		if err := app.validateHibernationStorage(request.Request.Context(), vm, vmi); err != nil {
			writeError(err, response)
			return
		}
	}
	if vm.Annotations[hibernation.RequestAnnotation] == operation || (operation == hibernation.RequestDiscard && vm.Annotations[hibernation.StateAnnotation] == hibernation.StateDiscarded) {
		response.WriteHeader(http.StatusAccepted)
		return
	}
	updated := vm.DeepCopy()
	if updated.Annotations == nil {
		updated.Annotations = map[string]string{}
	}
	updated.Annotations[hibernation.RequestAnnotation] = operation
	// ResourceVersion makes concurrent requests conflict instead of replacing
	// a different operation or newly completed attempt.
	if _, err := app.virtCli.VirtualMachine(namespace).Update(request.Request.Context(), updated, *options); err != nil {
		if statusErr, ok := err.(*errors.StatusError); ok {
			writeError(statusErr, response)
		} else {
			writeError(errors.NewInternalError(err), response)
		}
		return
	}
	response.WriteHeader(http.StatusAccepted)
}

func validateHibernationRequest(vm *v1.VirtualMachine, vmi *v1.VirtualMachineInstance, operation string) error {
	state := vm.Annotations[hibernation.StateAnnotation]
	request := vm.Annotations[hibernation.RequestAnnotation]
	if request != "" && request != operation && !(operation == hibernation.RequestFinalize && state == hibernation.StateRunningAwaitingVerification && request == hibernation.RequestResume) {
		return fmt.Errorf("hibernation operation %q is already pending", request)
	}
	switch operation {
	case hibernation.RequestHibernate:
		if metav1.GetControllerOf(vm) != nil {
			return fmt.Errorf("hibernation requires an independently managed VM")
		}
		if state != "" && state != hibernation.StateRunning && state != hibernation.StateDiscarded && !(state == hibernation.StateSaving && request == operation) {
			return fmt.Errorf("cannot hibernate from state %q", state)
		}
		if len(vm.Status.StateChangeRequests) != 0 || vm.Status.SnapshotInProgress != nil {
			return fmt.Errorf("hibernation cannot overlap a pending lifecycle or snapshot operation")
		}
		if vmi == nil || vmi.DeletionTimestamp != nil || !vmi.IsRunning() {
			return fmt.Errorf("hibernation requires a running VMI")
		}
		for _, condition := range vmi.Status.Conditions {
			if condition.Type == v1.VirtualMachineInstancePaused && condition.Status == k8sv1.ConditionTrue {
				return fmt.Errorf("hibernation requires an unpaused guest")
			}
		}
		if len(vmi.Spec.Domain.Devices.HostDevices) != 0 || len(vmi.Spec.Domain.Devices.GPUs) != 0 {
			return fmt.Errorf("hibernation does not support passthrough devices")
		}
		if migration := vmi.Status.MigrationState; migration != nil && !migration.Completed && !migration.Failed {
			return fmt.Errorf("hibernation cannot run during migration")
		}
	case hibernation.RequestResume:
		if state != hibernation.StateHibernated && state != hibernation.StateResumeRejected {
			return fmt.Errorf("cannot resume from state %q", state)
		}
		if vmi != nil {
			return fmt.Errorf("resume requires the previous VMI to be absent")
		}
		if vm.Annotations[hibernation.ArtifactDigestAnnotation] == "" {
			return fmt.Errorf("resume requires a controller-recorded artifact digest")
		}
	case hibernation.RequestDiscard:
		if !hibernation.IsTerminal(state) && state != hibernation.StateDiscarding && state != hibernation.StateDiscarded {
			return fmt.Errorf("discard requires a failed hibernation attempt")
		}
		if len(vm.Status.StateChangeRequests) != 0 || vm.Status.SnapshotInProgress != nil {
			return fmt.Errorf("discard cannot overlap a pending lifecycle or snapshot operation")
		}
		if vmi != nil && !(((state == hibernation.StateDiscarding && request == operation) || state == hibernation.StateDiscarded) &&
			vmi.Annotations[hibernation.AttemptAnnotation] == vm.Annotations[hibernation.AttemptAnnotation] &&
			vmi.Annotations[hibernation.VMUIDAnnotation] == string(vm.UID) &&
			(vmi.Annotations[hibernation.StateAnnotation] == hibernation.StateDiscarding || vmi.Annotations[hibernation.StateAnnotation] == hibernation.StateDiscarded) && !vmi.IsRunning()) {
			return fmt.Errorf("discard requires the previous VMI to be absent")
		}
	case hibernation.RequestFinalize:
		if state != hibernation.StateRunningAwaitingVerification || vmi == nil || !vmi.IsRunning() {
			return fmt.Errorf("finalization requires a resumed, running VMI awaiting verification")
		}
		for _, condition := range vmi.Status.Conditions {
			if condition.Type == v1.VirtualMachineInstanceReady && condition.Status == k8sv1.ConditionTrue {
				return nil
			}
		}
		return fmt.Errorf("finalization requires a Ready VMI and completed operator verification")
	default:
		return fmt.Errorf("unsupported hibernation operation %q", operation)
	}
	return nil
}

func (app *SubresourceAPIApp) validateHibernationStorage(ctx context.Context, vm *v1.VirtualMachine, vmi *v1.VirtualMachineInstance) *errors.StatusError {
	name := vm.Annotations[hibernation.StatePVCAnnotation]
	if name == "" || vmi.Annotations[hibernation.StatePVCAnnotation] != name {
		return errors.NewConflict(v1.Resource("virtualmachine"), vm.Name, fmt.Errorf("the state PVC must be configured before the launcher starts"))
	}
	pvc, statusErr := app.fetchPersistentVolumeClaim(name, vm.Namespace)
	if statusErr != nil {
		return statusErr
	}
	if !hibernation.StatePVCBoundTo(pvc, vm.UID) {
		return errors.NewConflict(v1.Resource("persistentvolumeclaim"), name, fmt.Errorf("state PVC is not reserved for this VM"))
	}
	if len(pvc.Spec.AccessModes) == 0 || pvc.Status.Phase != k8sv1.ClaimBound || pvc.Spec.StorageClassName == nil || (pvc.Spec.VolumeMode != nil && *pvc.Spec.VolumeMode == k8sv1.PersistentVolumeBlock) {
		return errors.NewConflict(v1.Resource("persistentvolumeclaim"), name, fmt.Errorf("hibernation requires a bound filesystem PVC with an approved encrypted StorageClass"))
	}
	for _, mode := range pvc.Spec.AccessModes {
		if mode != k8sv1.ReadWriteOnce && mode != k8sv1.ReadWriteOncePod {
			return errors.NewConflict(v1.Resource("persistentvolumeclaim"), name, fmt.Errorf("hibernation state storage requires RWO or RWOP access mode"))
		}
	}
	storageClass, err := app.virtCli.StorageV1().StorageClasses().Get(ctx, *pvc.Spec.StorageClassName, metav1.GetOptions{})
	if err != nil {
		return errors.NewInternalError(err)
	}
	if storageClass.Annotations[encryptedHibernationStorageAnnotation] != "true" {
		return errors.NewConflict(v1.Resource("persistentvolumeclaim"), name, fmt.Errorf("StorageClass has not been approved for encrypted hibernation state"))
	}
	required := hibernation.StateCapacity(vmi)
	if pvc.Status.Capacity.Storage().Cmp(required) < 0 {
		return errors.NewConflict(v1.Resource("persistentvolumeclaim"), name, fmt.Errorf("state PVC must hold guest RAM plus 10 percent and 1 GiB overhead"))
	}
	return nil
}

func (app *SubresourceAPIApp) rejectConflictingHibernation(vmi *v1.VirtualMachineInstance) *errors.StatusError {
	active := hibernation.Active(vmi.Annotations)
	// Read the VM when this launcher supports state storage, closing the window
	// between accepting a VM request and dispatching it to the VMI.
	if !active && vmi.Annotations[hibernation.StatePVCAnnotation] != "" {
		vm, err := app.fetchVirtualMachine(vmi.Name, vmi.Namespace)
		if err != nil && !errors.IsNotFound(err) {
			return err
		}
		if err == nil {
			active = hibernation.Active(vm.Annotations)
		}
	}
	if active {
		return errors.NewConflict(v1.Resource("virtualmachineinstance"), vmi.Name, fmt.Errorf("lifecycle operation conflicts with an active hibernation attempt"))
	}
	return nil
}

func rejectVMHibernationLifecycle(vm *v1.VirtualMachine) *errors.StatusError {
	if hibernation.Active(vm.Annotations) {
		return errors.NewConflict(v1.Resource("virtualmachine"), vm.Name, fmt.Errorf("VM lifecycle operation conflicts with an active hibernation attempt"))
	}
	return nil
}
