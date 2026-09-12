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

package admitters

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	snapshotv1 "github.com/kubernetes-csi/external-snapshotter/client/v4/apis/volumesnapshot/v1"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "kubevirt.io/api/core/v1"
	exportv1 "kubevirt.io/api/export/v1beta1"
	"kubevirt.io/client-go/kubecli"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"

	"kubevirt.io/kubevirt/pkg/hibernation"
	webhookutils "kubevirt.io/kubevirt/pkg/util/webhooks"
)

// This validates core storage entry points as well as KubeVirt exports. Pod
// requests are scoped by an administrator's namespace label in the webhook
// configuration; cross-namespace clone references are checked at their source.
type HibernationStateAdmitter struct {
	Client                  kubecli.KubevirtClient
	KubeVirtServiceAccounts map[string]struct{}
}

func (a *HibernationStateAdmitter) isController(username string) bool {
	_, trusted := a.KubeVirtServiceAccounts[username]
	return trusted && strings.HasSuffix(username, ":kubevirt-controller")
}

func (a *HibernationStateAdmitter) Admit(ctx context.Context, review *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	if review.Request == nil {
		return webhookutils.ToAdmissionResponseError(fmt.Errorf("admission request is required"))
	}
	request := review.Request
	var err error
	switch {
	case request.Resource.Group == "" && request.Resource.Resource == "pods":
		err = a.admitPod(ctx, request)
	case request.Resource.Group == "" && request.Resource.Resource == "persistentvolumeclaims":
		err = a.admitPVC(ctx, request)
	case request.Resource.Group == "snapshot.storage.k8s.io" && request.Resource.Resource == "volumesnapshots":
		var snapshot snapshotv1.VolumeSnapshot
		if err = json.Unmarshal(request.Object.Raw, &snapshot); err == nil && snapshot.Spec.Source.PersistentVolumeClaimName != nil {
			err = a.rejectReservedPVC(ctx, request.Namespace, *snapshot.Spec.Source.PersistentVolumeClaimName)
		}
	case request.Resource.Group == "cdi.kubevirt.io" && request.Resource.Resource == "datavolumes":
		var volume cdiv1.DataVolume
		if err = json.Unmarshal(request.Object.Raw, &volume); err == nil {
			if volume.Spec.Source != nil {
				err = a.checkCopySource(ctx, request.Namespace, volume.Spec.Source.PVC, volume.Spec.Source.Snapshot)
			}
			if err == nil && volume.Spec.SourceRef != nil && volume.Spec.SourceRef.Kind == "DataSource" {
				namespace := request.Namespace
				if volume.Spec.SourceRef.Namespace != nil {
					namespace = *volume.Spec.SourceRef.Namespace
				}
				err = a.checkDataSource(ctx, namespace, volume.Spec.SourceRef.Name, 0)
			}
		}
	case request.Resource.Group == "cdi.kubevirt.io" && request.Resource.Resource == "datasources":
		var source cdiv1.DataSource
		if err = json.Unmarshal(request.Object.Raw, &source); err == nil {
			err = a.checkCopySource(ctx, request.Namespace, source.Spec.Source.PVC, source.Spec.Source.Snapshot)
			if err == nil && source.Spec.Source.DataSource != nil {
				namespace := source.Spec.Source.DataSource.Namespace
				if namespace == "" {
					namespace = request.Namespace
				}
				err = a.checkDataSource(ctx, namespace, source.Spec.Source.DataSource.Name, 0)
			}
		}
	case request.Resource.Group == exportv1.SchemeGroupVersion.Group && request.Resource.Resource == "virtualmachineexports":
		var export exportv1.VirtualMachineExport
		if err = json.Unmarshal(request.Object.Raw, &export); err == nil && export.Spec.Source.Kind == "PersistentVolumeClaim" {
			err = a.rejectReservedPVC(ctx, request.Namespace, export.Spec.Source.Name)
		}
	default:
		err = fmt.Errorf("unexpected hibernation admission resource")
	}
	if err != nil {
		return webhookutils.ToAdmissionResponseError(err)
	}
	return &admissionv1.AdmissionResponse{Allowed: true}
}

func (a *HibernationStateAdmitter) admitPVC(ctx context.Context, request *admissionv1.AdmissionRequest) error {
	var pvc, old corev1.PersistentVolumeClaim
	if request.Operation != admissionv1.Delete {
		if err := json.Unmarshal(request.Object.Raw, &pvc); err != nil {
			return err
		}
	}
	if request.Operation != admissionv1.Create {
		if err := json.Unmarshal(request.OldObject.Raw, &old); err != nil {
			return err
		}
	}
	if request.Operation == admissionv1.Delete {
		if !hibernation.ReservedStatePVC(&old) {
			return nil
		}
		owner := hibernation.StatePVCOwner(&old)
		if owner == nil {
			return fmt.Errorf("reserved state PVC has no valid VM owner")
		}
		vm, err := a.Client.VirtualMachine(request.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if vm.UID != owner.UID {
			return nil
		}
		if vm.DeletionTimestamp != nil && !hibernation.Active(vm.Annotations) {
			return nil
		}
		return fmt.Errorf("reserved state PVC cannot be deleted while its VM exists")
	}
	oldBinding, binding := old.Annotations[hibernation.VMUIDAnnotation], pvc.Annotations[hibernation.VMUIDAnnotation]
	if oldBinding != "" {
		if oldBinding != binding || !reflect.DeepEqual(old.OwnerReferences, pvc.OwnerReferences) {
			return fmt.Errorf("state PVC reservation and ownership are immutable")
		}
	} else if binding != "" {
		if !a.isController(request.UserInfo.Username) {
			return fmt.Errorf("only the KubeVirt controller may reserve a state PVC")
		}
		owner := hibernation.StatePVCOwner(&pvc)
		if owner == nil {
			return fmt.Errorf("reservation requires a matching VM owner")
		}
		vm, err := a.Client.VirtualMachine(request.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if vm.UID != owner.UID || vm.Annotations[hibernation.StatePVCAnnotation] != pvc.Name {
			return fmt.Errorf("VM does not own this state PVC reservation")
		}
		namespace, err := a.Client.CoreV1().Namespaces().Get(ctx, request.Namespace, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if namespace.Labels[hibernation.StateProtectionNamespaceLabel] != "enabled" {
			return fmt.Errorf("namespace state protection must be enabled first")
		}
	}
	if binding != "" && (pvc.Spec.DataSource != nil || pvc.Spec.DataSourceRef != nil) {
		return fmt.Errorf("a reserved state PVC cannot be populated or cloned")
	}
	if pvc.Spec.DataSource != nil {
		if err := a.checkTypedSource(ctx, request.Namespace, pvc.Spec.DataSource.Kind, pvc.Spec.DataSource.Name); err != nil {
			return err
		}
	}
	if pvc.Spec.DataSourceRef != nil {
		namespace := request.Namespace
		if pvc.Spec.DataSourceRef.Namespace != nil {
			namespace = *pvc.Spec.DataSourceRef.Namespace
		}
		if err := a.checkTypedSource(ctx, namespace, pvc.Spec.DataSourceRef.Kind, pvc.Spec.DataSourceRef.Name); err != nil {
			return err
		}
	}
	return nil
}

func (a *HibernationStateAdmitter) admitPod(ctx context.Context, request *admissionv1.AdmissionRequest) error {
	var pod corev1.Pod
	if request.Operation == admissionv1.Connect {
		current, err := a.Client.CoreV1().Pods(request.Namespace).Get(ctx, request.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		pod = *current
	} else if err := json.Unmarshal(request.Object.Raw, &pod); err != nil {
		return err
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.PersistentVolumeClaim == nil {
			continue
		}
		pvc, err := a.Client.CoreV1().PersistentVolumeClaims(request.Namespace).Get(ctx, volume.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		if !hibernation.ReservedStatePVC(pvc) {
			continue
		}
		if request.Operation == admissionv1.Connect || request.SubResource == "ephemeralcontainers" {
			return fmt.Errorf("interactive access to a hibernation state launcher is prohibited")
		}
		if request.Operation == admissionv1.Update {
			var old corev1.Pod
			if err := json.Unmarshal(request.OldObject.Raw, &old); err != nil {
				return err
			}
			// Metadata-only pod-controller and scheduler updates remain possible.
			if reflect.DeepEqual(old.Spec, pod.Spec) && reflect.DeepEqual(old.OwnerReferences, pod.OwnerReferences) {
				continue
			}
		}
		if !a.isController(request.UserInfo.Username) {
			return fmt.Errorf("reserved state PVC can only be mounted by the KubeVirt controller")
		}
		owner := metav1.GetControllerOf(&pod)
		if owner == nil || owner.Kind != "VirtualMachineInstance" || owner.APIVersion != v1.SchemeGroupVersion.String() {
			return fmt.Errorf("state PVC requires a VMI launcher owner")
		}
		vmi, err := a.Client.VirtualMachineInstance(request.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		vmOwner := metav1.GetControllerOf(vmi)
		if vmi.UID != owner.UID || vmOwner == nil || vmOwner.Kind != "VirtualMachine" || !hibernation.StatePVCBoundTo(pvc, vmOwner.UID) || vmi.Annotations[hibernation.StatePVCAnnotation] != pvc.Name {
			return fmt.Errorf("launcher does not belong to the state PVC's VM")
		}
		if volume.Name != hibernation.StateVolumeName {
			return fmt.Errorf("state PVC cannot be used as a guest or hotplug volume")
		}
		for _, container := range append(append([]corev1.Container{}, pod.Spec.Containers...), pod.Spec.InitContainers...) {
			for _, mount := range container.VolumeMounts {
				if mount.Name == volume.Name && (container.Name != "compute" || mount.MountPath != hibernation.StateMountPath || mount.SubPath != "" || mount.SubPathExpr != "") {
					return fmt.Errorf("state PVC must be private to the compute container")
				}
			}
		}
		if len(pod.Spec.EphemeralContainers) != 0 {
			return fmt.Errorf("state launcher cannot contain ephemeral containers")
		}
	}
	return nil
}

func (a *HibernationStateAdmitter) rejectReservedPVC(ctx context.Context, namespace, name string) error {
	if name == "" {
		return nil
	}
	pvc, err := a.Client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if hibernation.ReservedStatePVC(pvc) {
		return fmt.Errorf("reserved hibernation state PVC cannot be copied, snapshotted, or exported")
	}
	return nil
}

func (a *HibernationStateAdmitter) checkTypedSource(ctx context.Context, namespace, kind, name string) error {
	switch kind {
	case "PersistentVolumeClaim":
		return a.rejectReservedPVC(ctx, namespace, name)
	case "VolumeSnapshot":
		snapshot, err := a.Client.KubernetesSnapshotClient().SnapshotV1().VolumeSnapshots(namespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if snapshot.Spec.Source.PersistentVolumeClaimName != nil {
			return a.rejectReservedPVC(ctx, namespace, *snapshot.Spec.Source.PersistentVolumeClaimName)
		}
	case "DataSource":
		return a.checkDataSource(ctx, namespace, name, 0)
	}
	return nil
}

func (a *HibernationStateAdmitter) checkCopySource(ctx context.Context, namespace string, pvc *cdiv1.DataVolumeSourcePVC, snapshot *cdiv1.DataVolumeSourceSnapshot) error {
	if pvc != nil {
		sourceNamespace := pvc.Namespace
		if sourceNamespace == "" {
			sourceNamespace = namespace
		}
		if err := a.rejectReservedPVC(ctx, sourceNamespace, pvc.Name); err != nil {
			return err
		}
	}
	if snapshot != nil {
		sourceNamespace := snapshot.Namespace
		if sourceNamespace == "" {
			sourceNamespace = namespace
		}
		if err := a.checkTypedSource(ctx, sourceNamespace, "VolumeSnapshot", snapshot.Name); err != nil {
			return err
		}
	}
	return nil
}

func (a *HibernationStateAdmitter) checkDataSource(ctx context.Context, namespace, name string, depth int) error {
	if depth > 1 {
		return fmt.Errorf("DataSource reference chain exceeds the supported depth")
	}
	source, err := a.Client.CdiClient().CdiV1beta1().DataSources(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := a.checkCopySource(ctx, namespace, source.Spec.Source.PVC, source.Spec.Source.Snapshot); err != nil {
		return err
	}
	// CDI can still resolve a previously populated status while spec updates.
	if err := a.checkCopySource(ctx, namespace, source.Status.Source.PVC, source.Status.Source.Snapshot); err != nil {
		return err
	}
	if source.Spec.Source.DataSource != nil {
		next := source.Spec.Source.DataSource
		if next.Namespace != "" {
			namespace = next.Namespace
		}
		return a.checkDataSource(ctx, namespace, next.Name, depth+1)
	}
	return nil
}
