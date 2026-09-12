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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	virtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/kubevirt/pkg/hibernation"
)

// Reserve before creating the VMI. Namespace admission must already be enabled
// by an administrator. The immutable PVC binding follows the VM's lifetime.
func (c *Controller) reserveHibernationStatePVC(vm *virtv1.VirtualMachine) error {
	name := vm.Annotations[hibernation.StatePVCAnnotation]
	if name == "" {
		return nil
	}
	if vm.UID == "" {
		return fmt.Errorf("state PVC reservation requires a persisted VM identity")
	}
	ctx := context.Background()
	namespace, err := c.clientset.CoreV1().Namespaces().Get(ctx, vm.Namespace, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if namespace.Labels[hibernation.StateProtectionNamespaceLabel] != "enabled" {
		return fmt.Errorf("namespace must enable hibernation state protection before launcher creation")
	}
	for _, volume := range vm.Spec.Template.Spec.Volumes {
		if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == name || volume.DataVolume != nil && volume.DataVolume.Name == name {
			return fmt.Errorf("state PVC cannot also be a guest volume")
		}
	}
	pvc, err := c.clientset.CoreV1().PersistentVolumeClaims(vm.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if hibernation.StatePVCBoundTo(pvc, vm.UID) {
		return nil
	}
	if hibernation.ReservedStatePVC(pvc) {
		return fmt.Errorf("hibernation state PVC is reserved for a different VM")
	}
	if pvc.DeletionTimestamp != nil || pvc.Spec.DataSource != nil || pvc.Spec.DataSourceRef != nil || len(pvc.OwnerReferences) != 0 || pvc.Spec.VolumeMode != nil && *pvc.Spec.VolumeMode == corev1.PersistentVolumeBlock {
		return fmt.Errorf("hibernation requires a dedicated filesystem PVC without clone, import, or other ownership")
	}
	pods, err := c.clientset.CoreV1().Pods(vm.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, pod := range pods.Items {
		if hibernation.PodUsesPVC(&pod, name) {
			return fmt.Errorf("state PVC is already referenced by pod %s", pod.Name)
		}
	}
	pvc = pvc.DeepCopy()
	if pvc.Annotations == nil {
		pvc.Annotations = map[string]string{}
	}
	pvc.Annotations[hibernation.VMUIDAnnotation] = string(vm.UID)
	pvc.OwnerReferences = append(pvc.OwnerReferences, metav1.OwnerReference{APIVersion: virtv1.SchemeGroupVersion.String(), Kind: "VirtualMachine", Name: vm.Name, UID: vm.UID})
	_, err = c.clientset.CoreV1().PersistentVolumeClaims(vm.Namespace).Update(ctx, pvc, metav1.UpdateOptions{})
	return err
}
