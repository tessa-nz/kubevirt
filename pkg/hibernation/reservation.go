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

package hibernation

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	v1 "kubevirt.io/api/core/v1"
)

func ReservedStatePVC(pvc *corev1.PersistentVolumeClaim) bool {
	return pvc != nil && pvc.Annotations[VMUIDAnnotation] != ""
}

func StatePVCOwner(pvc *corev1.PersistentVolumeClaim) *metav1.OwnerReference {
	if !ReservedStatePVC(pvc) {
		return nil
	}
	for _, owner := range pvc.OwnerReferences {
		if owner.APIVersion == v1.SchemeGroupVersion.String() && owner.Kind == "VirtualMachine" && string(owner.UID) == pvc.Annotations[VMUIDAnnotation] {
			return &owner
		}
	}
	return nil
}

func StatePVCBoundTo(pvc *corev1.PersistentVolumeClaim, vmUID types.UID) bool {
	owner := StatePVCOwner(pvc)
	return owner != nil && vmUID != "" && owner.UID == vmUID
}

func PodUsesPVC(pod *corev1.Pod, name string) bool {
	for _, volume := range pod.Spec.Volumes {
		if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == name {
			return true
		}
	}
	return false
}
