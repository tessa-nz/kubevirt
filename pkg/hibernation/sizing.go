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
	"k8s.io/apimachinery/pkg/api/resource"
	v1 "kubevirt.io/api/core/v1"
)

// StateCapacity covers one full plaintext save image in private tmpfs, or its
// ciphertext on the state PVC. It is added to launcher memory overhead because
// libvirt can retain the guest's RAM until the complete save has been written.
func StateCapacity(vmi *v1.VirtualMachineInstance) resource.Quantity {
	memory := GuestMemoryBytes(vmi)
	required := resource.NewQuantity(memory, resource.BinarySI)
	required.Add(*resource.NewQuantity(memory/10, resource.BinarySI))
	required.Add(*resource.NewQuantity(1<<30, resource.BinarySI))
	return *required
}

func GuestMemoryBytes(vmi *v1.VirtualMachineInstance) int64 {
	memory := vmi.Spec.Domain.Resources.Requests.Memory().Value()
	if vmi.Spec.Domain.Memory != nil && vmi.Spec.Domain.Memory.Guest != nil && vmi.Spec.Domain.Memory.Guest.Value() > memory {
		memory = vmi.Spec.Domain.Memory.Guest.Value()
	}
	return memory
}
