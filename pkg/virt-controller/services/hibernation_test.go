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

package services

import (
	"testing"

	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/hibernation"
)

func TestHibernationStatePVCIsMountedOnlyInLauncher(t *testing.T) {
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	pvc := &k8sv1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "state", Namespace: "lab", Annotations: map[string]string{hibernation.VMUIDAnnotation: "vm-uid"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: v1.SchemeGroupVersion.String(), Kind: "VirtualMachine", Name: "vm", UID: "vm-uid"}}}}
	if err := store.Add(pvc); err != nil {
		t.Fatal(err)
	}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{
		Namespace: "lab", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Name: "vm", UID: "vm-uid"}}, v1.VirtualMachineGroupVersionKind)},
		Annotations: map[string]string{hibernation.StatePVCAnnotation: "state"},
	}}
	renderer := &VolumeRenderer{}
	if err := withHibernationState(vmi, store)(renderer); err != nil {
		t.Fatal(err)
	}
	if len(renderer.podVolumes) != 2 || renderer.podVolumes[0].PersistentVolumeClaim.ClaimName != "state" {
		t.Fatalf("unexpected state volume: %#v", renderer.podVolumes)
	}
	if len(renderer.podVolumeMounts) != 2 || renderer.podVolumeMounts[0].MountPath != hibernation.StateMountPath {
		t.Fatalf("unexpected state mount: %#v", renderer.podVolumeMounts)
	}
	if len(vmi.Spec.Volumes) != 0 || len(vmi.Spec.Domain.Devices.Disks) != 0 {
		t.Fatal("state PVC must not be exposed as a guest volume or disk")
	}
	staging := renderer.podVolumes[1].EmptyDir
	if staging == nil || staging.Medium != k8sv1.StorageMediumMemory || staging.SizeLimit == nil || renderer.podVolumeMounts[1].MountPath != hibernation.StagingMountPath {
		t.Fatal("plaintext staging is not a bounded memory-only launcher volume")
	}
}

func TestHibernationMemoryCannotBeOvercommitted(t *testing.T) {
	guest := resource.MustParse("32Gi")
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{hibernation.StatePVCAnnotation: "state"}}, Spec: v1.VirtualMachineInstanceSpec{Domain: v1.DomainSpec{
		Memory: &v1.Memory{Guest: &guest}, Resources: v1.ResourceRequirements{OvercommitGuestOverhead: true, Requests: k8sv1.ResourceList{k8sv1.ResourceMemory: resource.MustParse("16Gi")}, Limits: k8sv1.ResourceList{k8sv1.ResourceMemory: guest}},
	}}}
	overhead := resource.MustParse("512Mi")
	renderer := NewResourceRenderer(vmi.Spec.Domain.Resources.Limits, vmi.Spec.Domain.Resources.Requests, WithMemoryOverhead(vmi.Spec.Domain.Resources, overhead), withHibernationMemory(vmi, overhead))
	want := hibernation.StateCapacity(vmi)
	want.Add(guest)
	want.Add(overhead)
	requests, limits := renderer.Requests(), renderer.Limits()
	if requests.Memory().Cmp(want) != 0 || limits.Memory().Cmp(want) != 0 {
		t.Fatal("launcher does not reserve guest RAM plus its entire private save image")
	}
}

func TestHibernationStateRejectsBlockPVC(t *testing.T) {
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	mode := k8sv1.PersistentVolumeBlock
	pvc := &k8sv1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "state", Namespace: "lab", Annotations: map[string]string{hibernation.VMUIDAnnotation: "vm-uid"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: v1.SchemeGroupVersion.String(), Kind: "VirtualMachine", Name: "vm", UID: "vm-uid"}}},
		Spec:       k8sv1.PersistentVolumeClaimSpec{VolumeMode: &mode},
	}
	if err := store.Add(pvc); err != nil {
		t.Fatal(err)
	}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{
		Namespace: "lab", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Name: "vm", UID: "vm-uid"}}, v1.VirtualMachineGroupVersionKind)},
		Annotations: map[string]string{hibernation.StatePVCAnnotation: "state"},
	}}
	if err := withHibernationState(vmi, store)(&VolumeRenderer{}); err == nil {
		t.Fatal("expected raw Block state PVC to be rejected")
	}
}
