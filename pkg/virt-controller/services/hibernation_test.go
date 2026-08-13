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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/hibernation"
)

func TestHibernationStatePVCIsMountedOnlyInLauncher(t *testing.T) {
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	pvc := &k8sv1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "state", Namespace: "lab"}}
	if err := store.Add(pvc); err != nil {
		t.Fatal(err)
	}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{
		Namespace:   "lab",
		Annotations: map[string]string{hibernation.StatePVCAnnotation: "state"},
	}}
	renderer := &VolumeRenderer{}
	if err := withHibernationState(vmi, store)(renderer); err != nil {
		t.Fatal(err)
	}
	if len(renderer.podVolumes) != 1 || renderer.podVolumes[0].PersistentVolumeClaim.ClaimName != "state" {
		t.Fatalf("unexpected state volume: %#v", renderer.podVolumes)
	}
	if len(renderer.podVolumeMounts) != 1 || renderer.podVolumeMounts[0].MountPath != hibernation.StateMountPath {
		t.Fatalf("unexpected state mount: %#v", renderer.podVolumeMounts)
	}
	if len(vmi.Spec.Volumes) != 0 || len(vmi.Spec.Domain.Devices.Disks) != 0 {
		t.Fatal("state PVC must not be exposed as a guest volume or disk")
	}
}

func TestHibernationStateRejectsBlockPVC(t *testing.T) {
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	mode := k8sv1.PersistentVolumeBlock
	pvc := &k8sv1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "state", Namespace: "lab"},
		Spec:       k8sv1.PersistentVolumeClaimSpec{VolumeMode: &mode},
	}
	if err := store.Add(pvc); err != nil {
		t.Fatal(err)
	}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{
		Namespace:   "lab",
		Annotations: map[string]string{hibernation.StatePVCAnnotation: "state"},
	}}
	if err := withHibernationState(vmi, store)(&VolumeRenderer{}); err == nil {
		t.Fatal("expected raw Block state PVC to be rejected")
	}
}
