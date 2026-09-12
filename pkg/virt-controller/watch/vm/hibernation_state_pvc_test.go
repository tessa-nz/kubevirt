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
	"errors"
	"testing"

	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
	"kubevirt.io/kubevirt/pkg/hibernation"
)

func TestStatePVCReservationPreservesOwnershipAndConflicts(t *testing.T) {
	for _, scenario := range []string{"reserve", "namespace-disabled", "foreign-owner", "existing-pod", "conflict", "idempotent"} {
		t.Run(scenario, func(t *testing.T) {
			vm := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "vm", UID: "vm-uid", Annotations: map[string]string{hibernation.StatePVCAnnotation: "state"}}, Spec: v1.VirtualMachineSpec{Template: &v1.VirtualMachineInstanceTemplateSpec{}}}
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test", Labels: map[string]string{hibernation.StateProtectionNamespaceLabel: "enabled"}}}
			pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "state", ResourceVersion: "42"}}
			if scenario == "namespace-disabled" {
				ns.Labels = nil
			}
			if scenario == "foreign-owner" {
				pvc.Annotations = map[string]string{hibernation.VMUIDAnnotation: "someone-else"}
			}
			if scenario == "idempotent" {
				pvc.Annotations = map[string]string{hibernation.VMUIDAnnotation: string(vm.UID)}
				pvc.OwnerReferences = []metav1.OwnerReference{{APIVersion: v1.SchemeGroupVersion.String(), Kind: "VirtualMachine", Name: vm.Name, UID: vm.UID}}
			}
			objects := []runtime.Object{ns, pvc}
			if scenario == "existing-pod" {
				objects = append(objects, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "test", Name: "reader"}, Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "existing", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "state"}}}}}})
			}
			api := fake.NewSimpleClientset(objects...)
			updates := 0
			api.PrependReactor("update", "persistentvolumeclaims", func(action k8stesting.Action) (bool, runtime.Object, error) {
				updates++
				updated := action.(k8stesting.UpdateAction).GetObject().(*corev1.PersistentVolumeClaim)
				if updated.ResourceVersion != "42" || !hibernation.StatePVCBoundTo(updated, vm.UID) {
					t.Fatal("reservation lost optimistic concurrency or ownership")
				}
				if scenario == "conflict" {
					return true, nil, errors.New("resource version conflict")
				}
				return false, nil, nil
			})
			client := kubecli.NewMockKubevirtClient(gomock.NewController(t))
			client.EXPECT().CoreV1().Return(api.CoreV1()).AnyTimes()
			c := &Controller{clientset: client}
			err := c.reserveHibernationStatePVC(vm)
			if (err == nil) != (scenario == "reserve" || scenario == "idempotent") {
				t.Fatalf("unexpected reservation result: %v", err)
			}
			expectedUpdates := 0
			if scenario == "reserve" || scenario == "conflict" {
				expectedUpdates = 1
			}
			if updates != expectedUpdates {
				t.Fatalf("unexpected PVC mutations: %d", updates)
			}
		})
	}
}
