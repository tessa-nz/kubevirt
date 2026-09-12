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
	"testing"

	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	v1 "kubevirt.io/api/core/v1"
	cdifake "kubevirt.io/client-go/containerizeddataimporter/fake"
	"kubevirt.io/client-go/kubecli"
	cdiv1 "kubevirt.io/containerized-data-importer-api/pkg/apis/core/v1beta1"
	"kubevirt.io/kubevirt/pkg/hibernation"
)

const hibernationTestController = "system:serviceaccount:kubevirt:kubevirt-controller"

func hibernationAdmissionFixture(t *testing.T) (*HibernationStateAdmitter, *kubecli.MockKubevirtClient, *corev1.PersistentVolumeClaim, *v1.VirtualMachineInstance, *corev1.Pod) {
	t.Helper()
	ctrl := gomock.NewController(t)
	client := kubecli.NewMockKubevirtClient(ctrl)
	vm := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Name: "vm", Namespace: "lab", UID: "vm-uid", Annotations: map[string]string{hibernation.StatePVCAnnotation: "state"}}}
	pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "state", Namespace: "lab", UID: "pvc-uid", Annotations: map[string]string{hibernation.VMUIDAnnotation: "vm-uid"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: v1.SchemeGroupVersion.String(), Kind: "VirtualMachine", Name: "vm", UID: "vm-uid"}}}}
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Name: "vm", Namespace: "lab", UID: "vmi-uid", Annotations: map[string]string{hibernation.StatePVCAnnotation: "state"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(vm, v1.VirtualMachineGroupVersionKind)}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "virt-launcher-vm", Namespace: "lab", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(vmi, v1.VirtualMachineInstanceGroupVersionKind)}}, Spec: corev1.PodSpec{
		Volumes:    []corev1.Volume{{Name: hibernation.StateVolumeName, VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "state"}}}},
		Containers: []corev1.Container{{Name: "compute", VolumeMounts: []corev1.VolumeMount{{Name: hibernation.StateVolumeName, MountPath: hibernation.StateMountPath}}}},
	}}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "lab", Labels: map[string]string{hibernation.StateProtectionNamespaceLabel: "enabled"}}}
	kube := fake.NewSimpleClientset(pvc, pod, namespace)
	client.EXPECT().CoreV1().Return(kube.CoreV1()).AnyTimes()
	vmClient := kubecli.NewMockVirtualMachineInterface(ctrl)
	client.EXPECT().VirtualMachine("lab").Return(vmClient).AnyTimes()
	vmClient.EXPECT().Get(gomock.Any(), "vm", gomock.Any()).Return(vm, nil).AnyTimes()
	vmiClient := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)
	client.EXPECT().VirtualMachineInstance("lab").Return(vmiClient).AnyTimes()
	vmiClient.EXPECT().Get(gomock.Any(), "vm", gomock.Any()).Return(vmi, nil).AnyTimes()
	return &HibernationStateAdmitter{Client: client, KubeVirtServiceAccounts: map[string]struct{}{hibernationTestController: {}}}, client, pvc, vmi, pod
}

func stateAdmissionRequest(t *testing.T, group, resource string, operation admissionv1.Operation, object, old any, username string) *admissionv1.AdmissionReview {
	t.Helper()
	encode := func(value any) runtime.RawExtension {
		if value == nil {
			return runtime.RawExtension{}
		}
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return runtime.RawExtension{Raw: data}
	}
	return &admissionv1.AdmissionReview{Request: &admissionv1.AdmissionRequest{Resource: metav1.GroupVersionResource{Group: group, Version: "v1", Resource: resource}, Namespace: "lab", Name: "virt-launcher-vm", Operation: operation, UserInfo: authv1.UserInfo{Username: username}, Object: encode(object), OldObject: encode(old)}}
}

func TestHibernationReservedPodAdmission(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		mutate      func(*corev1.Pod)
		username    string
		operation   admissionv1.Operation
		subresource string
		allowed     bool
	}{
		{name: "ordinary pod denied", username: "alice", operation: admissionv1.Create},
		{name: "controller launcher allowed", username: hibernationTestController, operation: admissionv1.Create, allowed: true},
		{name: "wrong controller denied", username: "system:serviceaccount:other:kubevirt-controller", operation: admissionv1.Create},
		{name: "forged launcher owner denied", username: hibernationTestController, operation: admissionv1.Create, mutate: func(p *corev1.Pod) { p.OwnerReferences[0].UID = "forged" }},
		{name: "guest mount denied", username: hibernationTestController, operation: admissionv1.Create, mutate: func(p *corev1.Pod) { p.Spec.Volumes[0].Name = "guest-disk" }},
		{name: "sidecar mount denied", username: hibernationTestController, operation: admissionv1.Create, mutate: func(p *corev1.Pod) { p.Spec.Containers[0].Name = "sidecar" }},
		{name: "exec denied", username: "alice", operation: admissionv1.Connect, subresource: "exec"},
		{name: "attach denied", username: "alice", operation: admissionv1.Connect, subresource: "attach"},
		{name: "ephemeral container denied", username: "alice", operation: admissionv1.Update, subresource: "ephemeralcontainers"},
		{name: "metadata update allowed", username: "system:kube-scheduler", operation: admissionv1.Update, allowed: true, mutate: func(p *corev1.Pod) { p.Labels = map[string]string{"unrelated": "value"} }},
		{name: "ordinary unreserved PVC allowed", username: "alice", operation: admissionv1.Create, allowed: true, mutate: func(p *corev1.Pod) { p.Spec.Volumes[0].PersistentVolumeClaim.ClaimName = "ordinary" }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			admitter, _, _, _, pod := hibernationAdmissionFixture(t)
			old := pod.DeepCopy()
			if scenario.mutate != nil {
				scenario.mutate(pod)
			}
			request := stateAdmissionRequest(t, "", "pods", scenario.operation, pod, old, scenario.username)
			request.Request.SubResource = scenario.subresource
			response := admitter.Admit(context.Background(), request)
			if response.Allowed != scenario.allowed {
				t.Fatalf("allowed=%t want=%t result=%v", response.Allowed, scenario.allowed, response.Result)
			}
		})
	}
}

func TestHibernationPVCReservationAdmission(t *testing.T) {
	for _, scenario := range []string{"remove binding", "replace binding", "remove owner", "ordinary reservation", "controller reservation", "unrelated metadata", "delete"} {
		t.Run(scenario, func(t *testing.T) {
			admitter, _, pvc, _, _ := hibernationAdmissionFixture(t)
			old := pvc.DeepCopy()
			username := "alice"
			operation := admissionv1.Update
			allowed := false
			switch scenario {
			case "remove binding":
				delete(pvc.Annotations, hibernation.VMUIDAnnotation)
			case "replace binding":
				pvc.Annotations[hibernation.VMUIDAnnotation] = "other-vm"
			case "remove owner":
				pvc.OwnerReferences = nil
			case "ordinary reservation":
				old.Annotations = nil
				old.OwnerReferences = nil
			case "controller reservation":
				old.Annotations = nil
				old.OwnerReferences = nil
				username = hibernationTestController
				allowed = true
			case "unrelated metadata":
				pvc.Labels = map[string]string{"normal": "edit"}
				allowed = true
			case "delete":
				operation = admissionv1.Delete
			}
			response := admitter.Admit(context.Background(), stateAdmissionRequest(t, "", "persistentvolumeclaims", operation, pvc, old, username))
			if response.Allowed != allowed {
				t.Fatalf("allowed=%t want=%t result=%v", response.Allowed, allowed, response.Result)
			}
		})
	}
}

func TestHibernationRejectsReservedStateCopyEntryPoints(t *testing.T) {
	for _, scenario := range []struct{ name, group, resource, object string }{
		{"PVC clone", "", "persistentvolumeclaims", `{"spec":{"dataSource":{"kind":"PersistentVolumeClaim","name":"state"}}}`},
		{"cross-namespace PVC clone", "", "persistentvolumeclaims", `{"spec":{"dataSourceRef":{"kind":"PersistentVolumeClaim","name":"state","namespace":"lab"}}}`},
		{"snapshot", "snapshot.storage.k8s.io", "volumesnapshots", `{"spec":{"source":{"persistentVolumeClaimName":"state"}}}`},
		{"DataVolume clone", "cdi.kubevirt.io", "datavolumes", `{"spec":{"source":{"pvc":{"namespace":"lab","name":"state"}}}}`},
		{"DataSource clone", "cdi.kubevirt.io", "datasources", `{"spec":{"source":{"pvc":{"namespace":"lab","name":"state"}}}}`},
		{"PVC export", "export.kubevirt.io", "virtualmachineexports", `{"spec":{"source":{"kind":"PersistentVolumeClaim","name":"state"}}}`},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			admitter, _, _, _, _ := hibernationAdmissionFixture(t)
			request := stateAdmissionRequest(t, scenario.group, scenario.resource, admissionv1.Create, nil, nil, "alice")
			request.Request.Object.Raw = []byte(scenario.object)
			if response := admitter.Admit(context.Background(), request); response.Allowed {
				t.Fatal("reserved state copy was admitted")
			}
		})
	}
}

func TestHibernationResolvesIndirectCrossNamespaceClone(t *testing.T) {
	admitter, client, _, _, _ := hibernationAdmissionFixture(t)
	source := &cdiv1.DataSource{ObjectMeta: metav1.ObjectMeta{Name: "indirect", Namespace: "other"}, Spec: cdiv1.DataSourceSpec{Source: cdiv1.DataSourceSource{PVC: &cdiv1.DataVolumeSourcePVC{Namespace: "lab", Name: "state"}}}}
	cdi := cdifake.NewSimpleClientset(source)
	client.EXPECT().CdiClient().Return(cdi)
	request := stateAdmissionRequest(t, "cdi.kubevirt.io", "datavolumes", admissionv1.Create, nil, nil, "alice")
	request.Request.Namespace = "other"
	request.Request.Object.Raw = []byte(`{"spec":{"sourceRef":{"kind":"DataSource","name":"indirect"}}}`)
	if response := admitter.Admit(context.Background(), request); response.Allowed {
		t.Fatal("indirect cross-namespace clone was admitted")
	}
}
