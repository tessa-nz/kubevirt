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

	admissionv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/api"
	"kubevirt.io/kubevirt/pkg/hibernation"
	instancetypeWebhooks "kubevirt.io/kubevirt/pkg/instancetype/webhooks/vm"
	"kubevirt.io/kubevirt/pkg/pointer"
	"kubevirt.io/kubevirt/pkg/testutils"
	"kubevirt.io/kubevirt/pkg/virt-api/webhooks"
)

func TestHibernationAdmissionProtectsVMControl(t *testing.T) {
	config, _, _ := testutils.NewFakeClusterConfigUsingKVConfig(&v1.KubeVirtConfiguration{})
	for _, tc := range []struct {
		name, key, value                                 string
		remove, active, spec, template, trusted, allowed bool
	}{
		{name: "forged request", key: hibernation.RequestAnnotation, value: "hibernate"},
		{name: "forged digest", key: hibernation.ArtifactDigestAnnotation, value: "forged"},
		{name: "deleted state", key: hibernation.StateAnnotation, remove: true, active: true},
		{name: "replaced state PVC", key: hibernation.StatePVCAnnotation, value: "other", active: true},
		{name: "active spec", active: true, spec: true},
		{name: "template injection", key: hibernation.RequestAnnotation, value: "save", template: true},
		{name: "unrelated metadata", key: "example.com/note", value: "hello", active: true, allowed: true},
		{name: "inert state PVC", key: hibernation.StatePVCAnnotation, value: "state", allowed: true},
		{name: "controller update", key: hibernation.StateAnnotation, value: hibernation.StateSaving, trusted: true, allowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := &v1.VirtualMachine{Spec: v1.VirtualMachineSpec{Running: pointer.P(false), Template: &v1.VirtualMachineInstanceTemplateSpec{Spec: api.NewMinimalVMI("test").Spec}}}
			old.Annotations = map[string]string{}
			if tc.active {
				old.Annotations[hibernation.StateAnnotation] = hibernation.StateHibernated
			}
			current := old.DeepCopy()
			if tc.template {
				current.Spec.Template.ObjectMeta.Annotations = map[string]string{tc.key: tc.value}
			} else if tc.spec {
				current.Spec.Template.Spec.Domain.CPU = &v1.CPU{Cores: 8}
			} else if tc.remove {
				delete(current.Annotations, tc.key)
			} else {
				current.Annotations[tc.key] = tc.value
			}
			oldRaw, _ := json.Marshal(old)
			newRaw, _ := json.Marshal(current)
			username := "editor"
			if tc.trusted {
				username = "system:serviceaccount:kubevirt:kubevirt-apiserver"
			}
			admitter := &VMsAdmitter{ClusterConfig: config, InstancetypeAdmitter: instancetypeWebhooks.NewAdmitterStub(), KubeVirtServiceAccounts: webhooks.KubeVirtServiceAccounts("kubevirt")}
			result := admitter.Admit(context.Background(), &admissionv1.AdmissionReview{Request: &admissionv1.AdmissionRequest{Resource: webhooks.VirtualMachineGroupVersionResource, Operation: admissionv1.Update, UserInfo: authv1.UserInfo{Username: username}, OldObject: runtime.RawExtension{Raw: oldRaw}, Object: runtime.RawExtension{Raw: newRaw}}})
			if result.Allowed != tc.allowed {
				t.Fatalf("allowed=%v want %v: %+v", result.Allowed, tc.allowed, result.Result)
			}
		})
	}
}

func TestHibernationAdmissionProtectsVMIControl(t *testing.T) {
	config, _, _ := testutils.NewFakeClusterConfigUsingKVConfig(&v1.KubeVirtConfiguration{})
	for _, tc := range []struct {
		name                     string
		remove, trusted, allowed bool
	}{
		{name: "forge"}, {name: "remove", remove: true}, {name: "controller", trusted: true, allowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := api.NewMinimalVMI("test")
			old.Annotations = map[string]string{hibernation.ArtifactDigestAnnotation: "original"}
			current := old.DeepCopy()
			if tc.remove {
				delete(current.Annotations, hibernation.ArtifactDigestAnnotation)
			} else {
				current.Annotations[hibernation.ArtifactDigestAnnotation] = "forged"
			}
			oldRaw, _ := json.Marshal(old)
			newRaw, _ := json.Marshal(current)
			username := "editor"
			if tc.trusted {
				username = "system:serviceaccount:kubevirt:kubevirt-controller"
			}
			admitter := NewVMIUpdateAdmitter(config, webhooks.KubeVirtServiceAccounts("kubevirt"))
			result := admitter.Admit(context.Background(), &admissionv1.AdmissionReview{Request: &admissionv1.AdmissionRequest{Resource: webhooks.VirtualMachineInstanceGroupVersionResource, Operation: admissionv1.Update, UserInfo: authv1.UserInfo{Username: username}, OldObject: runtime.RawExtension{Raw: oldRaw}, Object: runtime.RawExtension{Raw: newRaw}}})
			if result.Allowed != tc.allowed {
				t.Fatalf("allowed=%v want %v: %+v", result.Allowed, tc.allowed, result.Result)
			}
		})
	}
}
