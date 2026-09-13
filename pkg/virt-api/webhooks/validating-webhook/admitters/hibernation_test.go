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
	"strings"
	"testing"

	kubevirtfake "kubevirt.io/client-go/kubevirt/fake"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfield "k8s.io/apimachinery/pkg/util/validation/field"
	poolv1 "kubevirt.io/api/pool/v1beta1"

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

func TestHibernationDeletionRequiresCompletedAttempt(t *testing.T) {
	config, _, _ := testutils.NewFakeClusterConfigUsingKVConfig(&v1.KubeVirtConfiguration{})
	for _, active := range []bool{false, true} {
		for _, trusted := range []bool{false, true} {
			for _, kind := range []string{"vm", "vmi"} {
				t.Run(fmt.Sprintf("%s/active=%v/trusted=%v", kind, active, trusted), func(t *testing.T) {
					old := metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
					if active {
						old.Annotations[hibernation.StateAnnotation] = hibernation.StateHibernated
					}
					raw, err := json.Marshal(old)
					if err != nil {
						t.Fatal(err)
					}
					username := "editor"
					if trusted {
						username = "system:serviceaccount:kubevirt:kubevirt-controller"
					}
					accounts := webhooks.KubeVirtServiceAccounts("kubevirt")
					ar := &admissionv1.AdmissionReview{Request: &admissionv1.AdmissionRequest{Operation: admissionv1.Delete, UserInfo: authv1.UserInfo{Username: username}, OldObject: runtime.RawExtension{Raw: raw}}}
					var response *admissionv1.AdmissionResponse
					if kind == "vm" {
						ar.Request.Resource = webhooks.VirtualMachineGroupVersionResource
						response = (&VMsAdmitter{KubeVirtServiceAccounts: accounts}).Admit(context.Background(), ar)
					} else {
						ar.Request.Resource = webhooks.VirtualMachineInstanceGroupVersionResource
						response = NewVMIUpdateAdmitter(config, accounts).Admit(context.Background(), ar)
					}
					if response.Allowed != (!active || trusted) {
						t.Fatalf("unexpected delete response: %+v", response)
					}
				})
			}
		}
	}
}

func TestHibernationParentTemplatesCannotForgeControl(t *testing.T) {
	config, _, _ := testutils.NewFakeClusterConfigUsingKVConfig(&v1.KubeVirtConfiguration{})
	for _, kind := range []string{"pool", "replicaset"} {
		t.Run(kind, func(t *testing.T) {
			template := &v1.VirtualMachineInstanceTemplateSpec{Spec: api.NewMinimalVMI("test").Spec}
			annotations := map[string]string{hibernation.RequestAnnotation: hibernation.RequestHibernate}
			var causes []metav1.StatusCause
			if kind == "pool" {
				pool := &poolv1.VirtualMachinePool{Spec: poolv1.VirtualMachinePoolSpec{VirtualMachineTemplate: &poolv1.VirtualMachineTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: annotations}, Spec: v1.VirtualMachineSpec{Running: pointer.P(false), Template: template}}}}
				causes = ValidateVMPoolSpec(&admissionv1.AdmissionReview{Request: &admissionv1.AdmissionRequest{Operation: admissionv1.Create}}, k8sfield.NewPath("spec"), pool, config, false)
			} else {
				template.ObjectMeta.Annotations = annotations
				causes = ValidateVMIRSSpec(k8sfield.NewPath("spec"), &v1.VirtualMachineInstanceReplicaSetSpec{Template: template}, config)
			}
			for _, cause := range causes {
				if strings.Contains(cause.Message, "hibernation control") {
					return
				}
			}
			t.Fatalf("parent template control was accepted: %+v", causes)
		})
	}
}

func TestHibernationConfiguredVMICannotBeDeletedOrMigrated(t *testing.T) {
	config, _, _ := testutils.NewFakeClusterConfigUsingKVConfig(&v1.KubeVirtConfiguration{})
	vmi := api.NewMinimalVMI("test")
	vmi.Namespace = "default"
	vmi.Annotations = map[string]string{hibernation.StatePVCAnnotation: "state"}
	raw, _ := json.Marshal(vmi)
	ar := &admissionv1.AdmissionReview{Request: &admissionv1.AdmissionRequest{Resource: webhooks.VirtualMachineInstanceGroupVersionResource, Operation: admissionv1.Delete, OldObject: runtime.RawExtension{Raw: raw}}}
	response := NewVMIUpdateAdmitter(config, webhooks.KubeVirtServiceAccounts("kubevirt")).Admit(context.Background(), ar)
	if response.Allowed {
		t.Fatal("direct delete passed before save request propagation")
	}
	migration := &v1.VirtualMachineInstanceMigration{ObjectMeta: metav1.ObjectMeta{Name: "migration", Namespace: "default"}, Spec: v1.VirtualMachineInstanceMigrationSpec{VMIName: "test"}}
	raw, _ = json.Marshal(migration)
	ar = &admissionv1.AdmissionReview{Request: &admissionv1.AdmissionRequest{Resource: webhooks.MigrationGroupVersionResource, Operation: admissionv1.Create, Object: runtime.RawExtension{Raw: raw}}}
	response = NewMigrationCreateAdmitter(kubevirtfake.NewSimpleClientset(vmi), config, nil).Admit(context.Background(), ar)
	if response.Allowed || !strings.Contains(response.Result.Message, "hibernation") {
		t.Fatalf("migration bypassed preconfigured state: %+v", response)
	}
}

func TestHibernationOwnershipCannotBeTransferred(t *testing.T) {
	config, _, _ := testutils.NewFakeClusterConfigUsingKVConfig(&v1.KubeVirtConfiguration{})
	old := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{hibernation.StatePVCAnnotation: "state"}}, Spec: v1.VirtualMachineSpec{Running: pointer.P(false), Template: &v1.VirtualMachineInstanceTemplateSpec{Spec: api.NewMinimalVMI("test").Spec}}}
	updated := old.DeepCopy()
	updated.OwnerReferences = []metav1.OwnerReference{{APIVersion: "pool.kubevirt.io/v1beta1", Kind: "VirtualMachinePool", Name: "pool", UID: "pool-uid", Controller: pointer.P(true)}}
	oldRaw, _ := json.Marshal(old)
	newRaw, _ := json.Marshal(updated)
	ar := &admissionv1.AdmissionReview{Request: &admissionv1.AdmissionRequest{Resource: webhooks.VirtualMachineGroupVersionResource, Operation: admissionv1.Update, OldObject: runtime.RawExtension{Raw: oldRaw}, Object: runtime.RawExtension{Raw: newRaw}}}
	response := (&VMsAdmitter{ClusterConfig: config}).Admit(context.Background(), ar)
	if response.Allowed || response.Result.Details.Causes[0].Field != "metadata.ownerReferences" {
		t.Fatalf("VM ownership change bypassed attempt: %+v", response)
	}
	oldVMI := api.NewMinimalVMI("test")
	oldVMI.Annotations = old.Annotations
	newVMI := oldVMI.DeepCopy()
	newVMI.OwnerReferences = updated.OwnerReferences
	oldRaw, _ = json.Marshal(oldVMI)
	newRaw, _ = json.Marshal(newVMI)
	ar.Request.Resource = webhooks.VirtualMachineInstanceGroupVersionResource
	ar.Request.OldObject.Raw = oldRaw
	ar.Request.Object.Raw = newRaw
	response = NewVMIUpdateAdmitter(config, nil).Admit(context.Background(), ar)
	if response.Allowed || response.Result.Details.Causes[0].Field != "metadata.ownerReferences" {
		t.Fatalf("VMI ownership change bypassed attempt: %+v", response)
	}
}

func TestDiscardHaltAdmissionIsNarrow(t *testing.T) {
	config, _, _ := testutils.NewFakeClusterConfigUsingKVConfig(&v1.KubeVirtConfiguration{})
	for _, tc := range []struct {
		name                                    string
		trusted, alterDisk, newAttempt, allowed bool
	}{
		{name: "controller halts discarded attempt", trusted: true, allowed: true},
		{name: "editor cannot halt active attempt"},
		{name: "controller cannot also change disks", trusted: true, alterDisk: true},
		{name: "controller cannot replace attempt", trusted: true, newAttempt: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := &v1.VirtualMachine{Spec: v1.VirtualMachineSpec{RunStrategy: pointer.P(v1.RunStrategyAlways), Template: &v1.VirtualMachineInstanceTemplateSpec{Spec: api.NewMinimalVMI("test").Spec}}}
			old.Annotations = map[string]string{hibernation.StateAnnotation: hibernation.StateSaveIncomplete, hibernation.RequestAnnotation: hibernation.RequestDiscard, hibernation.AttemptAnnotation: "attempt"}
			current := old.DeepCopy()
			current.Spec.RunStrategy = pointer.P(v1.RunStrategyHalted)
			current.Annotations[hibernation.StateAnnotation] = hibernation.StateDiscarding
			if tc.alterDisk {
				current.Spec.Template.Spec.Domain.CPU = &v1.CPU{Cores: 8}
			}
			if tc.newAttempt {
				current.Annotations[hibernation.AttemptAnnotation] = "different-attempt"
			}
			oldRaw, _ := json.Marshal(old)
			newRaw, _ := json.Marshal(current)
			username := "editor"
			if tc.trusted {
				username = "system:serviceaccount:kubevirt:kubevirt-controller"
			}
			admitter := &VMsAdmitter{ClusterConfig: config, InstancetypeAdmitter: instancetypeWebhooks.NewAdmitterStub(), KubeVirtServiceAccounts: webhooks.KubeVirtServiceAccounts("kubevirt")}
			result := admitter.Admit(context.Background(), &admissionv1.AdmissionReview{Request: &admissionv1.AdmissionRequest{Resource: webhooks.VirtualMachineGroupVersionResource, Operation: admissionv1.Update, UserInfo: authv1.UserInfo{Username: username}, OldObject: runtime.RawExtension{Raw: oldRaw}, Object: runtime.RawExtension{Raw: newRaw}}})
			if result.Allowed != tc.allowed {
				t.Fatalf("allowed=%t want=%t result=%+v", result.Allowed, tc.allowed, result.Result)
			}
		})
	}
}
