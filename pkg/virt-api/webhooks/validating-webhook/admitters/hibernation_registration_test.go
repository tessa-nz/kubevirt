// SPDX-License-Identifier: Apache-2.0
package admitters

import (
	"context"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	v1 "kubevirt.io/api/core/v1"
	api "kubevirt.io/api/hibernation/v1alpha1"
	"kubevirt.io/client-go/kubecli"
	virtfake "kubevirt.io/client-go/kubevirt/fake"
	"kubevirt.io/kubevirt/pkg/hibernation"
	"testing"
)

func TestRegistrationAdmissionUsePermissionAndActiveBinding(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := kubecli.NewMockKubevirtClient(ctrl)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "node-uid", Labels: map[string]string{"kubernetes.io/hostname": "node"}}}
	kube := fake.NewSimpleClientset(node)
	allowed := false
	kube.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		review := action.(ktesting.CreateAction).GetObject().(*authv1.SubjectAccessReview)
		if review.Spec.ResourceAttributes.Verb != "use" || review.Spec.ResourceAttributes.Name != "registration" {
			t.Fatal("wrong authorization request")
		}
		return true, &authv1.SubjectAccessReview{Status: authv1.SubjectAccessReviewStatus{Allowed: allowed}}, nil
	})
	virt := virtfake.NewSimpleClientset(&api.HibernationKeyRegistration{ObjectMeta: metav1.ObjectMeta{Name: "registration", UID: "registration-uid"}, Spec: api.HibernationKeyRegistrationSpec{NodeName: "node", NodeUID: "node-uid"}})
	client.EXPECT().AuthorizationV1().Return(kube.AuthorizationV1()).AnyTimes()
	client.EXPECT().CoreV1().Return(kube.CoreV1()).AnyTimes()
	client.EXPECT().GeneratedKubeVirtClient().Return(virt).AnyTimes()
	old := &v1.VirtualMachine{}
	current := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{hibernation.KeyRegistrationAnnotation: "registration"}}, Spec: v1.VirtualMachineSpec{Template: &v1.VirtualMachineInstanceTemplateSpec{Spec: v1.VirtualMachineInstanceSpec{NodeSelector: map[string]string{"kubernetes.io/hostname": "node"}}}}}
	req := &admissionv1.AdmissionRequest{}
	ctx := context.Background()
	if e := validateKeyRegistration(ctx, client, req, old, current, false); e == nil {
		t.Fatal("VM editor could select registration")
	}
	allowed = true
	if e := validateKeyRegistration(ctx, client, req, old, current, false); e != nil {
		t.Fatal(e)
	}
	current.Spec.Template.Spec.NodeSelector["kubernetes.io/hostname"] = "other"
	if e := validateKeyRegistration(ctx, client, req, old, current, false); e == nil {
		t.Fatal("wrong node accepted")
	}
	old = current.DeepCopy()
	old.Annotations[hibernation.StateAnnotation] = hibernation.StateHibernated
	current = old.DeepCopy()
	delete(current.Annotations, hibernation.KeyRegistrationAnnotation)
	if e := validateKeyRegistration(ctx, client, req, old, current, true); e == nil {
		t.Fatal("trusted writer could change active provider")
	}
}
