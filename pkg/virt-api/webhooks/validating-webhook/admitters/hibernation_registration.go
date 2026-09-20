// SPDX-License-Identifier: Apache-2.0
package admitters

import (
	"context"
	"fmt"
	"maps"
	"reflect"

	admissionv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
	"kubevirt.io/kubevirt/pkg/hibernation"
)

// The separate use permission lets cluster administrators delegate selection of
// a specific registration without permitting enrollment configuration changes.
func validateKeyRegistration(ctx context.Context, client kubecli.KubevirtClient, request *admissionv1.AdmissionRequest, old, current *v1.VirtualMachine, trusted bool) error {
	previous, name := old.Annotations[hibernation.KeyRegistrationAnnotation], current.Annotations[hibernation.KeyRegistrationAnnotation]
	if previous != name && hibernation.Active(old.Annotations) {
		return fmt.Errorf("key registration is immutable during an active attempt")
	}
	if previous != name && !trusted {
		target := name
		if target == "" {
			target = previous
		}
		extra := map[string]authv1.ExtraValue{}
		for k, v := range request.UserInfo.Extra {
			extra[k] = authv1.ExtraValue(v)
		}
		review, e := client.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authv1.SubjectAccessReview{Spec: authv1.SubjectAccessReviewSpec{User: request.UserInfo.Username, UID: request.UserInfo.UID, Groups: request.UserInfo.Groups, Extra: extra, ResourceAttributes: &authv1.ResourceAttributes{Group: "hibernation.kubevirt.io", Resource: "hibernationkeyregistrations", Name: target, Verb: "use"}}}, metav1.CreateOptions{})
		if e != nil {
			return e
		}
		if !review.Status.Allowed {
			return fmt.Errorf("administrator permission to use this key registration is required")
		}
	}
	if name == "" || (previous == name && reflect.DeepEqual(old.Spec, current.Spec)) {
		return nil
	}
	if current.Spec.Template == nil {
		return fmt.Errorf("remote hibernation requires a VM template")
	}
	registration, e := client.GeneratedKubeVirtClient().HibernationV1alpha1().HibernationKeyRegistrations().Get(ctx, name, metav1.GetOptions{})
	if e != nil {
		return e
	}
	if registration.DeletionTimestamp != nil {
		return fmt.Errorf("key registration is being deleted")
	}
	node, e := client.CoreV1().Nodes().Get(ctx, registration.Spec.NodeName, metav1.GetOptions{})
	if e != nil {
		return e
	}
	if string(node.UID) != registration.Spec.NodeUID {
		return fmt.Errorf("key registration refers to a replaced node")
	}
	hostname := current.Spec.Template.Spec.NodeSelector["kubernetes.io/hostname"]
	if hostname == "" || hostname != node.Labels["kubernetes.io/hostname"] {
		return fmt.Errorf("remote hibernation VM must select the registered node hostname")
	}
	return nil
}
func withoutKeyRegistration(annotations map[string]string) map[string]string {
	copy := maps.Clone(annotations)
	delete(copy, hibernation.KeyRegistrationAnnotation)
	return copy
}
