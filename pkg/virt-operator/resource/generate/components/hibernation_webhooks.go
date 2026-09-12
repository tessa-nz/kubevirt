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

package components

import (
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubevirt.io/kubevirt/pkg/hibernation"
)

const HibernationStateValidatePath = "/hibernation-state-validate"

func hibernationStateWebhook(namespace, name string, rules []admissionv1.RuleWithOperations, expression string, namespaceScoped bool) admissionv1.ValidatingWebhook {
	failure, sideEffects, path := admissionv1.Fail, admissionv1.SideEffectClassNone, HibernationStateValidatePath
	webhook := admissionv1.ValidatingWebhook{
		Name: name + ".kubevirt.io", AdmissionReviewVersions: []string{"v1"}, FailurePolicy: &failure, SideEffects: &sideEffects,
		TimeoutSeconds: &defaultTimeoutSeconds, Rules: rules,
		ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{Namespace: namespace, Name: VirtApiServiceName, Path: &path}},
	}
	if expression != "" {
		webhook.MatchConditions = []admissionv1.MatchCondition{{Name: "hibernation-storage-entry-point", Expression: expression}}
	}
	if namespaceScoped {
		webhook.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{hibernation.StateProtectionNamespaceLabel: "enabled"}}
	}
	return webhook
}

func hibernationPodWebhook(namespace string) admissionv1.ValidatingWebhook {
	return hibernationStateWebhook(namespace, "hibernation-state-pods", []admissionv1.RuleWithOperations{
		{Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update}, Rule: admissionv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods", "pods/ephemeralcontainers"}}},
		{Operations: []admissionv1.OperationType{admissionv1.Connect}, Rule: admissionv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods/exec", "pods/attach"}}},
	}, `request.operation == 'CONNECT' || request.subResource == 'ephemeralcontainers' || (object != null && has(object.spec.volumes) && object.spec.volumes.exists(v, has(v.persistentVolumeClaim)))`, true)
}

func hibernationPVCWebhook(namespace string) admissionv1.ValidatingWebhook {
	return hibernationStateWebhook(namespace, "hibernation-state-pvcs", []admissionv1.RuleWithOperations{
		{Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update, admissionv1.Delete}, Rule: admissionv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"persistentvolumeclaims"}}},
	}, `(object != null && ((has(object.metadata.annotations) && 'hibernation.kubevirt.io/vm-uid' in object.metadata.annotations) || has(object.spec.dataSource) || has(object.spec.dataSourceRef))) || (oldObject != null && has(oldObject.metadata.annotations) && 'hibernation.kubevirt.io/vm-uid' in oldObject.metadata.annotations)`, false)
}

func hibernationSnapshotWebhook(namespace string) admissionv1.ValidatingWebhook {
	return hibernationStateWebhook(namespace, "hibernation-state-snapshots", []admissionv1.RuleWithOperations{
		{Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update}, Rule: admissionv1.Rule{APIGroups: []string{"snapshot.storage.k8s.io"}, APIVersions: []string{"v1"}, Resources: []string{"volumesnapshots"}}},
	}, `object != null && has(object.spec.source.persistentVolumeClaimName)`, true)
}

func hibernationCopyWebhook(namespace string) admissionv1.ValidatingWebhook {
	return hibernationStateWebhook(namespace, "hibernation-state-copies", []admissionv1.RuleWithOperations{
		{Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update}, Rule: admissionv1.Rule{APIGroups: []string{"cdi.kubevirt.io"}, APIVersions: []string{"v1beta1"}, Resources: []string{"datavolumes", "datasources"}}},
		{Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update}, Rule: admissionv1.Rule{APIGroups: []string{"export.kubevirt.io"}, APIVersions: []string{"v1beta1", "v1alpha1"}, Resources: []string{"virtualmachineexports"}}},
	}, `request.resource.resource != 'datavolumes' || has(object.spec.sourceRef) || (has(object.spec.source) && (has(object.spec.source.pvc) || has(object.spec.source.snapshot)))`, false)
}
