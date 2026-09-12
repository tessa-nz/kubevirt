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
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	celplugin "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	"k8s.io/apiserver/pkg/cel/environment"
	"kubevirt.io/kubevirt/pkg/hibernation"
)

func TestHibernationWebhookFiltersAndBootstrapBoundary(t *testing.T) {
	compiler := celplugin.NewCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion(), true))
	webhooks := []admissionv1.ValidatingWebhook{hibernationPodWebhook("kubevirt"), hibernationPVCWebhook("kubevirt"), hibernationSnapshotWebhook("kubevirt"), hibernationCopyWebhook("kubevirt")}
	for _, webhook := range webhooks {
		if webhook.FailurePolicy == nil || *webhook.FailurePolicy != admissionv1.Fail {
			t.Fatal("state protection must fail closed")
		}
		if webhook.ClientConfig.Service == nil || *webhook.ClientConfig.Service.Path != HibernationStateValidatePath {
			t.Fatal("state protection is not routed to its validator")
		}
		condition := matchconditions.MatchCondition(webhook.MatchConditions[0])
		compiled := compiler.CompileCELExpression(&condition, celplugin.OptionalVariableDeclarations{}, environment.NewExpressions)
		if compiled.Error != nil {
			t.Fatalf("%s: %v", webhook.Name, compiled.Error)
		}
		if webhook.Name == "hibernation-state-pods.kubevirt.io" {
			if webhook.NamespaceSelector.MatchLabels[hibernation.StateProtectionNamespaceLabel] != "enabled" {
				t.Fatal("pod policy is not namespace-scoped")
			}
			for _, scenario := range []struct {
				name            string
				request, object any
				want            bool
			}{
				{"bootstrap api pod", map[string]any{"operation": "CREATE", "subResource": ""}, map[string]any{"spec": map[string]any{"containers": []any{}}}, false},
				{"PVC pod", map[string]any{"operation": "CREATE", "subResource": ""}, map[string]any{"spec": map[string]any{"volumes": []any{map[string]any{"persistentVolumeClaim": map[string]any{"claimName": "state"}}}}}, true},
				{"exec", map[string]any{"operation": "CONNECT", "subResource": "exec"}, nil, true},
			} {
				result, _, err := compiled.Program.Eval(map[string]any{"request": scenario.request, "object": scenario.object, "oldObject": nil})
				if err != nil || result.Value() != scenario.want {
					t.Fatalf("%s: result=%v err=%v", scenario.name, result, err)
				}
			}
		}
		if webhook.Name == "hibernation-state-pvcs.kubevirt.io" {
			for _, scenario := range []struct {
				name        string
				object, old any
				want        bool
			}{
				{"ordinary PVC", map[string]any{"metadata": map[string]any{}, "spec": map[string]any{}}, nil, false},
				{"deleted reserved PVC", nil, map[string]any{"metadata": map[string]any{"annotations": map[string]any{hibernation.VMUIDAnnotation: "vm-uid"}}}, true},
				{"stripped reservation", map[string]any{"metadata": map[string]any{}, "spec": map[string]any{}}, map[string]any{"metadata": map[string]any{"annotations": map[string]any{hibernation.VMUIDAnnotation: "vm-uid"}}}, true},
			} {
				result, _, err := compiled.Program.Eval(map[string]any{"object": scenario.object, "oldObject": scenario.old})
				if err != nil || result.Value() != scenario.want {
					t.Fatalf("%s: result=%v err=%v", scenario.name, result, err)
				}
			}
		}
	}
}
