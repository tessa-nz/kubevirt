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

package rbac

import (
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	v1 "kubevirt.io/api/core/v1"
)

func TestHibernationRequiresExplicitOperationRBAC(t *testing.T) {
	for _, operation := range []string{"hibernate", "resume", "finalizehibernation", "discardhibernation"} {
		for _, tc := range []struct {
			role    *rbacv1.ClusterRole
			allowed bool
		}{{newAdminClusterRole(), true}, {newEditClusterRole(), false}, {newViewClusterRole(), false}} {
			allowed := false
			for _, rule := range tc.role.Rules {
				if slices.Contains(rule.APIGroups, v1.SubresourceGroupName) && slices.Contains(rule.Resources, "virtualmachines/"+operation) && slices.Contains(rule.Verbs, "update") {
					allowed = true
				}
			}
			if allowed != tc.allowed {
				t.Fatalf("%s operation %s allowed=%v, want %v", tc.role.Name, operation, allowed, tc.allowed)
			}
		}
	}
}

func TestHibernationRegistrationConfigurationAndStatusAreSeparate(t *testing.T) {
	admin, handler := newHibernationRegistrationAdminRole(), newHandlerClusterRole()
	permits := func(role *rbacv1.ClusterRole, resource, verb string) bool {
		for _, r := range role.Rules {
			if slices.Contains(r.APIGroups, "hibernation.kubevirt.io") && slices.Contains(r.Resources, resource) && slices.Contains(r.Verbs, verb) {
				return true
			}
		}
		return false
	}
	if !permits(admin, "hibernationkeyregistrations", "update") || permits(admin, "hibernationkeyregistrations/status", "update") {
		t.Fatal("configuration role has wrong status boundary")
	}
	if permits(handler, "hibernationkeyregistrations", "update") || !permits(handler, "hibernationkeyregistrations/status", "update") {
		t.Fatal("handler can modify enrollment configuration or cannot report status")
	}
	if permits(newEditClusterRole(), "hibernationkeyregistrations", "use") {
		t.Fatal("ordinary VM edit grants provider selection")
	}
}
