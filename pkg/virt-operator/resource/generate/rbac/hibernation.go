// SPDX-License-Identifier: Apache-2.0
package rbac

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	virtv1 "kubevirt.io/api/core/v1"
)

// Configuration delegation never grants status write or service-side approval.
// No binding is installed automatically.
func newHibernationRegistrationAdminRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{TypeMeta: metav1.TypeMeta{APIVersion: VersionNamev1, Kind: "ClusterRole"}, ObjectMeta: metav1.ObjectMeta{Name: "hibernation.kubevirt.io:registration-admin", Labels: map[string]string{virtv1.AppLabel: ""}}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{"hibernation.kubevirt.io"}, Resources: []string{"hibernationkeyregistrations"}, Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete", "use"}}}}
}
