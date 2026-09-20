// SPDX-License-Identifier: Apache-2.0
package components

import (
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"testing"
)

func TestHibernationRegistrationCRDValidation(t *testing.T) {
	crd, e := NewHibernationKeyRegistrationCrd()
	if e != nil {
		t.Fatal(e)
	}
	version := crd.Spec.Versions[0]
	if version.Subresources.Status == nil || crd.Spec.Scope != extv1.ClusterScoped {
		t.Fatal("registration status or scope incorrect")
	}
	for _, field := range []string{"providerID", "nodeName", "nodeUID"} {
		if len(version.Schema.OpenAPIV3Schema.Properties["spec"].Properties[field].XValidations) != 1 {
			t.Fatalf("mutable identity: %s", field)
		}
	}
}
