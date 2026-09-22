// SPDX-License-Identifier: Apache-2.0
package components

import (
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// NewHibernationKeyRegistrationCrd exposes enrollment intent and observations,
// not approval or key material. The provider remains the authorization authority.
func NewHibernationKeyRegistrationCrd() (*extv1.CustomResourceDefinition, error) {
	str := func(max int64) extv1.JSONSchemaProps { return extv1.JSONSchemaProps{Type: "string", MaxLength: &max} }
	immutable := func(schema extv1.JSONSchemaProps) extv1.JSONSchemaProps {
		schema.XValidations = extv1.ValidationRules{{Rule: "self == oldSelf", Message: "identity is immutable; create a new registration"}}
		return schema
	}
	id := str(128)
	one := int64(1)
	id.MinLength = &one
	id.Pattern = `^[a-zA-Z0-9][a-zA-Z0-9-]*$`
	provider := str(76)
	provider.Pattern = `^tpm2-sha256-[0-9a-f]{64}$`
	endpoint := str(2048)
	endpoint.Pattern = `^https://[^/?#@]+$`
	ca := str(32768)
	ca.MinLength = &one
	ca.XValidations = extv1.ValidationRules{{Rule: "!self.contains('PRIVATE KEY')", Message: "only public CA certificates may be stored"}}
	node := str(253)
	node.MinLength = &one
	maxItems := int64(128)
	vm := extv1.JSONSchemaProps{Type: "object", Required: []string{"vmUID"}, Properties: map[string]extv1.JSONSchemaProps{"vmUID": id, "name": str(253), "namespace": str(63)}}
	requested := extv1.JSONSchemaProps{Type: "array", MaxItems: &maxItems, Items: &extv1.JSONSchemaPropsOrArray{Schema: &vm}}
	grant := extv1.JSONSchemaProps{Type: "object", Required: []string{"clusterID", "vmUID"}, Properties: map[string]extv1.JSONSchemaProps{"clusterID": id, "vmUID": id}}
	condition := extv1.JSONSchemaProps{Type: "object", Required: []string{"type", "status", "reason", "message", "lastTransitionTime"}, Properties: map[string]extv1.JSONSchemaProps{
		"type":               {Type: "string", Enum: []extv1.JSON{{Raw: []byte(`"PendingApproval"`)}, {Raw: []byte(`"Registered"`)}, {Raw: []byte(`"Ready"`)}, {Raw: []byte(`"Revoked"`)}, {Raw: []byte(`"Degraded"`)}}},
		"status":             {Type: "string", Enum: []extv1.JSON{{Raw: []byte(`"True"`)}, {Raw: []byte(`"False"`)}, {Raw: []byte(`"Unknown"`)}}},
		"observedGeneration": {Type: "integer", Format: "int64"}, "reason": str(1024), "message": str(32768), "lastTransitionTime": {Type: "string", Format: "date-time"}}}
	mapType := "map"
	maxConditions := int64(5)
	kernel := str(128)
	kernel.Pattern = `^[a-zA-Z0-9][a-zA-Z0-9._+-]*$`
	qualification := extv1.JSONSchemaProps{Type: "object", Required: []string{"vmUID", "sourceKernel", "targetKernel"}, Properties: map[string]extv1.JSONSchemaProps{"vmUID": id, "sourceKernel": kernel, "targetKernel": kernel}, XValidations: extv1.ValidationRules{{Rule: "self.sourceKernel != self.targetKernel", Message: "qualification requires different kernels"}}}
	maxQualifications := int64(32)
	qualifications := extv1.JSONSchemaProps{Type: "array", MaxItems: &maxQualifications, XListType: &mapType, XListMapKeys: []string{"vmUID"}, Items: &extv1.JSONSchemaPropsOrArray{Schema: &qualification}}
	spec := extv1.JSONSchemaProps{Type: "object", Required: []string{"endpoint", "serverCA", "providerID", "nodeName", "nodeUID"}, Properties: map[string]extv1.JSONSchemaProps{
		"endpoint": endpoint, "serverCA": ca, "providerID": immutable(provider), "nodeName": immutable(node), "nodeUID": immutable(id), "requestedVMs": requested, "kernelQualifications": qualifications}}
	status := extv1.JSONSchemaProps{Type: "object", Properties: map[string]extv1.JSONSchemaProps{
		"observedGeneration": {Type: "integer", Format: "int64"}, "clusterID": id, "nodeUID": id, "clientFingerprint": str(64), "enrollmentRequestID": str(64), "certificateExpiry": {Type: "string", Format: "date-time"},
		"effectiveGrants": {Type: "array", MaxItems: &maxItems, Items: &extv1.JSONSchemaPropsOrArray{Schema: &grant}},
		"conditions":      {Type: "array", MaxItems: &maxConditions, XListType: &mapType, XListMapKeys: []string{"type"}, Items: &extv1.JSONSchemaPropsOrArray{Schema: &condition}}}}
	crd := newBlankCrd()
	crd.Name = "hibernationkeyregistrations.hibernation.kubevirt.io"
	crd.Spec = extv1.CustomResourceDefinitionSpec{Group: "hibernation.kubevirt.io", Scope: extv1.ClusterScoped, Names: extv1.CustomResourceDefinitionNames{Plural: "hibernationkeyregistrations", Singular: "hibernationkeyregistration", Kind: "HibernationKeyRegistration", ListKind: "HibernationKeyRegistrationList", ShortNames: []string{"hkr"}}, Versions: []extv1.CustomResourceDefinitionVersion{{Name: "v1alpha1", Served: true, Storage: true, Subresources: &extv1.CustomResourceSubresources{Status: &extv1.CustomResourceSubresourceStatus{}}, Schema: &extv1.CustomResourceValidation{OpenAPIV3Schema: &extv1.JSONSchemaProps{Type: "object", Required: []string{"spec"}, Properties: map[string]extv1.JSONSchemaProps{"apiVersion": {Type: "string"}, "kind": {Type: "string"}, "metadata": {Type: "object"}, "spec": spec, "status": status}}}}}}
	return crd, nil
}
