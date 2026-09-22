// SPDX-License-Identifier: Apache-2.0
package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// HibernationKeyRegistration requests enrollment; only the provider can approve it.
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster,shortName=hkr
// +kubebuilder:subresource:status
type HibernationKeyRegistration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              HibernationKeyRegistrationSpec   `json:"spec"`
	Status            HibernationKeyRegistrationStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type HibernationKeyRegistrationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HibernationKeyRegistration `json:"items"`
}
type HibernationKeyRegistrationSpec struct {
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https://[^/?#@]+$`
	Endpoint string `json:"endpoint"`
	// ServerCA contains only public PEM certificates.
	// +kubebuilder:validation:XValidation:rule="!self.contains('PRIVATE KEY')",message="only public CA certificates may be stored"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=32768
	ServerCA string `json:"serverCA"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="provider identity is immutable"
	// +kubebuilder:validation:Pattern=`^tpm2-sha256-[0-9a-f]{64}$`
	ProviderID string `json:"providerID"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="node name is immutable"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	NodeName string `json:"nodeName"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="node UID is immutable"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	NodeUID string `json:"nodeUID"`
	// RequestedVMs are hints for operators, never grants.
	// +kubebuilder:validation:MaxItems=128
	// +listType=map
	// +listMapKey=vmUID
	RequestedVMs []RequestedVM `json:"requestedVMs,omitempty"`
	// KernelQualifications authorize controlled experiments for exact VM UIDs.
	// They do not grant key access or certify a transition for production.
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=vmUID
	KernelQualifications []KernelQualification `json:"kernelQualifications,omitempty"`
}
type RequestedVM struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	VMUID string `json:"vmUID"`
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace,omitempty"`
}
type HibernationKeyGrant struct {
	ClusterID string `json:"clusterID"`
	VMUID     string `json:"vmUID"`
}
type HibernationKeyRegistrationStatus struct {
	ObservedGeneration  int64                 `json:"observedGeneration,omitempty"`
	ClusterID           string                `json:"clusterID,omitempty"`
	NodeUID             string                `json:"nodeUID,omitempty"`
	ClientFingerprint   string                `json:"clientFingerprint,omitempty"`
	EnrollmentRequestID string                `json:"enrollmentRequestID,omitempty"`
	EffectiveGrants     []HibernationKeyGrant `json:"effectiveGrants,omitempty"`
	CertificateExpiry   *metav1.Time          `json:"certificateExpiry,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// KernelQualification is an exact, directional kernel experiment selected by an administrator.
// +kubebuilder:validation:XValidation:rule="self.sourceKernel != self.targetKernel",message="qualification requires different kernels"
type KernelQualification struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	VMUID string `json:"vmUID"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9][a-zA-Z0-9._+-]*$`
	// +kubebuilder:validation:MaxLength=128
	SourceKernel string `json:"sourceKernel"`
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9][a-zA-Z0-9._+-]*$`
	// +kubebuilder:validation:MaxLength=128
	TargetKernel string `json:"targetKernel"`
}
