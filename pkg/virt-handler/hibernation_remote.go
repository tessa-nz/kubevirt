// SPDX-License-Identifier: Apache-2.0
package virthandler

import (
	"context"
	"fmt"
	"time"

	v1 "kubevirt.io/api/core/v1"
	cmdv1 "kubevirt.io/kubevirt/pkg/handler-launcher-com/cmd/v1"
	"kubevirt.io/kubevirt/pkg/hibernation"
	"kubevirt.io/kubevirt/pkg/hibernation/keyservice"
	"kubevirt.io/kubevirt/pkg/hibernation/protection"
)

func (c *VirtualMachineController) hibernationStore(vmi *v1.VirtualMachineInstance) (hibernationKeyStore, *cmdv1.HibernationProtection, error) {
	name := vmi.Annotations[hibernation.KeyRegistrationAnnotation]
	if name == "" {
		if c.hibernationKeys == nil {
			return nil, nil, fmt.Errorf("node TPM hibernation key store is unavailable")
		}
		return c.hibernationKeys, &cmdv1.HibernationProtection{Provider: protection.Provider}, nil
	}
	if c.hibernationRegistrations == nil {
		return nil, nil, fmt.Errorf("remote registration controller is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, r, e := c.hibernationRegistrations.Client(ctx, name)
	if e != nil {
		return nil, nil, e
	}
	result := &cmdv1.HibernationProtection{Provider: protection.RemoteProvider, ProviderID: client.ProviderID, PrincipalID: client.PrincipalID, RegistrationUID: string(r.UID), ClusterID: client.Enrollment.ClusterID}
	for _, qualification := range r.Spec.KernelQualifications {
		if qualification.VMUID != vmi.Annotations[hibernation.VMUIDAnnotation] {
			continue
		}
		result.QualificationVMUID = qualification.VMUID
		result.QualificationNodeUID = r.Spec.NodeUID
		result.QualificationSourceKernel = qualification.SourceKernel
		result.QualificationTargetKernel = qualification.TargetKernel
		if !kernelQualificationFromProtection(result).Valid() {
			return nil, nil, fmt.Errorf("invalid kernel qualification")
		}
	}
	return &remoteHibernationStore{client: client, restoreVMIUID: string(vmi.UID), artifactDigest: vmi.Annotations[hibernation.ArtifactDigestAnnotation]}, result, nil
}

type remoteHibernationStore struct {
	client                        *keyservice.Client
	restoreVMIUID, artifactDigest string
}

func (r *remoteHibernationStore) operation(op string, a protection.Attempt) (*keyservice.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	req := keyservice.Request{Operation: op, VMUID: a.VMUID, AttemptID: a.ID}
	if op == "open" || op == "consume" || op == "finalize" {
		req.RestoreVMIUID = r.restoreVMIUID
		req.ArtifactDigest = r.artifactDigest
	}
	if op == "open" || op == "consume" || op == "finalize" {
		status, e := r.client.Operation(ctx, keyservice.Request{Operation: "status", VMUID: a.VMUID, AttemptID: a.ID})
		if e != nil {
			return nil, e
		}
		defer status.Close()
		req.KeyID = status.Key.ID
	}
	return r.client.Operation(ctx, req)
}
func (r *remoteHibernationStore) Create(a protection.Attempt) (protection.PublicKey, error) {
	out, e := r.operation("create", a)
	if e != nil {
		return protection.PublicKey{}, e
	}
	defer out.Close()
	return out.Key, nil
}
func (r *remoteHibernationStore) Open(a protection.Attempt) (*protection.PrivateKey, error) {
	out, e := r.operation("open", a)
	if e != nil {
		return nil, e
	}
	defer out.Close()
	return &protection.PrivateKey{PublicKey: out.Key, Identity: append([]byte(nil), out.PrivateIdentity...)}, nil
}
func (r *remoteHibernationStore) Consume(a protection.Attempt) (bool, error) {
	out, e := r.operation("consume", a)
	if e != nil {
		return false, e
	}
	defer out.Close()
	return out.Fresh, nil
}
func (r *remoteHibernationStore) erase(op string, a protection.Attempt) error {
	out, e := r.operation(op, a)
	if e != nil {
		return e
	}
	defer out.Close()
	if !out.Erased {
		return fmt.Errorf("provider did not confirm erasure")
	}
	return nil
}
func (r *remoteHibernationStore) Destroy(a protection.Attempt) error { return r.erase("finalize", a) }
func (r *remoteHibernationStore) Abandon(a protection.Attempt) error { return r.erase("abandon", a) }
func (r *remoteHibernationStore) Discard(a protection.Attempt) error { return r.erase("discard", a) }

// Validate the launcher receipt against the authority selected before saving.
// Remote format 3 must never inherit the interpretation of local format 2.
func validHibernationSaveProtection(m hibernation.Metadata, expected *cmdv1.HibernationProtection) bool {
	if expected == nil || !hibernation.SameKernelQualification(m.KernelQualification, kernelQualificationFromProtection(expected)) || expected.KeyID == "" || expected.Recipient == "" || m.ProtectionProvider != expected.Provider || m.ProtectionKeyID != expected.KeyID || m.ProtectionRecipient != expected.Recipient || m.StateSize <= 0 || m.PlaintextSize <= 0 {
		return false
	}
	switch expected.Provider {
	case protection.Provider:
		return m.FormatVersion == 2 && m.ProtectionProviderID == "" && m.ProtectionPrincipalID == "" && m.ProtectionRegistrationUID == "" && m.ProtectionClusterID == ""
	case protection.RemoteProvider:
		return m.FormatVersion == 3 && expected.ProviderID != "" && expected.PrincipalID != "" && expected.RegistrationUID != "" && expected.ClusterID != "" && m.ProtectionProviderID == expected.ProviderID && m.ProtectionPrincipalID == expected.PrincipalID && m.ProtectionRegistrationUID == expected.RegistrationUID && m.ProtectionClusterID == expected.ClusterID
	default:
		return false
	}
}

func kernelQualificationFromProtection(c *cmdv1.HibernationProtection) *hibernation.KernelQualification {
	if c == nil || (c.QualificationVMUID == "" && c.QualificationNodeUID == "" && c.QualificationSourceKernel == "" && c.QualificationTargetKernel == "") {
		return nil
	}
	return &hibernation.KernelQualification{VMUID: c.QualificationVMUID, NodeUID: c.QualificationNodeUID, SourceKernel: c.QualificationSourceKernel, TargetKernel: c.QualificationTargetKernel}
}
