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

package virthandler

import (
	"errors"
	"fmt"

	k8sv1 "k8s.io/api/core/v1"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/kubevirt/pkg/controller"
	cmdv1 "kubevirt.io/kubevirt/pkg/handler-launcher-com/cmd/v1"
	"kubevirt.io/kubevirt/pkg/hibernation"
	"kubevirt.io/kubevirt/pkg/hibernation/protection"
	cmdclient "kubevirt.io/kubevirt/pkg/virt-handler/cmd-client"
	"kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/api"
)

// hibernationKeyStore is implemented by the node TPM. Create never exports a
// private key; Open is unavailable after Consume. Destroy requires consumption,
// while Abandon is reserved for a proven save rejection with the guest live.
type hibernationKeyStore interface {
	Create(protection.Attempt) (protection.PublicKey, error)
	Open(protection.Attempt) (*protection.PrivateKey, error)
	Consume(protection.Attempt) (bool, error)
	Destroy(protection.Attempt) error
	Abandon(protection.Attempt) error
}

func hibernationAttempt(vmi *v1.VirtualMachineInstance) protection.Attempt {
	return protection.Attempt{VMUID: vmi.Annotations[hibernation.VMUIDAnnotation], ID: vmi.Annotations[hibernation.AttemptAnnotation]}
}

func (c *VirtualMachineController) prepareHibernationProtection(client cmdclient.LauncherClient, vmi *v1.VirtualMachineInstance, request string) (*cmdv1.HibernationProtection, error) {
	if c.hibernationKeys == nil {
		return nil, fmt.Errorf("node TPM hibernation key store is unavailable")
	}
	attempt := hibernationAttempt(vmi)
	result := &cmdv1.HibernationProtection{Provider: protection.Provider}
	switch request {
	case hibernation.RequestSave:
		key, err := c.hibernationKeys.Create(attempt)
		if err != nil {
			return nil, err
		}
		result.KeyID, result.Recipient = key.ID, key.Recipient
	case hibernation.RequestRestorePaused:
		key, err := c.hibernationKeys.Open(attempt)
		if errors.Is(err, protection.ErrConsumed) {
			return nil, hibernation.Reject(hibernation.StateRestoreCommitLost, err)
		}
		if err != nil {
			return nil, err
		}
		result.KeyID, result.Recipient, result.PrivateIdentity = key.ID, key.Recipient, key.Identity
	case hibernation.RequestCommitUnpause:
		domain, exists, err := client.GetDomain()
		if err != nil {
			return nil, err
		}
		if !exists || domain == nil || (domain.Status.Status != api.Paused && domain.Status.Status != api.Running) {
			return nil, fmt.Errorf("consumption requires the restored paused or already committed running domain")
		}
		if hibernation.LabEnabled && vmi.Annotations[hibernation.LabFailBeforeConsumeAnnotation] == attempt.ID && attempt.ID != "" {
			return nil, hibernation.Reject(hibernation.StateRestoreCommitLost, fmt.Errorf("injected failure before TPM consumption"))
		}
		fresh, err := c.hibernationKeys.Consume(attempt)
		if err != nil {
			return nil, err
		}
		result.ConsumptionCommitted, result.FreshConsumption = true, fresh
	case hibernation.RequestErase:
		if !vmi.IsRunning() || !controller.NewVirtualMachineInstanceConditionManager().HasConditionWithStatus(vmi, v1.VirtualMachineInstanceReady, k8sv1.ConditionTrue) || vmi.Annotations[hibernation.StateAnnotation] != hibernation.StateRunningAwaitingVerification {
			return nil, fmt.Errorf("TPM erasure requires the current running, Ready attempt awaiting verification")
		}
		domain, exists, err := client.GetDomain()
		if err != nil {
			return nil, err
		}
		if !exists || domain == nil || domain.Status.Status != api.Running {
			return nil, fmt.Errorf("TPM erasure requires a running domain")
		}
		if err := c.hibernationKeys.Destroy(attempt); err != nil {
			return nil, err
		}
		result.KeyErased = true
	default:
		return nil, fmt.Errorf("unknown hibernation protection operation")
	}
	return result, nil
}
