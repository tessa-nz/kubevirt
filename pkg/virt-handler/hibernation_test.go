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
	"context"
	"encoding/json"
	"errors"
	"testing"

	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "kubevirt.io/api/core/v1"

	k8sv1 "k8s.io/api/core/v1"
	cmdv1 "kubevirt.io/kubevirt/pkg/handler-launcher-com/cmd/v1"
	"kubevirt.io/kubevirt/pkg/hibernation"
	"kubevirt.io/kubevirt/pkg/hibernation/protection"
	cmdclient "kubevirt.io/kubevirt/pkg/virt-handler/cmd-client"
	"kubevirt.io/kubevirt/pkg/virt-launcher/virtwrap/api"
)

func TestSyncHibernationSaveIsDispatchedAndPublished(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := cmdclient.NewMockLauncherClient(ctrl)
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		hibernation.RequestAnnotation: hibernation.RequestSave,
		hibernation.AttemptAnnotation: "same-attempt",
		hibernation.VMUIDAnnotation:   "vm-uid",
	}}}
	client.EXPECT().HibernateVirtualMachine(vmi, cmdv1.HibernationAction_HIBERNATION_ACTION_SAVE, hibernation.StateMountPath+"/state.save", false, gomock.Any()).
		Return(hibernationResponse(t, vmi, hibernation.StateHibernated), nil)
	controller := &VirtualMachineController{hibernationKeys: &fakeHibernationKeys{}}
	if err := controller.syncHibernation(client, vmi, hibernation.RequestSave); err != nil {
		t.Fatal(err)
	}
	if vmi.Annotations[hibernation.StateAnnotation] != hibernation.StateHibernated {
		t.Fatalf("unexpected state %q", vmi.Annotations[hibernation.StateAnnotation])
	}
	if _, exists := vmi.Annotations[hibernation.RequestAnnotation]; exists {
		t.Fatal("completed request must be cleared")
	}
}

func TestSyncHibernationCommitFailureIsTerminal(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := cmdclient.NewMockLauncherClient(ctrl)
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
	client.EXPECT().GetDomain().Return(&api.Domain{Status: api.DomainStatus{Status: api.Paused}}, true, nil)
	client.EXPECT().HibernateVirtualMachine(gomock.Any(), cmdv1.HibernationAction_HIBERNATION_ACTION_COMMIT_UNPAUSE, gomock.Any(), false, gomock.Any()).
		Return(&cmdv1.HibernationResponse{Response: &cmdv1.Response{Success: false}, Phase: hibernation.StateRestoreCommitLost}, errors.New("lost after consumed marker"))
	controller := &VirtualMachineController{hibernationKeys: &fakeHibernationKeys{}}
	if err := controller.syncHibernation(client, vmi, hibernation.RequestCommitUnpause); err == nil {
		t.Fatal("expected commit failure")
	}
	if vmi.Annotations[hibernation.StateAnnotation] != hibernation.StateRestoreCommitLost {
		t.Fatalf("unexpected terminal state %q", vmi.Annotations[hibernation.StateAnnotation])
	}
}

func TestSyncHibernationRetriesUnknownOutcomesWithoutTerminalizing(t *testing.T) {
	for _, failure := range []error{context.DeadlineExceeded, status.Error(codes.Unavailable, "launcher connection lost"), errors.New("libvirt lookup timed out")} {
		for _, operation := range []struct {
			request, phase, completed string
			action                    cmdv1.HibernationAction
		}{
			{hibernation.RequestSave, hibernation.StateSaving, hibernation.StateHibernated, cmdv1.HibernationAction_HIBERNATION_ACTION_SAVE},
			{hibernation.RequestRestorePaused, hibernation.StateRestoring, hibernation.StateRestoredPaused, cmdv1.HibernationAction_HIBERNATION_ACTION_RESTORE_PAUSED},
			{hibernation.RequestCommitUnpause, hibernation.StateRestoreCommittedPaused, hibernation.StateRunningAwaitingVerification, cmdv1.HibernationAction_HIBERNATION_ACTION_COMMIT_UNPAUSE},
			{hibernation.RequestErase, hibernation.StateRunningAwaitingVerification, hibernation.StateRunning, cmdv1.HibernationAction_HIBERNATION_ACTION_ERASE},
		} {
			t.Run(operation.request+"/"+failure.Error(), func(t *testing.T) {
				ctrl := gomock.NewController(t)
				client := cmdclient.NewMockLauncherClient(ctrl)
				vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
					hibernation.RequestAnnotation: operation.request,
					hibernation.StateAnnotation:   operation.phase,
					hibernation.AttemptAnnotation: "same-attempt",
					hibernation.VMUIDAnnotation:   "vm-uid",
				}}}
				if operation.request == hibernation.RequestCommitUnpause || operation.request == hibernation.RequestErase {
					domainStatus := api.Paused
					if operation.request == hibernation.RequestErase {
						domainStatus = api.Running
						vmi.Status.Phase = v1.Running
						vmi.Status.Conditions = []v1.VirtualMachineInstanceCondition{{Type: v1.VirtualMachineInstanceReady, Status: k8sv1.ConditionTrue}}
					}
					client.EXPECT().GetDomain().Return(&api.Domain{Status: api.DomainStatus{Status: domainStatus}}, true, nil).Times(2)
				}
				gomock.InOrder(
					client.EXPECT().HibernateVirtualMachine(vmi, operation.action, gomock.Any(), false, gomock.Any()).Return(nil, failure),
					client.EXPECT().HibernateVirtualMachine(vmi, operation.action, gomock.Any(), false, gomock.Any()).Return(hibernationResponse(t, vmi, operation.completed), nil),
				)
				controller := &VirtualMachineController{hibernationKeys: &fakeHibernationKeys{}}
				if err := controller.syncHibernation(client, vmi, operation.request); err == nil {
					t.Fatal("unknown outcome must be retried")
				}
				if vmi.Annotations[hibernation.StateAnnotation] != operation.phase || vmi.Annotations[hibernation.RequestAnnotation] != operation.request || vmi.Annotations[hibernation.AttemptAnnotation] != "same-attempt" {
					t.Fatal("transport failure changed the lifecycle or attempt")
				}
				if err := controller.syncHibernation(client, vmi, operation.request); err != nil {
					t.Fatal(err)
				}
				if vmi.Annotations[hibernation.StateAnnotation] != operation.completed {
					t.Fatalf("retry did not recover: %q", vmi.Annotations[hibernation.StateAnnotation])
				}
			})
		}
	}
}

func hibernationResponse(t *testing.T, vmi *v1.VirtualMachineInstance, phase string) *cmdv1.HibernationResponse {
	t.Helper()
	metadata, err := json.Marshal(hibernation.Metadata{
		Completed: true, FormatVersion: 2, ProtectionProvider: protection.Provider, ProtectionKeyID: "key-id", ProtectionRecipient: "recipient", StateSize: 42, PlaintextSize: 21,
		AttemptID: vmi.Annotations[hibernation.AttemptAnnotation],
		VMUID:     vmi.Annotations[hibernation.VMUIDAnnotation],
	})
	if err != nil {
		t.Fatal(err)
	}
	return &cmdv1.HibernationResponse{Response: &cmdv1.Response{Success: true}, Phase: phase, MetadataJson: metadata}
}

func TestSyncHibernationPublishesPausedRestoreBeforeCommitAndUnpause(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := cmdclient.NewMockLauncherClient(ctrl)
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
	client.EXPECT().HibernateVirtualMachine(vmi, cmdv1.HibernationAction_HIBERNATION_ACTION_RESTORE_PAUSED, hibernation.StateMountPath+"/state.save", false, gomock.Any()).
		Return(&cmdv1.HibernationResponse{Phase: hibernation.StateRestoredPaused}, nil)
	controller := &VirtualMachineController{hibernationKeys: &fakeHibernationKeys{}}
	if err := controller.syncHibernation(client, vmi, hibernation.RequestRestorePaused); err != nil {
		t.Fatal(err)
	}
	if vmi.Annotations[hibernation.StateAnnotation] != hibernation.StateRestoredPaused {
		t.Fatalf("unexpected state %q", vmi.Annotations[hibernation.StateAnnotation])
	}
}

func TestSyncHibernationCommitsAndUnpausesOnlyAfterSeparateDispatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := cmdclient.NewMockLauncherClient(ctrl)
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
	client.EXPECT().GetDomain().Return(&api.Domain{Status: api.DomainStatus{Status: api.Paused}}, true, nil)
	client.EXPECT().HibernateVirtualMachine(vmi, cmdv1.HibernationAction_HIBERNATION_ACTION_COMMIT_UNPAUSE, hibernation.StateMountPath+"/state.save", false, gomock.Any()).
		Return(&cmdv1.HibernationResponse{Phase: hibernation.StateRunningAwaitingVerification}, nil)
	controller := &VirtualMachineController{hibernationKeys: &fakeHibernationKeys{}}
	if err := controller.syncHibernation(client, vmi, hibernation.RequestCommitUnpause); err != nil {
		t.Fatal(err)
	}
	if vmi.Annotations[hibernation.StateAnnotation] != hibernation.StateRunningAwaitingVerification {
		t.Fatalf("unexpected state %q", vmi.Annotations[hibernation.StateAnnotation])
	}
}

func TestHibernationRequestBypassesPhaseOptimization(t *testing.T) {
	vmi := &v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			hibernation.RequestAnnotation: hibernation.RequestCommitUnpause,
		}},
		Status: v1.VirtualMachineInstanceStatus{Phase: v1.Scheduled},
	}
	if !shouldProcessVMIUpdate(vmi, v1.Running) {
		t.Fatal("commit-unpause must be processed while the restored VMI is still Scheduled")
	}
	delete(vmi.Annotations, hibernation.RequestAnnotation)
	if shouldProcessVMIUpdate(vmi, v1.Running) {
		t.Fatal("ordinary updates must retain the phase optimization")
	}
}

func TestHibernationRequestBypassesRestoredDomainMigrationGuard(t *testing.T) {
	vmi := &v1.VirtualMachineInstance{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
			hibernation.RequestAnnotation: hibernation.RequestCommitUnpause,
		}},
	}
	domain := &api.Domain{Status: api.DomainStatus{
		Status: api.Paused,
		Reason: api.ReasonPausedMigration,
	}}
	if shouldIgnoreInProgressMigration(vmi, domain) {
		t.Fatal("commit-unpause must not be mistaken for a live migration")
	}
	delete(vmi.Annotations, hibernation.RequestAnnotation)
	if !shouldIgnoreInProgressMigration(vmi, domain) {
		t.Fatal("ordinary paused migration must retain the migration guard")
	}
}

func TestSyncHibernationDoesNotRunOrdinarySyncBetweenRequests(t *testing.T) {
	for _, state := range []string{hibernation.StateSaving, hibernation.StateHibernated, hibernation.StateRestoredPaused, hibernation.StateRestoreCommittedPaused, hibernation.StateRunningAwaitingVerification} {
		t.Run(state, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			client := cmdclient.NewMockLauncherClient(ctrl)
			controller := &VirtualMachineController{hibernationKeys: &fakeHibernationKeys{}}
			vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{hibernation.StateAnnotation: state}}}
			// No regular Sync RPC or ordinary-start configuration lookup is permitted.
			if err := controller.syncVirtualMachine(client, vmi, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// The fake exercises controller ordering without accessing a host TPM.
type fakeHibernationKeys struct {
	consumed             bool
	failure              error
	destroyed, abandoned bool
}

func (*fakeHibernationKeys) Create(protection.Attempt) (protection.PublicKey, error) {
	return protection.PublicKey{ID: "key-id", Recipient: "recipient"}, nil
}
func (f *fakeHibernationKeys) Open(protection.Attempt) (*protection.PrivateKey, error) {
	if f.consumed {
		return nil, protection.ErrConsumed
	}
	return &protection.PrivateKey{PublicKey: protection.PublicKey{ID: "key-id", Recipient: "recipient"}, Identity: []byte("test-only-private-key")}, f.failure
}
func (f *fakeHibernationKeys) Consume(protection.Attempt) (bool, error) {
	fresh := !f.consumed
	f.consumed = true
	return fresh, f.failure
}
func (f *fakeHibernationKeys) Destroy(protection.Attempt) error {
	if f.failure == nil {
		f.destroyed = true
	}
	return f.failure
}
func (f *fakeHibernationKeys) Discard(protection.Attempt) error {
	if f.failure == nil {
		f.destroyed = true
	}
	return f.failure
}
func (f *fakeHibernationKeys) Abandon(protection.Attempt) error {
	if f.failure == nil {
		f.abandoned = true
	}
	return f.failure
}

func TestTPMProtectionPrecedesLauncherSideEffects(t *testing.T) {
	for _, request := range []string{hibernation.RequestCommitUnpause, hibernation.RequestErase} {
		t.Run(request, func(t *testing.T) {
			for _, fail := range []bool{false, true} {
				ctrl := gomock.NewController(t)
				client := cmdclient.NewMockLauncherClient(ctrl)
				keys := &fakeHibernationKeys{}
				if fail {
					keys.failure = errors.New("lost TPM response")
				}
				vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
					hibernation.AttemptAnnotation: "attempt", hibernation.VMUIDAnnotation: "vm", hibernation.RequestAnnotation: request,
					hibernation.StateAnnotation: hibernation.StateRunningAwaitingVerification,
				}}, Status: v1.VirtualMachineInstanceStatus{Phase: v1.Running, Conditions: []v1.VirtualMachineInstanceCondition{{Type: v1.VirtualMachineInstanceReady, Status: k8sv1.ConditionTrue}}}}
				client.EXPECT().GetDomain().Return(&api.Domain{Status: api.DomainStatus{Status: api.Running}}, true, nil)
				if !fail {
					client.EXPECT().HibernateVirtualMachine(vmi, gomock.Any(), gomock.Any(), false, gomock.Any()).DoAndReturn(func(_ *v1.VirtualMachineInstance, _ cmdv1.HibernationAction, _ string, _ bool, context *cmdv1.HibernationProtection) (*cmdv1.HibernationResponse, error) {
						if request == hibernation.RequestCommitUnpause && (!keys.consumed || !context.ConsumptionCommitted || !context.FreshConsumption) {
							t.Fatal("launcher reached before durable consumption")
						}
						if request == hibernation.RequestErase && (!keys.destroyed || !context.KeyErased) {
							t.Fatal("launcher reached before verified key destruction")
						}
						return &cmdv1.HibernationResponse{}, nil
					})
				}
				c := &VirtualMachineController{hibernationKeys: keys}
				err := c.syncHibernation(client, vmi, request)
				if (err != nil) != fail {
					t.Fatalf("unexpected result: %v", err)
				}
				if fail && vmi.Annotations[hibernation.RequestAnnotation] != request {
					t.Fatal("uncertain TPM result must remain retryable")
				}
			}
		})
	}
}

func TestRestorePrivateKeyIsClearedAfterFailedRPC(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := cmdclient.NewMockLauncherClient(ctrl)
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{hibernation.AttemptAnnotation: "attempt", hibernation.VMUIDAnnotation: "vm"}}}
	var keyBytes []byte
	client.EXPECT().HibernateVirtualMachine(vmi, gomock.Any(), gomock.Any(), false, gomock.Any()).DoAndReturn(func(_ *v1.VirtualMachineInstance, _ cmdv1.HibernationAction, _ string, _ bool, context *cmdv1.HibernationProtection) (*cmdv1.HibernationResponse, error) {
		keyBytes = context.PrivateIdentity
		if len(keyBytes) == 0 {
			t.Fatal("missing restore identity")
		}
		return nil, errors.New("transport lost")
	})
	c := &VirtualMachineController{hibernationKeys: &fakeHibernationKeys{}}
	if c.syncHibernation(client, vmi, hibernation.RequestRestorePaused) == nil {
		t.Fatal("expected RPC error")
	}
	for _, b := range keyBytes {
		if b != 0 {
			t.Fatal("private identity survived RPC completion")
		}
	}
}

func TestConsumedArtifactNeverReachesRestoreRPC(t *testing.T) {
	client := cmdclient.NewMockLauncherClient(gomock.NewController(t))
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
	c := &VirtualMachineController{hibernationKeys: &fakeHibernationKeys{consumed: true}}
	if c.syncHibernation(client, vmi, hibernation.RequestRestorePaused) == nil || vmi.Annotations[hibernation.StateAnnotation] != hibernation.StateRestoreCommitLost {
		t.Fatal("consumed artifact was not terminally rejected")
	}
}

func TestLabFailureBeforeTPMConsumption(t *testing.T) {
	if !hibernation.LabEnabled {
		t.Skip("lab build only")
	}
	client := cmdclient.NewMockLauncherClient(gomock.NewController(t))
	client.EXPECT().GetDomain().Return(&api.Domain{Status: api.DomainStatus{Status: api.Paused}}, true, nil)
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{hibernation.AttemptAnnotation: "attempt", hibernation.VMUIDAnnotation: "vm", hibernation.LabFailBeforeConsumeAnnotation: "attempt"}}}
	keys := &fakeHibernationKeys{}
	c := &VirtualMachineController{hibernationKeys: keys}
	if c.syncHibernation(client, vmi, hibernation.RequestCommitUnpause) == nil || keys.consumed {
		t.Fatal("before-consume injection changed TPM state")
	}
}

func TestDiscardRequiresSourceNodeAndAbsentDomain(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		domain       bool
		want         bool
	}{
		{"valid", "source-node", false, true},
		{"wrong node", "other-node", false, false},
		{"missing source", "", false, false},
		{"existing domain", "source-node", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			client := cmdclient.NewMockLauncherClient(ctrl)
			vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
				hibernation.StateAnnotation: hibernation.StateDiscarding, hibernation.RequestAnnotation: hibernation.RequestDiscard,
				hibernation.SourceNodeAnnotation: tc.source, hibernation.VMUIDAnnotation: "vm-uid", hibernation.AttemptAnnotation: "attempt",
			}}}
			keys := &fakeHibernationKeys{}
			controller := &VirtualMachineController{BaseController: &BaseController{host: "source-node"}, hibernationKeys: keys}
			if tc.source == "source-node" {
				// Match the real RPC client, including its allocated absent-domain object.
				domain := &api.Domain{}
				if tc.domain {
					domain = &api.Domain{Status: api.DomainStatus{Status: api.Paused}}
				}
				client.EXPECT().GetDomain().Return(domain, tc.domain, nil)
			}
			result, err := controller.prepareHibernationProtection(client, vmi, hibernation.RequestDiscard)
			if tc.want {
				if err != nil || result == nil || !result.KeyErased || !keys.destroyed {
					t.Fatalf("discard failed: %v", err)
				}
			} else if err == nil || keys.destroyed {
				t.Fatal("unsafe discard was allowed")
			}
		})
	}
}

func TestDiscardRetriesLostLauncherReplyWithoutColdBoot(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := cmdclient.NewMockLauncherClient(ctrl)
	vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		hibernation.StateAnnotation: hibernation.StateDiscarding, hibernation.RequestAnnotation: hibernation.RequestDiscard,
		hibernation.SourceNodeAnnotation: "source-node", hibernation.VMUIDAnnotation: "vm-uid", hibernation.AttemptAnnotation: "attempt",
	}}}
	client.EXPECT().GetDomain().Return(&api.Domain{}, false, nil).Times(2)
	gomock.InOrder(
		client.EXPECT().HibernateVirtualMachine(vmi, cmdv1.HibernationAction_HIBERNATION_ACTION_ERASE, gomock.Any(), false, gomock.Any()).Return(nil, context.DeadlineExceeded),
		client.EXPECT().HibernateVirtualMachine(vmi, cmdv1.HibernationAction_HIBERNATION_ACTION_ERASE, gomock.Any(), false, gomock.Any()).Return(&cmdv1.HibernationResponse{Response: &cmdv1.Response{Success: true}, Phase: hibernation.StateDiscarded, MetadataJson: []byte(`{"vmUID":"vm-uid","attemptID":"attempt","erasedAt":"now","discardedAt":"now"}`)}, nil),
	)
	c := &VirtualMachineController{BaseController: &BaseController{host: "source-node"}, hibernationKeys: &fakeHibernationKeys{}}
	if err := c.syncHibernation(client, vmi, hibernation.RequestDiscard); err == nil {
		t.Fatal("lost reply was accepted")
	}
	if vmi.Annotations[hibernation.StateAnnotation] != hibernation.StateDiscarding || vmi.Annotations[hibernation.RequestAnnotation] != hibernation.RequestDiscard {
		t.Fatal("retry identity lost")
	}
	if err := c.syncHibernation(client, vmi, hibernation.RequestDiscard); err != nil {
		t.Fatal(err)
	}
	// A discarded cleanup launcher must remain inert until the controller removes it.
	if err := c.syncVirtualMachine(client, vmi, nil); err != nil {
		t.Fatal(err)
	}
}
