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

package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/emicklei/go-restful/v3"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
	"kubevirt.io/kubevirt/pkg/hibernation"
	"kubevirt.io/kubevirt/pkg/testutils"
	"kubevirt.io/kubevirt/pkg/virt-config/featuregate"
)

func TestHibernationPublicRequest(t *testing.T) {
	for _, tc := range []struct {
		name, operation, state, capacity string
		gate, approved, dryRun, noVMI    bool
		want                             int
	}{
		{name: "save", operation: "hibernate", capacity: "40Gi", gate: true, approved: true, want: 202},
		{name: "dry run", operation: "hibernate", capacity: "40Gi", gate: true, approved: true, dryRun: true, want: 202},
		{name: "gate disabled", operation: "hibernate", capacity: "40Gi", approved: true, want: 400},
		{name: "unapproved storage", operation: "hibernate", capacity: "40Gi", gate: true, want: 409},
		{name: "undersized storage", operation: "hibernate", capacity: "32Gi", gate: true, approved: true, want: 409},
		{name: "resume", operation: "resume", state: hibernation.StateHibernated, gate: true, noVMI: true, want: 202},
		{name: "resume running", operation: "resume", state: hibernation.StateHibernated, gate: true, want: 409},
		{name: "finalize", operation: "finalizehibernation", state: hibernation.StateRunningAwaitingVerification, gate: true, want: 202},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			client := kubecli.NewMockKubevirtClient(ctrl)
			vmClient := kubecli.NewMockVirtualMachineInterface(ctrl)
			vmiClient := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)
			cfg := &v1.KubeVirtConfiguration{}
			if tc.gate {
				cfg.DeveloperConfiguration = &v1.DeveloperConfiguration{FeatureGates: []string{featuregate.HibernationGate}}
			}
			config, _, _ := testutils.NewFakeClusterConfigUsingKVConfig(cfg)
			vm := &v1.VirtualMachine{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default", ResourceVersion: "42", Annotations: map[string]string{hibernation.StatePVCAnnotation: "state", hibernation.StateAnnotation: tc.state, hibernation.ArtifactDigestAnnotation: "digest"}}}
			vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{hibernation.StatePVCAnnotation: "state"}}, Spec: v1.VirtualMachineInstanceSpec{Domain: v1.DomainSpec{Resources: v1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("32Gi")}}}}, Status: v1.VirtualMachineInstanceStatus{Phase: v1.Running, Conditions: []v1.VirtualMachineInstanceCondition{{Type: v1.VirtualMachineInstanceReady, Status: corev1.ConditionTrue}}}}
			if tc.gate {
				client.EXPECT().VirtualMachine("default").Return(vmClient).AnyTimes()
				vmClient.EXPECT().Get(gomock.Any(), "test", gomock.Any()).Return(vm, nil)
				client.EXPECT().VirtualMachineInstance("default").Return(vmiClient)
				if tc.noVMI {
					vmiClient.EXPECT().Get(gomock.Any(), "test", gomock.Any()).Return(nil, apierrors.NewNotFound(v1.Resource("virtualmachineinstance"), "test"))
				} else {
					vmiClient.EXPECT().Get(gomock.Any(), "test", gomock.Any()).Return(vmi, nil)
				}
				if tc.operation == "hibernate" {
					sc := "encrypted"
					pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "state", Namespace: "default"}, Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: &sc, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod}}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound, Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(tc.capacity)}}}
					storageClass := &storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: sc}}
					if tc.approved {
						storageClass.Annotations = map[string]string{encryptedHibernationStorageAnnotation: "true"}
					}
					kube := fake.NewSimpleClientset(pvc, storageClass)
					client.EXPECT().CoreV1().Return(kube.CoreV1())
					client.EXPECT().StorageV1().Return(kube.StorageV1())
				}
				if tc.want == 202 {
					vmClient.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, updated *v1.VirtualMachine, options metav1.UpdateOptions) (*v1.VirtualMachine, error) {
						operation := tc.operation
						if operation == "finalizehibernation" {
							operation = hibernation.RequestFinalize
						}
						if updated.ResourceVersion != "42" || updated.Annotations[hibernation.RequestAnnotation] != operation {
							t.Fatalf("incorrect queued update: %+v", updated.ObjectMeta)
						}
						if (len(options.DryRun) > 0) != tc.dryRun {
							t.Fatalf("dry run not preserved: %+v", options)
						}
						return updated, nil
					})
				}
			}
			app := &SubresourceAPIApp{virtCli: client, clusterConfig: config}
			ws := new(restful.WebService).Path("/namespaces/{namespace}/virtualmachines/{name}")
			ws.Route(ws.PUT("/hibernate").To(app.HibernateVMRequestHandler))
			ws.Route(ws.PUT("/resume").To(app.ResumeVMRequestHandler))
			ws.Route(ws.PUT("/finalizehibernation").To(app.FinalizeHibernationVMRequestHandler))
			container := restful.NewContainer()
			container.Add(ws)
			body := "{}"
			if tc.dryRun {
				body = `{"dryRun":["All"]}`
			}
			req := httptest.NewRequest(http.MethodPut, "/namespaces/default/virtualmachines/test/"+tc.operation, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp := httptest.NewRecorder()
			container.ServeHTTP(resp, req)
			if resp.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", resp.Code, tc.want, resp.Body.String())
			}
		})
	}
}

func TestHibernationBlocksOrdinaryLifecycleRequest(t *testing.T) {
	for _, operation := range []string{"pause", "unpause", "reset", "softreboot"} {
		t.Run(operation, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			client := kubecli.NewMockKubevirtClient(ctrl)
			vmiClient := kubecli.NewMockVirtualMachineInstanceInterface(ctrl)
			vmi := &v1.VirtualMachineInstance{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test", Annotations: map[string]string{hibernation.StateAnnotation: hibernation.StateRestoredPaused}}}
			client.EXPECT().VirtualMachineInstance("default").Return(vmiClient)
			vmiClient.EXPECT().Get(gomock.Any(), "test", gomock.Any()).Return(vmi, nil)
			if operation == "unpause" {
				vmClient := kubecli.NewMockVirtualMachineInterface(ctrl)
				client.EXPECT().VirtualMachine("default").Return(vmClient)
				vmClient.EXPECT().Get(gomock.Any(), "test", gomock.Any()).Return(nil, apierrors.NewNotFound(v1.Resource("virtualmachine"), "test"))
			}
			app := &SubresourceAPIApp{virtCli: client}
			ws := new(restful.WebService).Path("/namespaces/{namespace}/virtualmachineinstances/{name}")
			handlers := map[string]restful.RouteFunction{"pause": app.PauseVMIRequestHandler, "unpause": app.UnpauseVMIRequestHandler, "reset": app.ResetVMIRequestHandler, "softreboot": app.SoftRebootVMIRequestHandler}
			ws.Route(ws.PUT("/" + operation).To(handlers[operation]))
			container := restful.NewContainer()
			container.Add(ws)
			resp := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPut, "/namespaces/default/virtualmachineinstances/test/"+operation, nil)
			container.ServeHTTP(resp, req)
			if resp.Code != http.StatusConflict || !strings.Contains(resp.Body.String(), "hibernation") {
				t.Fatalf("ordinary %s passed the active attempt: %d %s", operation, resp.Code, resp.Body.String())
			}
		})
	}
}
