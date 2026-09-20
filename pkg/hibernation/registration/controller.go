// SPDX-License-Identifier: Apache-2.0
package registration

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	api "kubevirt.io/api/hibernation/v1alpha1"
	typed "kubevirt.io/client-go/kubevirt/typed/hibernation/v1alpha1"
	"kubevirt.io/client-go/log"
	"kubevirt.io/kubevirt/pkg/hibernation/keyservice"
)

// Controller owns node-local client identities; status is only an observation.
// The service independently checks its approval and grant records on every call.
type Controller struct {
	kube            kubernetes.Interface
	registrations   typed.HibernationKeyRegistrationInterface
	node, directory string
}

func New(kube kubernetes.Interface, registrations typed.HibernationKeyRegistrationInterface, node, directory string) *Controller {
	return &Controller{kube: kube, registrations: registrations, node: node, directory: directory}
}
func (c *Controller) Client(ctx context.Context, name string) (*keyservice.Client, *api.HibernationKeyRegistration, error) {
	r, e := c.registrations.Get(ctx, name, metav1.GetOptions{})
	if e != nil {
		return nil, nil, e
	}
	if r.DeletionTimestamp != nil || r.Spec.NodeName != c.node {
		return nil, r, fmt.Errorf("registration does not belong to this node")
	}
	node, e := c.kube.CoreV1().Nodes().Get(ctx, c.node, metav1.GetOptions{})
	if e != nil {
		return nil, r, e
	}
	if r.Spec.NodeUID != string(node.UID) || node.UID == "" || r.UID == "" {
		return nil, r, fmt.Errorf("registration node identity mismatch")
	}
	ns, e := c.kube.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if e != nil {
		return nil, r, e
	}
	client, e := keyservice.NewClient(r.Spec.Endpoint, r.Spec.ProviderID, r.Spec.ServerCA, filepath.Join(c.directory, string(r.UID)), keyservice.Enrollment{ClusterID: string(ns.UID), NodeUID: string(node.UID), RegistrationUID: string(r.UID)})
	return client, r, e
}
func (c *Controller) Reconcile(ctx context.Context, name string) error {
	client, r, e := c.Client(ctx, name)
	if r == nil || r.Spec.NodeName != c.node {
		return e
	}
	readyMetric.WithLabelValues(c.node, r.Name).Set(0)
	renewalFailureMetric.WithLabelValues(c.node, r.Name).Set(0)
	updated := r.DeepCopy()
	updated.Status.ObservedGeneration = r.Generation
	set := func(kind string, ok bool, reason, message string) {
		status := metav1.ConditionFalse
		if ok {
			status = metav1.ConditionTrue
		}
		meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{Type: kind, Status: status, ObservedGeneration: r.Generation, Reason: reason, Message: message})
	}
	if e == nil {
		updated.Status.ClusterID = client.Enrollment.ClusterID
		updated.Status.NodeUID = client.Enrollment.NodeUID
		var enrollment *keyservice.EnrollmentResponse
		enrollment, e = client.Enroll(ctx)
		if e == nil {
			updated.Status.ClientFingerprint = enrollment.Fingerprint
			updated.Status.EnrollmentRequestID = enrollment.RequestID
			updated.Status.EffectiveGrants = nil
			for _, g := range enrollment.Grants {
				updated.Status.EffectiveGrants = append(updated.Status.EffectiveGrants, api.HibernationKeyGrant{ClusterID: g.ClusterID, VMUID: g.VMUID})
			}
			approved := enrollment.Approved && !enrollment.Revoked
			expiryMetric.WithLabelValues(c.node, r.Name).Set(0)
			if approved {
				readyMetric.WithLabelValues(c.node, r.Name).Set(1)
				expiryMetric.WithLabelValues(c.node, r.Name).Set(float64(enrollment.ExpiresAt.Unix()))
			}
			updated.Status.CertificateExpiry = nil
			if approved {
				expiry := metav1.NewTime(enrollment.ExpiresAt)
				updated.Status.CertificateExpiry = &expiry
			}
			set("PendingApproval", !enrollment.Approved && !enrollment.Revoked, "ProviderDecision", "Operator approval occurs at the provider")
			set("Registered", approved, "ProviderDecision", "Registration approval does not grant VM access")
			set("Revoked", enrollment.Revoked, "ProviderDecision", "Current provider revocation decision")
			set("Ready", approved, "ProviderReachable", "VM access additionally requires an exact service-side grant")
		}
	}
	if e != nil {
		renewalFailureMetric.WithLabelValues(c.node, r.Name).Set(1)
		set("Ready", false, "EnrollmentFailed", "Cannot verify provider enrollment; inspect handler and provider health")
	}
	set("Degraded", e != nil, "EnrollmentReconciliation", "Enrollment and certificate renewal are reconciled with the provider")
	_, updateErr := c.registrations.UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	if updateErr != nil {
		return updateErr
	}
	return e
}
func (c *Controller) Run(ctx context.Context) {
	registerMetrics()
	informer := cache.NewSharedIndexInformer(&cache.ListWatch{
		ListFunc:  func(opts metav1.ListOptions) (runtime.Object, error) { return c.registrations.List(ctx, opts) },
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) { return c.registrations.Watch(ctx, opts) },
	}, &api.HibernationKeyRegistration{}, 5*time.Minute, cache.Indexers{})
	// Status updates must not recursively trigger certificate issuance. Resyncs
	// and spec changes reconcile; operations always consult live provider policy.
	reconcile := func(obj interface{}) {
		r, ok := obj.(*api.HibernationKeyRegistration)
		if !ok || r.Spec.NodeName != c.node {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 50*time.Second)
		defer cancel()
		if e := c.Reconcile(requestCtx, r.Name); e != nil {
			log.Log.Reason(e).Error("Hibernation registration reconciliation failed")
		}
	}
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{AddFunc: reconcile, DeleteFunc: func(obj interface{}) {
		if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
			obj = tombstone.Obj
		}
		if r, ok := obj.(*api.HibernationKeyRegistration); ok && r.Spec.NodeName == c.node {
			readyMetric.DeleteLabelValues(c.node, r.Name)
			renewalFailureMetric.DeleteLabelValues(c.node, r.Name)
			expiryMetric.DeleteLabelValues(c.node, r.Name)
		}
	}, UpdateFunc: func(old, new interface{}) {
		a := old.(*api.HibernationKeyRegistration)
		b := new.(*api.HibernationKeyRegistration)
		if a.ResourceVersion == b.ResourceVersion || a.Generation != b.Generation {
			reconcile(b)
		}
	}})
	informer.Run(ctx.Done())
}
