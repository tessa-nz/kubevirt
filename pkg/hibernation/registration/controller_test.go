// SPDX-License-Identifier: Apache-2.0
package registration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fake "k8s.io/client-go/kubernetes/fake"
	api "kubevirt.io/api/hibernation/v1alpha1"
	virtfake "kubevirt.io/client-go/kubevirt/fake"
)

func TestRegistrationIdentityPersistsAndRejectsRecreatedNode(t *testing.T) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "node-uid"}}
	r := &api.HibernationKeyRegistration{ObjectMeta: metav1.ObjectMeta{Name: "registration", UID: "registration-uid"}, Spec: api.HibernationKeyRegistrationSpec{Endpoint: "https://localhost", ServerCA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), ProviderID: "provider", NodeName: node.Name, NodeUID: string(node.UID)}}
	// A forged status grant is not used to construct or authorize the client.
	r.Status.EffectiveGrants = []api.HibernationKeyGrant{{ClusterID: "forged", VMUID: "forged"}}
	k := fake.NewSimpleClientset(node, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "cluster-uid"}})
	v := virtfake.NewSimpleClientset(r)
	dir := t.TempDir()
	ctx := context.Background()
	c := New(k, v.HibernationV1alpha1().HibernationKeyRegistrations(), "node", dir)
	first, _, e := c.Client(ctx, r.Name)
	if e != nil {
		t.Fatal(e)
	}
	replacement := New(k, v.HibernationV1alpha1().HibernationKeyRegistrations(), "node", dir)
	second, _, e := replacement.Client(ctx, r.Name)
	if e != nil {
		t.Fatal(e)
	}
	if first.PrincipalID != second.PrincipalID || second.Enrollment.ClusterID != "cluster-uid" {
		t.Fatal("pod replacement changed identity or trusted status")
	}
	info, e := os.Stat(filepath.Join(dir, string(r.UID), "client.key"))
	if e != nil {
		t.Fatal(e)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("private key permissions")
	}
	node.UID = "replacement"
	if _, e = k.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, _, e = c.Client(ctx, r.Name); e == nil {
		t.Fatal("recreated node inherited enrollment")
	}
	wrong := New(k, v.HibernationV1alpha1().HibernationKeyRegistrations(), "other", dir)
	if _, _, e = wrong.Client(ctx, r.Name); e == nil {
		t.Fatal("another handler reconciled registration")
	}
}
