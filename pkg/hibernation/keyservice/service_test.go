// SPDX-License-Identifier: Apache-2.0
package keyservice

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kubevirt.io/kubevirt/pkg/hibernation/protection"
)

type testBackend struct {
	status               protection.AttemptStatus
	createErr, deleteErr error
}

func (b *testBackend) Create(protection.Attempt) (protection.PublicKey, error) {
	b.status = protection.AttemptStatus{KeyPresent: true, NVPresent: true}
	return protection.PublicKey{ID: "key"}, b.createErr
}
func (b *testBackend) Open(protection.Attempt) (*protection.PrivateKey, error) {
	return nil, errors.New("not used")
}
func (b *testBackend) Consume(protection.Attempt) (bool, error) {
	fresh := !b.status.Consumed
	b.status.Consumed = true
	return fresh, nil
}
func (b *testBackend) Destroy(protection.Attempt) error {
	if b.deleteErr != nil {
		return b.deleteErr
	}
	b.status = protection.AttemptStatus{}
	return nil
}
func (b *testBackend) Abandon(a protection.Attempt) error { return b.Destroy(a) }
func (b *testBackend) Discard(a protection.Attempt) error { return b.Destroy(a) }
func (b *testBackend) Inspect(protection.Attempt) (protection.AttemptStatus, error) {
	return b.status, nil
}
func fixture(t *testing.T) (*Service, *testBackend) {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := Initialize(dir, "127.0.0.1", "provider"); e != nil {
		t.Fatal(e)
	}
	db, e := openDatabase(filepath.Join(dir, "metadata.db"), false, "provider")
	if e != nil {
		t.Fatal(e)
	}
	cb, e := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if e != nil {
		t.Fatal(e)
	}
	ca, e := parseCert(cb)
	if e != nil {
		t.Fatal(e)
	}
	kb, e := readPrivate(filepath.Join(dir, "ca.key"))
	if e != nil {
		t.Fatal(e)
	}
	key, e := parseKey(kb)
	clear(kb)
	if e != nil {
		t.Fatal(e)
	}
	b := &testBackend{}
	s := &Service{db: db, backend: b, dir: dir, ca: ca, caKey: key, now: time.Now}
	t.Cleanup(func() { s.Close() })
	return s, b
}
func enrollment(t *testing.T) Enrollment {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "forged-administrator"}}, key)
	if e != nil {
		t.Fatal(e)
	}
	return Enrollment{ClusterID: "cluster", NodeUID: "node", RegistrationUID: "registration", CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))}
}
func approvedClient(t *testing.T, s *Service) (*x509.Certificate, Enrollment) {
	t.Helper()
	en := enrollment(t)
	r, e := s.Enroll(en)
	if e != nil {
		t.Fatal(e)
	}
	if r.Approved || r.Certificate != "" {
		t.Fatal("unapproved enrollment received credentials")
	}
	if _, e = s.Admin(AdminRequest{Operation: "approve", RequestID: r.RequestID, Fingerprint: r.Fingerprint}); e != nil {
		t.Fatal(e)
	}
	r, e = s.Enroll(en)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := parseCert([]byte(r.Certificate))
	if e != nil {
		t.Fatal(e)
	}
	if cert.Subject.CommonName != r.RequestID {
		t.Fatal("CSR selected identity")
	}
	return cert, en
}
func grant(t *testing.T, s *Service, c *x509.Certificate) {
	t.Helper()
	if _, e := s.Admin(AdminRequest{Operation: "grant", RequestID: c.Subject.CommonName, Grant: Grant{ClusterID: "cluster", VMUID: "vm"}}); e != nil {
		t.Fatal(e)
	}
}
func request(op string) Request {
	return Request{Operation: op, ClusterID: "cluster", VMUID: "vm", AttemptID: "attempt", ProviderID: "provider", KeyID: "key", RestoreVMIUID: "restore", ArtifactDigest: strings.Repeat("a", 64)}
}
func TestEnrollmentApprovalAndGrants(t *testing.T) {
	s, _ := fixture(t)
	cert, en := approvedClient(t, s)
	if _, e := s.Operate(cert, request("create")); e == nil {
		t.Fatal("approval granted VM access")
	}
	grant(t, s, cert)
	for _, change := range []func(*Request){func(r *Request) { r.ClusterID = "other" }, func(r *Request) { r.VMUID = "other" }, func(r *Request) { r.ProviderID = "other" }} {
		r := request("create")
		change(&r)
		if _, e := s.Operate(cert, r); e == nil {
			t.Fatal("foreign identity accepted")
		}
	}
	if _, e := s.Operate(cert, request("create")); e != nil {
		t.Fatal(e)
	}
	replacement, e := s.Enroll(enrollment(t))
	if e != nil {
		t.Fatal(e)
	}
	if replacement.Approved {
		t.Fatal("replacement key inherited approval")
	}
	en.NodeUID = "new-node"
	changed, e := s.Enroll(en)
	if e != nil {
		t.Fatal(e)
	}
	if changed.Approved {
		t.Fatal("new node inherited approval")
	}
	if _, e = s.Admin(AdminRequest{Operation: "revoke", RequestID: cert.Subject.CommonName}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Operate(cert, request("status")); e == nil {
		t.Fatal("cached certificate bypassed revocation")
	}
}
func TestExpiredCertificateSameKeyRecovery(t *testing.T) {
	s, _ := fixture(t)
	cert, en := approvedClient(t, s)
	grant(t, s, cert)
	s.now = func() time.Time { return cert.NotAfter.Add(time.Hour) }
	if _, e := s.Operate(cert, request("status")); e == nil {
		t.Fatal("expired certificate accepted")
	}
	renewed, e := s.Enroll(en)
	if e != nil {
		t.Fatal(e)
	}
	next, e := parseCert([]byte(renewed.Certificate))
	if e != nil {
		t.Fatal(e)
	}
	if next.Subject.CommonName != cert.Subject.CommonName || !next.NotAfter.After(cert.NotAfter) {
		t.Fatal("renewal changed identity or failed to extend expiry")
	}
	if _, e = s.Operate(next, request("create")); e != nil {
		t.Fatal(e)
	}
}
func TestConsumptionConcurrencyLostReplyAndRollback(t *testing.T) {
	s, b := fixture(t)
	cert, _ := approvedClient(t, s)
	grant(t, s, cert)
	if _, e := s.Operate(cert, request("create")); e != nil {
		t.Fatal(e)
	}
	snapshot, e := readState(s.db)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 16)
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := s.Operate(cert, request("consume"))
			if e != nil {
				errs <- e
				return
			}
			results <- r.Fresh
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	fresh := 0
	for f := range results {
		if f {
			fresh++
		}
	}
	if fresh != 1 {
		t.Fatalf("fresh results=%d", fresh)
	}
	// The caller loses the first reply and metadata is restored from before consumption.
	if e = saveState(s.db, snapshot); e != nil {
		t.Fatal(e)
	}
	r, e := s.Operate(cert, request("consume"))
	if e != nil {
		t.Fatal(e)
	}
	if r.Fresh || !b.status.Consumed {
		t.Fatal("database rollback replayed authorization")
	}
	other := request("consume")
	other.RestoreVMIUID = "other"
	if _, e = s.Operate(cert, other); e == nil {
		t.Fatal("restore VMI binding changed")
	}
	if _, e = s.Operate(cert, request("open")); !errors.Is(e, protection.ErrConsumed) {
		t.Fatalf("open after consumption: %v", e)
	}
}
func TestInterruptedCreationAndCleanup(t *testing.T) {
	s, b := fixture(t)
	cert, _ := approvedClient(t, s)
	grant(t, s, cert)
	b.createErr = errors.New("interrupted")
	if _, e := s.Operate(cert, request("create")); e == nil {
		t.Fatal("creation fault ignored")
	}
	b.createErr = nil
	if _, e := s.Operate(cert, request("create")); e == nil {
		t.Fatal("interrupted creation silently reused")
	}
	r := request("discard")
	r.KeyID = ""
	b.deleteErr = errors.New("interrupted cleanup")
	if _, e := s.Operate(cert, r); e == nil {
		t.Fatal("cleanup fault ignored")
	}
	if _, e := s.Operate(cert, request("create")); e == nil {
		t.Fatal("erasing attempt reopened")
	}
	b.deleteErr = nil
	for i := 0; i < 2; i++ {
		out, e := s.Operate(cert, r)
		if e != nil {
			t.Fatal(e)
		}
		if !out.Erased {
			t.Fatal("cleanup not verified")
		}
	}
}

func TestConcurrentInitializationDoesNotReplaceAuthority(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- Initialize(dir, "localhost", "provider") }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("initializations succeeded=%d", successes)
	}
	cert, e := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if e != nil {
		t.Fatal(e)
	}
	if e = Initialize(dir, "localhost", "provider"); e == nil {
		t.Fatal("existing authority overwritten")
	}
	after, e := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if e != nil {
		t.Fatal(e)
	}
	if string(cert) != string(after) {
		t.Fatal("CA changed")
	}
}

func TestFinalizationMustMatchRestoringVMI(t *testing.T) {
	s, _ := fixture(t)
	cert, _ := approvedClient(t, s)
	grant(t, s, cert)
	if _, e := s.Operate(cert, request("create")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Operate(cert, request("consume")); e != nil {
		t.Fatal(e)
	}
	r := request("finalize")
	r.RestoreVMIUID = "other"
	if _, e := s.Operate(cert, r); e == nil {
		t.Fatal("foreign restore finalized key")
	}
	if _, e := s.Operate(cert, request("finalize")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Operate(cert, r); e == nil {
		t.Fatal("erased attempt lost restore binding")
	}
}
