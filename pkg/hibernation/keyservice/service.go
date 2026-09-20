// SPDX-License-Identifier: Apache-2.0
package keyservice

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"kubevirt.io/kubevirt/pkg/hibernation/protection"
)

type Service struct {
	mu      sync.Mutex
	db      *bolt.DB
	backend Backend
	dir     string
	ca      *x509.Certificate
	caKey   crypto.Signer
	now     func() time.Time
}

func Initialize(dir, host, providerID string) error {
	if host == "" || providerID == "" {
		return fmt.Errorf("host and provider identity required")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	st, e := os.Lstat(dir)
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 || !ownedByProcess(st) {
		return fmt.Errorf("service directory must be private")
	}
	// Concurrent explicit init commands share the existing TPM transaction lock;
	// otherwise both could pass the empty-directory check and race PKI writes.
	fd, e := unix.Open(filepath.Join(dir, "tpm.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	if e = unix.Flock(fd, unix.LOCK_EX); e != nil {
		return e
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if entry.Name() != "tpm.lock" {
			return fmt.Errorf("refusing to initialize nonempty service directory")
		}
	}
	if e = writePKI(dir, host); e != nil {
		return e
	}
	db, e := openDatabase(filepath.Join(dir, "metadata.db"), true, providerID)
	if e != nil {
		return e
	}
	return db.Close()
}
func New(dir, providerID string, backend Backend) (*Service, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 || !ownedByProcess(info) {
		return nil, fmt.Errorf("unsafe service directory")
	}

	if e := protection.RequireProtectedMemory(); e != nil {
		return nil, e
	}
	db, e := openDatabase(filepath.Join(dir, "metadata.db"), false, providerID)
	if e != nil {
		return nil, e
	}
	fail := func(err error) (*Service, error) { db.Close(); return nil, err }
	state, e := readState(db)
	if e != nil {
		return fail(e)
	}
	if state.ProviderID != providerID {
		return fail(fmt.Errorf("TPM provider identity changed"))
	}
	certBytes, e := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if e != nil {
		return fail(e)
	}
	ca, e := parseCert(certBytes)
	if e != nil {
		return fail(e)
	}
	keyBytes, e := readPrivate(filepath.Join(dir, "ca.key"))
	if e != nil {
		return fail(e)
	}
	defer clear(keyBytes)
	key, e := parseKey(keyBytes)
	if e != nil {
		return fail(e)
	}
	pub, e := x509.MarshalPKIXPublicKey(key.Public())
	if e != nil {
		return fail(e)
	}
	if fingerprint(pub) != fingerprint(ca.RawSubjectPublicKeyInfo) {
		return fail(fmt.Errorf("CA key mismatch"))
	}
	return &Service{db: db, backend: backend, dir: dir, ca: ca, caKey: key, now: time.Now}, nil
}
func (s *Service) Close() error { return s.db.Close() }
func (s *Service) ActiveAttempts() ([]protection.Attempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, e := readState(s.db)
	if e != nil {
		return nil, e
	}
	var out []protection.Attempt
	for _, a := range state.Attempts {
		if a.State == "erased" {
			continue
		}
		st, err := s.backend.Inspect(a.Request.attempt())
		if err != nil {
			return nil, err
		}
		switch a.State {
		case "active", "consumed":
			if !st.KeyPresent || !st.NVPresent || (a.State == "consumed" && !st.Consumed) {
				return nil, fmt.Errorf("attempt metadata disagrees with TPM; recovery required")
			}
		case "erased":
			if st.KeyPresent || st.NVPresent {
				return nil, fmt.Errorf("erased attempt retains TPM objects; recovery required")
			}
		case "creating", "erasing": // Interrupted transactions remain available for explicit cleanup.
		default:
			return nil, fmt.Errorf("unknown attempt state; recovery required")
		}
		if a.State != "erased" {
			out = append(out, a.Request.attempt())
		}
	}
	return out, nil
}
func (s *Service) Enroll(e Enrollment) (*EnrollmentResponse, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	if len(e.CSR) > 16384 {
		return nil, fmt.Errorf("CSR too large")
	}
	block, _ := pem.Decode([]byte(e.CSR))
	if block == nil {
		return nil, fmt.Errorf("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CSR")
	}
	if err = csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature")
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return nil, fmt.Errorf("unsupported public key")
	}
	fp := fingerprint(csr.RawSubjectPublicKeyInfo)
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := readState(s.db)
	if err != nil {
		return nil, err
	}
	identity := e.ClusterID + "/" + e.NodeUID + "/" + e.RegistrationUID + "/" + fp
	id := fingerprint([]byte(identity))
	p := state.Principals[id]
	if p == nil {
		if len(state.Principals) >= 1024 {
			return nil, fmt.Errorf("enrollment capacity reached")
		}
		p = &Principal{ID: id, ClusterID: e.ClusterID, NodeUID: e.NodeUID, RegistrationUID: e.RegistrationUID, Fingerprint: fp, PublicKey: csr.RawSubjectPublicKeyInfo}
		state.Principals[id] = p
		if err = saveState(s.db, state); err != nil {
			return nil, err
		}
	}
	out := &EnrollmentResponse{RequestID: p.ID, ProviderID: state.ProviderID, Fingerprint: fp, Approved: p.Approved, Revoked: p.Revoked}
	if p.Approved && !p.Revoked {
		out.Grants = p.Grants
		out.Certificate, out.ExpiresAt, err = s.issue(p)
	}
	return out, err
}
func (s *Service) approved(state *State, cert *x509.Certificate) (*Principal, error) {
	if cert == nil || s.now().Before(cert.NotBefore) || !s.now().Before(cert.NotAfter) {
		return nil, fmt.Errorf("client certificate required or expired")
	}
	roots := x509.NewCertPool()
	roots.AddCert(s.ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: s.now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, fmt.Errorf("invalid client certificate")
	}
	p := state.Principals[cert.Subject.CommonName]
	if p == nil || !p.Approved || p.Revoked || p.Fingerprint != fingerprint(cert.RawSubjectPublicKeyInfo) {
		return nil, fmt.Errorf("client not approved")
	}
	return p, nil
}
func granted(p *Principal, r Request) bool {
	for _, g := range p.Grants {
		if g.ClusterID == r.ClusterID && g.VMUID == r.VMUID {
			return true
		}
	}
	return false
}
func (s *Service) Operate(cert *x509.Certificate, r Request) (*Response, error) {
	if e := r.Validate(); e != nil {
		return nil, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, e := readState(s.db)
	if e != nil {
		return nil, e
	}
	p, e := s.approved(state, cert)
	if e != nil {
		return nil, e
	}
	if backend, ok := s.backend.(interface{ ProviderIdentity() (string, error) }); ok {
		actual, e := backend.ProviderIdentity()
		if e != nil {
			return nil, e
		}
		if actual != state.ProviderID {
			return nil, fmt.Errorf("TPM provider identity changed; recovery required")
		}
	}
	if r.ProviderID != state.ProviderID || r.ClusterID != p.ClusterID || !granted(p, r) {
		return nil, fmt.Errorf("attempt not authorized")
	}
	a := state.Attempts[r.dbKey()]
	if a == nil {
		if r.Operation != "create" {
			return nil, protection.ErrMissing
		}
		for _, other := range state.Attempts {
			if other.Request.VMUID == r.VMUID && other.Request.AttemptID == r.AttemptID {
				return nil, fmt.Errorf("attempt identity already allocated")
			}
		}
		st, e := s.backend.Inspect(r.attempt())
		if e != nil {
			return nil, e
		}
		if st.KeyPresent || st.NVPresent {
			return nil, fmt.Errorf("TPM object exists without ownership record")
		}
		active := 0
		for _, other := range state.Attempts {
			if other.State != "erased" {
				active++
			}
		}
		if active >= 8 {
			return nil, fmt.Errorf("active attempt capacity reached")
		}
		a = &AttemptRecord{Request: r, PrincipalID: p.ID, State: "creating", UpdatedAt: s.now()}
		state.Attempts[r.dbKey()] = a
		if e = saveState(s.db, state); e != nil {
			return nil, e
		}
		a.Key, e = s.backend.Create(r.attempt())
		if e != nil {
			return nil, e
		}
		a.State = "active"
		a.UpdatedAt = s.now()
		if e = saveState(s.db, state); e != nil {
			return nil, e
		}
	} else {
		if a.PrincipalID != p.ID {
			return nil, fmt.Errorf("attempt belongs to another client")
		}
		if r.KeyID != "" && r.KeyID != a.Key.ID {
			return nil, fmt.Errorf("key identity mismatch")
		}
		if a.State == "erasing" && r.Operation != "finalize" && r.Operation != "abandon" && r.Operation != "discard" && r.Operation != "status" {
			return nil, fmt.Errorf("cleanup is in progress")
		}
		if a.State == "creating" && r.Operation != "discard" && r.Operation != "status" {
			return nil, fmt.Errorf("interrupted creation requires recovery inspection")
		}
	}
	if r.Operation == "finalize" && (a.Request.RestoreVMIUID == "" || a.Request.RestoreVMIUID != r.RestoreVMIUID) {
		return nil, fmt.Errorf("finalization belongs to another restore VMI")
	}
	out := &Response{ProviderID: state.ProviderID, PrincipalID: p.ID, VMUID: r.VMUID, AttemptID: r.AttemptID, RestoreVMIUID: r.RestoreVMIUID, Key: a.Key, State: a.State}
	if a.State == "erased" {
		if r.Operation == "finalize" || r.Operation == "discard" || r.Operation == "abandon" || r.Operation == "status" {
			out.Erased = true
			return out, nil
		}
		return nil, protection.ErrMissing
	}
	st, e := s.backend.Inspect(r.attempt())
	if e != nil {
		return nil, e
	}
	if r.Operation == "open" || r.Operation == "consume" {
		if a.Request.ArtifactDigest != "" && a.Request.ArtifactDigest != r.ArtifactDigest {
			return nil, fmt.Errorf("artifact digest changed")
		}
		if a.Request.ArtifactDigest == "" {
			a.Request.ArtifactDigest = r.ArtifactDigest
			if e = saveState(s.db, state); e != nil {
				return nil, e
			}
		}
	}
	switch r.Operation {
	case "create":
		if !st.KeyPresent || !st.NVPresent {
			return nil, fmt.Errorf("attempt has lost TPM state")
		}
		if st.Consumed {
			return nil, protection.ErrConsumed
		}
	case "status":
		out.Erased = !st.KeyPresent && !st.NVPresent
		if st.Consumed {
			out.State = "consumed"
		}
	case "open":
		if st.Consumed {
			return nil, protection.ErrConsumed
		}
		key, e := s.backend.Open(r.attempt())
		if e != nil {
			return nil, e
		}
		defer key.Close()
		if key.ID != a.Key.ID {
			return nil, fmt.Errorf("TPM key identity changed")
		}
		out.PrivateIdentity = append([]byte(nil), key.Identity...)
	case "consume":
		if a.Request.RestoreVMIUID != "" && a.Request.RestoreVMIUID != r.RestoreVMIUID {
			return nil, fmt.Errorf("consumption belongs to another restore VMI")
		}
		// Persist the selected restore before changing irreversible TPM state.
		a.Request.RestoreVMIUID = r.RestoreVMIUID
		if e = saveState(s.db, state); e != nil {
			return nil, e
		}
		// Never return a recorded fresh acknowledgement on retry. The TPM decides.
		out.Fresh, e = s.backend.Consume(r.attempt())
		if e != nil {
			return nil, fmt.Errorf("%w: %v", ErrUncertainConsumption, e)
		}
		out.State = "consumed"
		if a.State != "consumed" {
			a.UpdatedAt = s.now()
		}
		a.State = "consumed"
		a.Request.RestoreVMIUID = r.RestoreVMIUID
		if e = saveState(s.db, state); e != nil {
			return nil, fmt.Errorf("%w: %v", ErrUncertainConsumption, e)
		}
	case "finalize", "abandon", "discard":
		// Record intent first; deletion is retryable and reads back TPM absence.
		if a.State != "erasing" {
			a.UpdatedAt = s.now()
		}
		a.State = "erasing"
		if e = saveState(s.db, state); e != nil {
			return nil, e
		}
		switch r.Operation {
		case "finalize":
			e = s.backend.Destroy(r.attempt())
		case "abandon":
			e = s.backend.Abandon(r.attempt())
		case "discard":
			e = s.backend.Discard(r.attempt())
		}
		if e != nil {
			return nil, e
		}
		a.State = "erased"
		a.UpdatedAt = s.now()
		if e = saveState(s.db, state); e != nil {
			return nil, e
		}
		out.Erased = true
		out.State = "erased"
	}
	return out, nil
}

type AdminRequest struct {
	Operation   string `json:"operation"`
	RequestID   string `json:"requestID,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Grant       Grant  `json:"grant,omitempty"`
}

func (s *Service) Admin(r AdminRequest) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, e := readState(s.db)
	if e != nil {
		return nil, e
	}
	if r.Operation == "inspect" {
		return state, nil
	}
	if r.Operation == "renew-server" {
		expiry, e := s.RenewServerCertificate()
		return map[string]any{"expiresAt": expiry}, e
	}
	p := state.Principals[r.RequestID]
	if p == nil {
		return nil, fmt.Errorf("unknown request")
	}
	switch r.Operation {
	case "approve":
		if r.Fingerprint == "" || r.Fingerprint != p.Fingerprint {
			return nil, fmt.Errorf("verified fingerprint required")
		}
		if p.Revoked {
			return nil, fmt.Errorf("revoked identity cannot be reapproved")
		}
		p.Approved = true
	case "revoke":
		p.Revoked = true
	case "grant", "ungrant":
		if !p.Approved || p.Revoked || r.Grant.ClusterID != p.ClusterID || !validID(r.Grant.VMUID) {
			return nil, fmt.Errorf("invalid grant")
		}
		filtered := []Grant{}
		for _, g := range p.Grants {
			if g != r.Grant {
				filtered = append(filtered, g)
			}
		}
		p.Grants = filtered
		if r.Operation == "grant" {
			p.Grants = append(p.Grants, r.Grant)
		}
	default:
		return nil, fmt.Errorf("unknown administrative operation")
	}
	if e = saveState(s.db, state); e != nil {
		return nil, e
	}
	return p, nil
}
func errorCode(e error) string {
	if errors.Is(e, ErrUncertainConsumption) {
		return "commit-uncertain"
	}
	if errors.Is(e, protection.ErrConsumed) {
		return "consumed"
	}
	if errors.Is(e, protection.ErrMissing) {
		return "missing"
	}
	return "rejected"
}
func (s *Service) publicState() (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, e := readState(s.db)
	if e != nil {
		return nil, e
	}
	return map[string]any{"providerID": st.ProviderID, "version": 1}, nil
}
func (s *Service) MarshalPublicState() ([]byte, error) {
	st, e := s.publicState()
	if e != nil {
		return nil, e
	}
	return json.Marshal(st)
}
