// SPDX-License-Identifier: Apache-2.0
package keyservice

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"kubevirt.io/kubevirt/pkg/hibernation/protection"
)

type Client struct {
	Endpoint    string
	ProviderID  string
	PrincipalID string
	Enrollment  Enrollment
	Directory   string
	key         crypto.Signer
	roots       *x509.CertPool
}

func NewClient(endpoint, providerID, caPEM, directory string, enrollment Enrollment) (*Client, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, fmt.Errorf("provider must be a bare HTTPS origin")
	}
	if e = enrollment.Validate(); e != nil {
		return nil, e
	}
	if providerID == "" {
		return nil, fmt.Errorf("provider identity required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("invalid server trust bundle")
	}
	if e = os.MkdirAll(directory, 0700); e != nil {
		return nil, e
	}
	st, e := os.Lstat(directory)
	if e != nil {
		return nil, e
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 || !ownedByProcess(st) {
		return nil, fmt.Errorf("unsafe identity directory")
	}
	// Overlapping handler pods must not generate competing keys for one registration.
	fd, e := unix.Open(filepath.Join(directory, "identity.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	defer unix.Close(fd)
	if e = unix.Flock(fd, unix.LOCK_EX); e != nil {
		return nil, e
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	keyPath := filepath.Join(directory, "client.key")
	data, e := readPrivate(keyPath)
	if errors.Is(e, os.ErrNotExist) {
		// A retained marker prevents silent replacement of a previously generated
		// identity when its key file is missing.
		if _, markerErr := os.Lstat(filepath.Join(directory, "identity.json")); !errors.Is(markerErr, os.ErrNotExist) {
			return nil, fmt.Errorf("client key lost; explicit re-enrollment required")
		}
		_, key, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			return nil, keyErr
		}
		data, e = encodeKey(key)
		if e != nil {
			return nil, e
		}
		if e = AtomicWrite(keyPath, data, 0600); e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	}
	defer clear(data)
	key, e := parseKey(data)
	if e != nil {
		return nil, e
	}
	pub, e := x509.MarshalPKIXPublicKey(key.Public())
	if e != nil {
		return nil, e
	}
	c := &Client{Endpoint: endpoint, ProviderID: providerID, Enrollment: enrollment, Directory: directory, key: key, roots: roots}
	c.PrincipalID = fingerprint([]byte(enrollment.ClusterID + "/" + enrollment.NodeUID + "/" + enrollment.RegistrationUID + "/" + fingerprint(pub)))
	marker := map[string]string{"principalID": c.PrincipalID, "fingerprint": fingerprint(pub), "providerID": providerID}
	if old, err := os.ReadFile(filepath.Join(directory, "identity.json")); err == nil {
		var existing map[string]string
		if json.Unmarshal(old, &existing) != nil || existing["principalID"] != c.PrincipalID || existing["providerID"] != providerID || existing["fingerprint"] != fingerprint(pub) {
			return nil, fmt.Errorf("client identity binding changed")
		}
		return c, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	markerData, _ := json.Marshal(marker)
	if e = AtomicWrite(filepath.Join(directory, "identity.json"), markerData, 0644); e != nil {
		return nil, e
	}
	return c, nil
}
func (c *Client) transport(authenticated bool) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.roots}
	if authenticated {
		certData, e := os.ReadFile(filepath.Join(c.Directory, "client.crt"))
		if e != nil {
			return nil, e
		}
		keyData, e := encodeKey(c.key)
		if e != nil {
			return nil, e
		}
		defer clear(keyData)
		pair, e := tls.X509KeyPair(certData, keyData)
		if e != nil {
			return nil, e
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return &http.Client{Timeout: 45 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}, CheckRedirect: func(r *http.Request, via []*http.Request) error { return fmt.Errorf("redirect refused") }}, nil
}
func (c *Client) post(ctx context.Context, path string, in, out any, authenticated bool) error {
	client, e := c.transport(authenticated)
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	data, e := json.Marshal(in)
	if e != nil {
		return e
	}
	defer clear(data)
	req, e := http.NewRequestWithContext(ctx, "POST", c.Endpoint+path, bytes.NewReader(data))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	var sent atomic.Bool
	operation, isOperation := in.(Request)
	uncertain := func(err error) error {
		if isOperation && operation.Operation == "consume" && sent.Load() {
			return fmt.Errorf("%w: %v", ErrUncertainConsumption, err)
		}
		return err
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
		if info.Err == nil {
			sent.Store(true)
		}
	}}))
	res, e := client.Do(req)
	if e != nil {
		return uncertain(fmt.Errorf("key service transport failed: %w", e))
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 65537))
	if e != nil {
		return uncertain(e)
	}
	defer clear(b)
	if len(b) > 65536 {
		return uncertain(fmt.Errorf("service response too large"))
	}
	if res.StatusCode != 200 {
		var failure struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(b, &failure)
		switch failure.Code {
		case "commit-uncertain":
			return ErrUncertainConsumption
		case "consumed":
			return protection.ErrConsumed
		case "missing":
			return protection.ErrMissing
		}
		if res.StatusCode >= 500 {
			return uncertain(fmt.Errorf("key service failed (HTTP %d)", res.StatusCode))
		}
		return fmt.Errorf("key service rejected operation (HTTP %d)", res.StatusCode)
	}
	if e := json.Unmarshal(b, out); e != nil {
		return uncertain(e)
	}
	return nil
}
func (c *Client) Enroll(ctx context.Context) (*EnrollmentResponse, error) {
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "enrollment"}}, c.key)
	if e != nil {
		return nil, e
	}
	req := c.Enrollment
	req.CSR = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	out := &EnrollmentResponse{}
	if e = c.post(ctx, "/v1/enroll", req, out, false); e != nil {
		return nil, e
	}
	if out.ProviderID != c.ProviderID || out.RequestID != c.PrincipalID {
		return nil, fmt.Errorf("enrollment authority mismatch")
	}
	if out.Approved && !out.Revoked {
		cert, e := parseCert([]byte(out.Certificate))
		if e != nil {
			return nil, e
		}
		if _, e = cert.Verify(x509.VerifyOptions{Roots: c.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
			return nil, e
		}
		pub, e := x509.MarshalPKIXPublicKey(c.key.Public())
		if e != nil {
			return nil, e
		}
		if cert.Subject.CommonName != c.PrincipalID || fingerprint(cert.RawSubjectPublicKeyInfo) != fingerprint(pub) {
			return nil, fmt.Errorf("issued identity mismatch")
		}
		if e = AtomicWrite(filepath.Join(c.Directory, "client.crt"), []byte(out.Certificate), 0644); e != nil {
			return nil, e
		}
	}
	return out, nil
}
func (c *Client) Operation(ctx context.Context, r Request) (*Response, error) {
	if r.Operation == "open" {
		if err := protection.RequireProtectedMemory(); err != nil {
			return nil, err
		}
	}
	r.ProviderID = c.ProviderID
	r.ClusterID = c.Enrollment.ClusterID
	out := &Response{}
	if e := c.post(ctx, "/v1/operation", r, out, true); e != nil {
		out.Close()
		return nil, e
	}
	if out.ProviderID != c.ProviderID || out.PrincipalID != c.PrincipalID || out.VMUID != r.VMUID || out.AttemptID != r.AttemptID || out.RestoreVMIUID != r.RestoreVMIUID {
		out.Close()
		if r.Operation == "consume" {
			return nil, ErrUncertainConsumption
		}
		return nil, fmt.Errorf("response identity mismatch")
	}
	return out, nil
}
