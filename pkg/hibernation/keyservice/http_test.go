// SPDX-License-Identifier: Apache-2.0
package keyservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestMTLSRevocationOnExistingConnection(t *testing.T) {
	s, _ := fixture(t)
	cfg, e := s.TLSConfig()
	if e != nil {
		t.Fatal(e)
	}
	addresses := map[string]bool{}
	var mu sync.Mutex
	handler := s.Handler()
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.URL.Path == "/v1/operation" && certificate(r) != nil {
			addresses[r.RemoteAddr] = true
		}
		mu.Unlock()
		handler.ServeHTTP(w, r)
	})
	ts := httptest.NewUnstartedServer(wrapped)
	ts.TLS = cfg
	ts.Listener = tls.NewListener(ts.Listener, cfg)
	ts.Start()
	ts.URL = strings.Replace(ts.URL, "http://", "https://", 1)
	defer ts.Close()
	ca, e := os.ReadFile(filepath.Join(s.dir, "ca.crt"))
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(t.TempDir(), "identity")
	c, e := NewClient(ts.URL, "provider", string(ca), dir, Enrollment{ClusterID: "cluster", NodeUID: "node", RegistrationUID: "registration"})
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	pending, e := c.Enroll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Operation(ctx, request("create")); e == nil {
		t.Fatal("unapproved client accepted")
	}
	if _, e = s.Admin(AdminRequest{Operation: "approve", RequestID: pending.RequestID, Fingerprint: pending.Fingerprint}); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Enroll(ctx); e != nil {
		t.Fatal(e)
	}
	certBytes, e := os.ReadFile(filepath.Join(dir, "client.crt"))
	if e != nil {
		t.Fatal(e)
	}
	cert, e := parseCert(certBytes)
	if e != nil {
		t.Fatal(e)
	}
	grant(t, s, cert)
	authenticated, e := c.transport(true)
	if e != nil {
		t.Fatal(e)
	}
	defer authenticated.CloseIdleConnections()
	tr := authenticated.Transport.(*http.Transport)
	tr.DisableKeepAlives = false

	send := func() int {
		t.Helper()
		b, _ := json.Marshal(request("create"))
		r, e := authenticated.Post(ts.URL+"/v1/operation", "application/json", bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		return r.StatusCode
	}
	if code := send(); code != 200 {
		t.Fatalf("approved call=%d", code)
	}
	if _, e = s.Admin(AdminRequest{Operation: "revoke", RequestID: pending.RequestID}); e != nil {
		t.Fatal(e)
	}
	if code := send(); code == 200 {
		t.Fatal("revocation bypassed")
	}
	mu.Lock()
	n := len(addresses)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("test did not reuse connection: %d", n)
	}
	// Enrollment is allowed without a certificate, key operations are not.
	anonymous, e := c.transport(false)
	if e != nil {
		t.Fatal(e)
	}
	defer anonymous.CloseIdleConnections()
	r, e := anonymous.Post(ts.URL+"/v1/operation", "application/json", bytes.NewReader([]byte(`{}`)))
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatal("anonymous key request accepted")
	}
	wrong, e := NewClient(ts.URL, "other-provider", string(ca), filepath.Join(t.TempDir(), "identity"), c.Enrollment)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = wrong.Enroll(ctx); e == nil {
		t.Fatal("wrong provider accepted")
	}
	bad := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}}
	defer bad.CloseIdleConnections()
	if r, e := bad.Get(ts.URL + "/healthz"); e == nil {
		r.Body.Close()
		t.Fatal("unknown CA accepted")
	}
}
func TestConcurrentClientIdentityAndLostKey(t *testing.T) {
	s, _ := fixture(t)
	ca, e := os.ReadFile(filepath.Join(s.dir, "ca.crt"))
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(t.TempDir(), "identity")
	var wg sync.WaitGroup
	ids := make(chan string, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := NewClient("https://localhost", "provider", string(ca), dir, Enrollment{ClusterID: "cluster", NodeUID: "node", RegistrationUID: "registration"})
			if e != nil {
				errs <- e
				return
			}
			ids <- c.PrincipalID
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	id := ""
	for other := range ids {
		if id != "" && id != other {
			t.Fatal("concurrent initialization replaced key")
		}
		id = other
	}
	if e = os.Remove(filepath.Join(dir, "client.key")); e != nil {
		t.Fatal(e)
	}
	if _, e = NewClient("https://localhost", "provider", string(ca), dir, Enrollment{ClusterID: "cluster", NodeUID: "node", RegistrationUID: "registration"}); e == nil {
		t.Fatal("lost key silently replaced")
	}
}

func TestListenerRequiresExplicitNetworkBoundary(t *testing.T) {
	for _, tc := range []struct {
		address, allowed string
		ok               bool
	}{
		{"127.0.0.1:19444", "", true}, {":19443", "", false}, {":19443", "0.0.0.0/0", false}, {":19443", "::/0", false}, {":19443", "172.23.0.2/32,172.23.0.3/32", true},
	} {
		_, e := allowedPrefixes(tc.address, tc.allowed)
		if (e == nil) != tc.ok {
			t.Fatalf("%s %s: %v", tc.address, tc.allowed, e)
		}
	}
}

func TestLostConsumptionResponseIsUncertainAndCannotReplay(t *testing.T) {
	s, b := fixture(t)
	cfg, e := s.TLSConfig()
	if e != nil {
		t.Fatal(e)
	}
	normal := s.Handler()
	var dropped atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/operation" {
			data, e := io.ReadAll(r.Body)
			if e != nil {
				t.Error(e)
				return
			}
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(data))
			var req Request
			if e = json.Unmarshal(data, &req); e != nil {
				t.Error(e)
				return
			}
			if req.Operation == "consume" && dropped.CompareAndSwap(false, true) {
				out, e := s.Operate(certificate(r), req)
				if e != nil {
					t.Error(e)
					return
				}
				out.Close()
				connection, _, e := w.(http.Hijacker).Hijack()
				if e != nil {
					t.Error(e)
					return
				}
				connection.Close()
				return
			}
		}
		normal.ServeHTTP(w, r)
	})
	ts := httptest.NewUnstartedServer(handler)
	ts.Listener = tls.NewListener(ts.Listener, cfg)
	ts.Start()
	defer ts.Close()
	ts.URL = strings.Replace(ts.URL, "http://", "https://", 1)
	ca, e := os.ReadFile(filepath.Join(s.dir, "ca.crt"))
	if e != nil {
		t.Fatal(e)
	}
	c, e := NewClient(ts.URL, "provider", string(ca), filepath.Join(t.TempDir(), "identity"), Enrollment{ClusterID: "cluster", NodeUID: "node", RegistrationUID: "registration"})
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	pending, e := c.Enroll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Admin(AdminRequest{Operation: "approve", RequestID: pending.RequestID, Fingerprint: pending.Fingerprint}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Admin(AdminRequest{Operation: "grant", RequestID: pending.RequestID, Grant: Grant{ClusterID: "cluster", VMUID: "vm"}}); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Enroll(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Operation(ctx, request("create")); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Operation(ctx, request("consume")); !errors.Is(e, ErrUncertainConsumption) {
		t.Fatalf("lost response did not mark uncertainty: %v", e)
	}
	out, e := c.Operation(ctx, request("consume"))
	if e != nil {
		t.Fatal(e)
	}
	defer out.Close()
	if out.Fresh || !b.status.Consumed {
		t.Fatal("lost response replayed fresh authorization")
	}
}
