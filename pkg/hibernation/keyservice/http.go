// SPDX-License-Identifier: Apache-2.0
package keyservice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/time/rate"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return fmt.Errorf("invalid request")
	}
	var trailing any
	if e := d.Decode(&trailing); e != io.EOF {
		return fmt.Errorf("invalid trailing data")
	}
	return nil
}
func reply(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": errorCode(err), "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}
func certificate(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}
func (s *Service) Handler() http.Handler {
	var requests, failures atomic.Uint64
	// A global bound keeps unauthenticated enrollment from creating unlimited
	// signing work. Persistent pending records have a separate capacity limit.
	slots := make(chan struct{}, 8)
	enrollLimit := rate.NewLimiter(rate.Every(time.Second), 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", 429)
			return
		}
		switch r.URL.Path {
		case "/v1/enroll":
			if !enrollLimit.Allow() {
				http.Error(w, "enrollment rate limit", 429)
				return
			}
			if r.Method != "POST" {
				http.Error(w, "method", 405)
				return
			}
			var req Enrollment
			if e := decode(w, r, &req); e != nil {
				reply(w, nil, e)
				return
			}
			out, e := s.Enroll(req)
			if e != nil {
				failures.Add(1)
			}
			reply(w, out, e)
		case "/v1/operation":
			if r.Method != "POST" {
				http.Error(w, "method", 405)
				return
			}
			if certificate(r) == nil {
				http.Error(w, "client certificate required", 401)
				return
			}
			var req Request
			if e := decode(w, r, &req); e != nil {
				reply(w, nil, e)
				return
			}
			out, e := s.Operate(certificate(r), req)
			if out != nil {
				defer out.Close()
			}
			if e != nil {
				failures.Add(1)
			}
			reply(w, out, e)
		case "/healthz":
			if r.Method != "GET" {
				http.Error(w, "method", 405)
				return
			}
			out, e := s.publicState()
			reply(w, out, e)
		case "/metrics":
			if r.Method != "GET" {
				http.Error(w, "method", 405)
				return
			}
			s.mu.Lock()
			st, e := readState(s.db)
			if e == nil {
				_, e = s.approved(st, certificate(r))
			}
			s.mu.Unlock()
			if e != nil {
				http.Error(w, "not authorized", 403)
				return
			}
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			pending, revoked := 0, 0
			for _, p := range st.Principals {
				if p.Revoked {
					revoked++
				} else if !p.Approved {
					pending++
				}
			}
			oldestStuck := float64(0)
			active := 0
			for _, a := range st.Attempts {
				if (a.State == "creating" || a.State == "erasing" || a.State == "consumed") && !a.UpdatedAt.IsZero() {
					age := time.Since(a.UpdatedAt).Seconds()
					if age > oldestStuck {
						oldestStuck = age
					}
				}
				if a.State != "erased" {
					active++
				}
			}
			fmt.Fprintf(w, "hibernation_key_service_pending_enrollments %d\nhibernation_key_service_revoked_clients %d\nhibernation_key_service_stuck_attempt_age_seconds %g\nhibernation_key_service_ca_expiry_timestamp_seconds %d\n", pending, revoked, oldestStuck, s.ca.NotAfter.Unix())
			if bytes, err := os.ReadFile(s.dir + "/server.crt"); err == nil {
				if cert, err := parseCert(bytes); err == nil {
					fmt.Fprintf(w, "hibernation_key_service_server_certificate_expiry_timestamp_seconds %d\n", cert.NotAfter.Unix())
				}
			}
			if backend, ok := s.backend.(interface{ PersistentCapacity() (uint32, error) }); ok {
				capacity, err := backend.PersistentCapacity()
				healthy := 1
				if err != nil {
					healthy = 0
				}
				fmt.Fprintf(w, "hibernation_key_service_tpm_reachable %d\nhibernation_key_service_tpm_persistent_slots_available %d\n", healthy, capacity)
			}
			fmt.Fprintf(w, "hibernation_key_service_up 1\nhibernation_key_service_requests_total %d\nhibernation_key_service_failures_total %d\nhibernation_key_service_active_attempts %d\n", requests.Load(), failures.Load(), active)
		default:
			http.NotFound(w, r)
		}
	})
}
func (s *Service) AdminHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/admin" {
			http.NotFound(w, r)
			return
		}
		var req AdminRequest
		if e := decode(w, r, &req); e != nil {
			reply(w, nil, e)
			return
		}
		out, e := s.Admin(req)
		reply(w, out, e)
	})
}
func server(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
}
func (s *Service) Serve(ctx context.Context, address, socket, allowedCIDRs string) error {
	prefixes, e := allowedPrefixes(address, allowedCIDRs)
	if e != nil {
		return e
	}
	if st, e := os.Lstat(socket); e == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("admin socket path occupied")
		}
		conn, e := net.DialTimeout("unix", socket, time.Second)
		if e == nil {
			conn.Close()
			return fmt.Errorf("admin service already running")
		}
		if e = os.Remove(socket); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	adminListener, e := net.Listen("unix", socket)
	if e != nil {
		return e
	}
	defer adminListener.Close()
	if e = os.Chmod(socket, 0600); e != nil {
		return e
	}
	tlsConfig, e := s.TLSConfig()
	if e != nil {
		return e
	}
	listener, e := net.Listen("tcp", address)
	if e != nil {
		return e
	}
	defer listener.Close()
	publicListener := tls.NewListener(&allowedListener{Listener: listener, prefixes: prefixes}, tlsConfig)
	public := server(s.Handler())
	public.Addr = address
	public.TLSConfig = tlsConfig
	admin := server(s.AdminHandler())
	errs := make(chan error, 2)
	go func() { errs <- admin.Serve(adminListener) }()
	go func() { errs <- public.Serve(publicListener) }()
	select {
	case <-ctx.Done():
		e = nil
	case e = <-errs:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	public.Shutdown(shutdown)
	admin.Shutdown(shutdown)
	return e
}
