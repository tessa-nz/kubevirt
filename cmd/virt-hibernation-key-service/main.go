// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"filippo.io/age"
	"kubevirt.io/kubevirt/pkg/hibernation/keyservice"
	"kubevirt.io/kubevirt/pkg/hibernation/protection"
)

func run() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("service and local administrative/client operations require root")
	}
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: virt-hibernation-key-service init|serve|admin|inspect-offline|client-enroll|client-operation [flags]")
	}
	action := os.Args[1]
	f := flag.NewFlagSet(action, flag.ContinueOnError)
	dir := f.String("state-dir", "/state", "private persistent directory")
	host := f.String("hostname", "nas.home.hawara.nz", "server certificate hostname")
	allowedCIDRs := f.String("allow-client-cidrs", "", "comma-separated Orion host CIDRs; required for a non-loopback listener")
	address := f.String("listen", ":19443", "HTTPS listen address")
	endpoint := f.String("endpoint", "", "trusted HTTPS origin")
	caFile := f.String("ca-file", "", "public CA bundle")
	provider := f.String("provider-id", "", "pinned TPM provider identity")
	cluster := f.String("cluster-id", "", "cluster UID")
	node := f.String("node-uid", "", "node UID")
	registration := f.String("registration-uid", "", "registration UID")
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	if action == "inspect-offline" {
		state, e := keyservice.RecoveryMetadata(*dir)
		if e != nil {
			return e
		}
		store := protection.NewNodeTPMStore(filepath.Join(*dir, "tpm.lock"))
		actual, identityErr := store.ProviderIdentity()
		observations := map[string]any{}
		var attempts []protection.Attempt
		for id, a := range state.Attempts {
			if a.State == "erased" {
				continue
			}
			attempt := protection.Attempt{VMUID: a.Request.VMUID, ID: a.Request.AttemptID}
			attempts = append(attempts, attempt)
			status, err := store.Inspect(attempt)
			if err != nil {
				observations[id] = map[string]string{"error": err.Error()}
			} else {
				observations[id] = status
			}
		}
		report := map[string]any{"metadata": state, "actualProviderID": actual, "providerMatches": identityErr == nil && actual == state.ProviderID, "attempts": observations}
		if identityErr != nil {
			report["identityError"] = identityErr.Error()
		}
		if err := store.CheckInventory(attempts); err != nil {
			report["inventoryError"] = err.Error()
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	if action == "admin" {
		client := http.Client{Timeout: time.Minute, Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(*dir, "admin.sock"))
		}}}
		data, e := io.ReadAll(io.LimitReader(os.Stdin, 32769))
		if e != nil {
			return e
		}
		if len(data) > 32768 {
			return fmt.Errorf("request too large")
		}
		res, e := client.Post("http://admin/v1/admin", "application/json", bytes.NewReader(data))
		if e != nil {
			return e
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("administrative request rejected (HTTP %d)", res.StatusCode)
		}
		_, e = io.Copy(os.Stdout, io.LimitReader(res.Body, 1048576))
		return e
	}
	if action == "client-enroll" || action == "client-operation" {
		if e := protection.RequireProtectedMemory(); e != nil {
			return e
		}
		ca, e := os.ReadFile(*caFile)
		if e != nil {
			return e
		}
		client, e := keyservice.NewClient(*endpoint, *provider, string(ca), *dir, keyservice.Enrollment{ClusterID: *cluster, NodeUID: *node, RegistrationUID: *registration})
		if e != nil {
			return e
		}
		if action == "client-enroll" {
			out, e := client.Enroll(context.Background())
			if e != nil {
				return e
			}
			return json.NewEncoder(os.Stdout).Encode(out)
		}
		var request keyservice.Request
		if e = json.NewDecoder(io.LimitReader(os.Stdin, 32768)).Decode(&request); e != nil {
			return e
		}
		out, e := client.Operation(context.Background(), request)
		if e != nil {
			return e
		}
		defer out.Close()
		// Diagnostic clients never print private key responses. Verify a small
		// in-memory encryption round trip instead, then erase the returned bytes.
		verified := false
		if len(out.PrivateIdentity) > 0 {
			identity, e := age.ParseX25519Identity(string(out.PrivateIdentity))
			if e != nil {
				return fmt.Errorf("invalid returned identity")
			}
			if identity.Recipient().String() != out.Key.Recipient {
				return fmt.Errorf("public/private key mismatch")
			}
			var encrypted bytes.Buffer
			w, e := age.Encrypt(&encrypted, identity.Recipient())
			if e != nil {
				return e
			}
			if _, e = w.Write([]byte("disposable service probe")); e != nil {
				return e
			}
			if e = w.Close(); e != nil {
				return e
			}
			r, e := age.Decrypt(&encrypted, identity)
			if e != nil {
				return e
			}
			plaintext, e := io.ReadAll(r)
			if e != nil {
				return e
			}
			verified = string(plaintext) == "disposable service probe"
			clear(plaintext)
			if !verified {
				return fmt.Errorf("key round trip failed")
			}
		}
		out.Close()
		return json.NewEncoder(os.Stdout).Encode(struct {
			Result      *keyservice.Response `json:"result"`
			KeyVerified bool                 `json:"keyVerified"`
		}{out, verified})
	}
	store := protection.NewNodeTPMStore(filepath.Join(*dir, "tpm.lock"))
	id, e := store.ProviderIdentity()
	if e != nil {
		return e
	}
	switch action {
	case "init":
		if e = store.CheckInventory(nil); e != nil {
			return e
		}
		if e = keyservice.Initialize(*dir, *host, id); e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"providerID": id, "caFile": filepath.Join(*dir, "ca.crt")})
	case "serve":
		service, e := keyservice.New(*dir, id, store)
		if e != nil {
			return e
		}
		defer service.Close()
		attempts, e := service.ActiveAttempts()
		if e != nil {
			return e
		}
		if e = store.CheckInventory(attempts); e != nil {
			return e
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return service.Serve(ctx, *address, filepath.Join(*dir, "admin.sock"), *allowedCIDRs)
	default:
		return fmt.Errorf("unknown command")
	}
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
