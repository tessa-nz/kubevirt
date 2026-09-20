// SPDX-License-Identifier: Apache-2.0
package keyservice

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func serial() *big.Int {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		panic(e)
	}
	return n
}
func encodeKey(key crypto.Signer) ([]byte, error) {
	b, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}
func parseKey(data []byte) (crypto.Signer, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, fmt.Errorf("invalid key encoding")
	}
	k, e := x509.ParsePKCS8PrivateKey(b.Bytes)
	if e != nil {
		return nil, fmt.Errorf("invalid private key")
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("invalid signer")
	}
	return s, nil
}
func parseCert(data []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, fmt.Errorf("invalid certificate encoding")
	}
	return x509.ParseCertificate(b.Bytes)
}
func readPrivate(path string) ([]byte, error) {
	s, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 || !ownedByProcess(s) || s.Size() > 65536 {
		return nil, fmt.Errorf("unsafe private file")
	}
	return os.ReadFile(path)
}
func writePKI(dir, host string) error {
	_, caKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "KubeVirt hibernation key service CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if e != nil {
		return e
	}
	ca, e = x509.ParseCertificate(der)
	if e != nil {
		return e
	}
	keyPEM, e := encodeKey(caKey)
	if e != nil {
		return e
	}
	defer clear(keyPEM)
	if e = AtomicWrite(filepath.Join(dir, "ca.key"), keyPEM, 0600); e != nil {
		return e
	}
	if e = AtomicWrite(filepath.Join(dir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); e != nil {
		return e
	}
	_, serverKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: host}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		cert.IPAddresses = []net.IP{ip}
	} else {
		cert.DNSNames = []string{host}
	}
	der, e = x509.CreateCertificate(rand.Reader, cert, ca, serverKey.Public(), caKey)
	if e != nil {
		return e
	}
	keyPEM, e = encodeKey(serverKey)
	if e != nil {
		return e
	}
	defer clear(keyPEM)
	if e = AtomicWrite(filepath.Join(dir, "server.key"), keyPEM, 0600); e != nil {
		return e
	}
	return AtomicWrite(filepath.Join(dir, "server.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
}
func (s *Service) issue(p *Principal) (string, time.Time, error) {
	pub, e := x509.ParsePKIXPublicKey(p.PublicKey)
	if e != nil {
		return "", time.Time{}, e
	}
	now := s.now()
	if now.Before(s.ca.NotBefore) || !now.Add(30*24*time.Hour).Before(s.ca.NotAfter) {
		return "", time.Time{}, fmt.Errorf("CA trust maintenance required before client renewal")
	}
	cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: p.ID}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, s.ca, pub, s.caKey)
	if e != nil {
		return "", time.Time{}, e
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert.NotAfter, nil
}
func (s *Service) TLSConfig() (*tls.Config, error) {
	certPEM, e := os.ReadFile(filepath.Join(s.dir, "server.crt"))
	if e != nil {
		return nil, e
	}
	keyPEM, e := readPrivate(filepath.Join(s.dir, "server.key"))
	if e != nil {
		return nil, e
	}
	defer clear(keyPEM)
	pair, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.ca)
	_ = pair // Validate the initial pair before opening a listener.
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		certPEM, e := os.ReadFile(filepath.Join(s.dir, "server.crt"))
		if e != nil {
			return nil, e
		}
		keyPEM, e := readPrivate(filepath.Join(s.dir, "server.key"))
		if e != nil {
			return nil, e
		}
		defer clear(keyPEM)
		pair, e := tls.X509KeyPair(certPEM, keyPEM)
		return &pair, e
	}, ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven, SessionTicketsDisabled: true}, nil
}

// RenewServerCertificate retains the server key and CA, so replacing the one
// public certificate file is atomic for both existing and new connections.
func (s *Service) RenewServerCertificate() (time.Time, error) {
	oldPEM, e := os.ReadFile(filepath.Join(s.dir, "server.crt"))
	if e != nil {
		return time.Time{}, e
	}
	old, e := parseCert(oldPEM)
	if e != nil {
		return time.Time{}, e
	}
	keyPEM, e := readPrivate(filepath.Join(s.dir, "server.key"))
	if e != nil {
		return time.Time{}, e
	}
	defer clear(keyPEM)
	key, e := parseKey(keyPEM)
	if e != nil {
		return time.Time{}, e
	}
	now := s.now()
	expiry := now.AddDate(1, 0, 0)
	if expiry.After(s.ca.NotAfter) {
		expiry = s.ca.NotAfter
	}
	if !expiry.After(now.Add(24 * time.Hour)) {
		return time.Time{}, fmt.Errorf("CA renewal requires planned trust maintenance")
	}
	cert := &x509.Certificate{SerialNumber: serial(), Subject: old.Subject, DNSNames: old.DNSNames, IPAddresses: old.IPAddresses, NotBefore: now.Add(-time.Minute), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, s.ca, key.Public(), s.caKey)
	if e != nil {
		return time.Time{}, e
	}
	e = AtomicWrite(filepath.Join(s.dir, "server.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
	return expiry, e
}

func ownedByProcess(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
