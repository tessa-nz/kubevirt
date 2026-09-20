// SPDX-License-Identifier: Apache-2.0
package keyservice

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"kubevirt.io/kubevirt/pkg/hibernation/protection"
)

var ErrUncertainConsumption = errors.New("remote consumption outcome is uncertain")

const RemoteProvider = protection.RemoteProvider
const RegistrationAnnotation = "hibernation.kubevirt.io/key-registration"
const ClientDirectory = "/var/lib/kubevirt/hibernation-client"

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,127}$`)

func validID(s string) bool       { return identifier.MatchString(s) }
func fingerprint(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type Enrollment struct {
	ClusterID       string `json:"clusterID"`
	NodeUID         string `json:"nodeUID"`
	RegistrationUID string `json:"registrationUID"`
	CSR             string `json:"csr"`
}

func (e Enrollment) Validate() error {
	if !validID(e.ClusterID) || !validID(e.NodeUID) || !validID(e.RegistrationUID) {
		return fmt.Errorf("invalid enrollment identity")
	}
	return nil
}

type Grant struct {
	ClusterID string `json:"clusterID"`
	VMUID     string `json:"vmUID"`
}
type Principal struct {
	ID              string  `json:"id"`
	ClusterID       string  `json:"clusterID"`
	NodeUID         string  `json:"nodeUID"`
	RegistrationUID string  `json:"registrationUID"`
	Fingerprint     string  `json:"fingerprint"`
	PublicKey       []byte  `json:"publicKey"`
	Approved        bool    `json:"approved"`
	Revoked         bool    `json:"revoked"`
	Grants          []Grant `json:"grants"`
}
type EnrollmentResponse struct {
	RequestID   string    `json:"requestID"`
	ProviderID  string    `json:"providerID"`
	Fingerprint string    `json:"fingerprint"`
	Approved    bool      `json:"approved"`
	Revoked     bool      `json:"revoked"`
	Certificate string    `json:"certificate,omitempty"`
	ExpiresAt   time.Time `json:"expiresAt,omitempty"`
	Grants      []Grant   `json:"grants,omitempty"`
}
type Request struct {
	Operation      string `json:"operation"`
	ClusterID      string `json:"clusterID"`
	VMUID          string `json:"vmUID"`
	AttemptID      string `json:"attemptID"`
	ProviderID     string `json:"providerID"`
	KeyID          string `json:"keyID,omitempty"`
	RestoreVMIUID  string `json:"restoreVMIUID,omitempty"`
	ArtifactDigest string `json:"artifactDigest,omitempty"`
}

func (r Request) attempt() protection.Attempt {
	return protection.Attempt{VMUID: r.VMUID, ID: r.AttemptID}
}
func (r Request) dbKey() string { return r.ClusterID + "/" + r.VMUID + "/" + r.AttemptID }
func (r Request) Validate() error {
	if !validID(r.ClusterID) || !validID(r.VMUID) || !validID(r.AttemptID) || r.ProviderID == "" {
		return fmt.Errorf("invalid attempt identity")
	}
	switch r.Operation {
	case "create", "status", "abandon", "discard":
	case "open", "consume", "finalize":
		if r.KeyID == "" {
			return fmt.Errorf("key identity required")
		}
	default:
		return fmt.Errorf("unknown operation")
	}
	if r.Operation == "finalize" && !validID(r.RestoreVMIUID) {
		return fmt.Errorf("restore VMI identity required for finalization")
	}
	if r.Operation == "open" || r.Operation == "consume" {
		if !validID(r.RestoreVMIUID) || len(r.ArtifactDigest) != 64 {
			return fmt.Errorf("restore identity and artifact digest required")
		}
		if _, err := hex.DecodeString(r.ArtifactDigest); err != nil {
			return fmt.Errorf("invalid artifact digest")
		}
	}
	return nil
}

type Response struct {
	ProviderID      string               `json:"providerID"`
	PrincipalID     string               `json:"principalID"`
	VMUID           string               `json:"vmUID"`
	AttemptID       string               `json:"attemptID"`
	RestoreVMIUID   string               `json:"restoreVMIUID,omitempty"`
	Key             protection.PublicKey `json:"key"`
	PrivateIdentity []byte               `json:"privateIdentity,omitempty"`
	Fresh           bool                 `json:"fresh"`
	Erased          bool                 `json:"erased"`
	State           string               `json:"state"`
}

func (Response) String() string   { return "hibernation service response [key material redacted]" }
func (Response) GoString() string { return "hibernation service response [key material redacted]" }
func (r *Response) Close()        { clear(r.PrivateIdentity); r.PrivateIdentity = nil }

type AttemptRecord struct {
	UpdatedAt   time.Time            `json:"updatedAt"`
	Request     Request              `json:"request"`
	PrincipalID string               `json:"principalID"`
	Key         protection.PublicKey `json:"key"`
	State       string               `json:"state"`
}
type State struct {
	Version    int                       `json:"version"`
	ProviderID string                    `json:"providerID"`
	Principals map[string]*Principal     `json:"principals"`
	Attempts   map[string]*AttemptRecord `json:"attempts"`
}
type Backend interface {
	Create(protection.Attempt) (protection.PublicKey, error)
	Open(protection.Attempt) (*protection.PrivateKey, error)
	Consume(protection.Attempt) (bool, error)
	Destroy(protection.Attempt) error
	Abandon(protection.Attempt) error
	Discard(protection.Attempt) error
	Inspect(protection.Attempt) (protection.AttemptStatus, error)
}
