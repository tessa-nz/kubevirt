// SPDX-License-Identifier: Apache-2.0
package hibernation

import "testing"

func TestLocalArtifactDigestRetainsPreRemoteInterpretation(t *testing.T) {
	m := Metadata{FormatVersion: 2, Completed: true, AttemptID: "attempt", VMUID: "vm", ProtectionProvider: "tpm2-persistent-age-x25519-v1", ProtectionKeyID: "key", ProtectionRecipient: "recipient"}
	digest, e := ArtifactDigest(m)
	if e != nil {
		t.Fatal(e)
	}
	// Computed using the unmodified 25c55ec local-provider implementation.
	if digest != "e197653fa09281503f454a5398150793845877475d091324af5bbf1d088c6a4f" {
		t.Fatal("existing local artifact digest interpretation changed")
	}
}
