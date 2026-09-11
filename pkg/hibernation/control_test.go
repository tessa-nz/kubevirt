/*
 * This file is part of the KubeVirt project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright The KubeVirt Authors.
 */

package hibernation

import "testing"

func TestControlAnnotationsCannotBeForgedChangedOrRemoved(t *testing.T) {
	for _, key := range []string{RequestAnnotation, StateAnnotation, AttemptAnnotation, ArtifactDigestAnnotation, LabAllowKernelMismatchAnnotation, LabFailAfterConsumeAnnotation} {
		for _, change := range []struct{ old, current map[string]string }{
			{nil, map[string]string{key: "forged"}},
			{map[string]string{key: "original"}, map[string]string{key: "forged"}},
			{map[string]string{key: "original"}, nil},
		} {
			if !ControlChanged(change.old, change.current, true) {
				t.Fatalf("did not protect %s", key)
			}
		}
	}
	if ControlChanged(map[string]string{StateAnnotation: StateHibernated}, map[string]string{StateAnnotation: StateHibernated, "description": "updated"}, true) {
		t.Fatal("unrelated metadata update was rejected")
	}
}

func TestStatePVCSelectionIsAllowedOnlyBeforeAnAttempt(t *testing.T) {
	if ControlChanged(nil, map[string]string{StatePVCAnnotation: "state"}, true) {
		t.Fatal("initial VM state-volume configuration must be permitted")
	}
	if !ControlChanged(map[string]string{StatePVCAnnotation: "original"}, map[string]string{StatePVCAnnotation: "substitute"}, false) {
		t.Fatal("active state-volume substitution must be rejected")
	}
}

func TestArtifactDigestBindsImmutableStateAndAllowsConsumption(t *testing.T) {
	original := Metadata{AttemptID: "attempt", StateSHA256: "original-memory", DomainXMLHash: "domain", Completed: true}
	digest, err := ArtifactDigest(original)
	if err != nil {
		t.Fatal(err)
	}
	consumed := original
	consumed.Consumed = true
	consumed.ConsumedAt = "2026-09-12T00:00:00Z"
	got, err := ArtifactDigest(consumed)
	if err != nil || got != digest {
		t.Fatal("consumption changed the saved artifact identity")
	}
	forged := original
	forged.StateSHA256 = "forged-memory"
	got, err = ArtifactDigest(forged)
	if err != nil || got == digest {
		t.Fatal("memory substitution retained the artifact identity")
	}
}
