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

import "strings"

// ControlChanged includes additions, changes, and removals. VM editors may
// select a state PVC before boot; only KubeVirt service accounts may change
// operation requests, lifecycle state, attempt IDs, and integrity anchors.
func ControlChanged(old, current map[string]string, allowStatePVC bool) bool {
	protected := func(key string) bool {
		return strings.HasPrefix(key, "hibernation.kubevirt.io/") && (!allowStatePVC || key != StatePVCAnnotation)
	}
	for key, value := range old {
		if protected(key) {
			if updated, exists := current[key]; !exists || updated != value {
				return true
			}
		}
	}
	for key := range current {
		if protected(key) {
			if _, exists := old[key]; !exists {
				return true
			}
		}
	}
	return false
}

func Active(annotations map[string]string) bool {
	state := annotations[StateAnnotation]
	return annotations[RequestAnnotation] != "" || (state != "" && state != StateRunning)
}
