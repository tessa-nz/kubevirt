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

import "errors"

// Rejection reports an observed lifecycle failure. Transport failures and
// failed observations must not be converted into a Rejection: their outcome
// remains unknown until the same idempotent operation is reconciled again.
type Rejection struct {
	Phase string
	Err   error
}

func (e *Rejection) Error() string { return e.Err.Error() }
func (e *Rejection) Unwrap() error { return e.Err }

func Reject(phase string, err error) error {
	return &Rejection{Phase: phase, Err: err}
}

func RejectionPhase(err error) string {
	var rejection *Rejection
	if errors.As(err, &rejection) {
		return rejection.Phase
	}
	return ""
}
