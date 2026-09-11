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

package admitters

import (
	"encoding/json"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubevirt.io/kubevirt/pkg/hibernation"
	webhookutils "kubevirt.io/kubevirt/pkg/util/webhooks"
)

func admitHibernationDelete(ar *admissionv1.AdmissionReview, serviceAccounts map[string]struct{}) *admissionv1.AdmissionResponse {
	var previous metav1.PartialObjectMetadata
	if err := json.Unmarshal(ar.Request.OldObject.Raw, &previous); err != nil {
		return webhookutils.ToAdmissionResponseError(err)
	}
	_, trusted := serviceAccounts[ar.Request.UserInfo.Username]
	if !trusted && hibernation.Active(previous.Annotations) {
		return webhookutils.ToAdmissionResponse([]metav1.StatusCause{{
			Type:    metav1.CauseTypeFieldValueNotSupported,
			Message: "cannot delete a VM or VMI while a hibernation attempt is active; complete or recover the attempt first",
			Field:   "metadata.annotations",
		}})
	}
	return &admissionv1.AdmissionResponse{Allowed: true}
}
