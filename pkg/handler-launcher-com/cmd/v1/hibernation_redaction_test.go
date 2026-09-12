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

package v1

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
)

func TestHibernationPrivateIdentityOnlyUsesBinaryRPC(t *testing.T) {
	secret := "test-only-private-identity"
	context := &HibernationProtection{Provider: "test", PrivateIdentity: []byte(secret)}
	request := &HibernationRequest{Protection: context}
	for _, message := range []any{context, request, *context, *request} {
		for _, rendered := range []string{fmt.Sprintf("%v", message), fmt.Sprintf("%+v", message), fmt.Sprintf("%#v", message), message.(fmt.Stringer).String()} {
			if strings.Contains(rendered, secret) || strings.Contains(rendered, base64.StdEncoding.EncodeToString([]byte(secret))) {
				t.Fatal("private identity escaped through formatting")
			}
		}
		payload, err := json.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(payload, []byte(secret)) || bytes.Contains(payload, []byte(base64.StdEncoding.EncodeToString([]byte(secret)))) {
			t.Fatal("private identity escaped through JSON")
		}
	}
	payload, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded HibernationRequest
	if err := proto.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Protection.PrivateIdentity, context.PrivateIdentity) {
		t.Fatal("binary RPC did not preserve the private identity")
	}
}
