/*
Copyright 2026 DNS Gateway Team.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package solver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
)

// gatewayFailure is a failed Gateway call. Its message, which cert-manager
// shows in the Challenge's status, names the cause and never carries the
// token, the challenge key or anything else from the request but the
// TTL; of the Gateway's reply it carries only the message of a
// Permission refusal.
type gatewayFailure struct {
	msg string
	err error
}

func (e *gatewayFailure) Error() string { return e.msg }

func (e *gatewayFailure) Unwrap() error { return e.err }

// gatewayFailed returns the error for err, the error a Gateway call sent
// with ttl ended with. It goes by the Gateway's error category and, when
// there is none, as for a failed connection or a deadline, by the gRPC
// code.
func gatewayFailed(err error, ttl uint32) error {
	st := gatewayStatus(err)

	detail := dnsgatev1.ErrorDetail(st)
	if detail == nil {
		return &gatewayFailure{msg: "the Gateway call failed: " + codeName(st.Code()), err: err}
	}

	var msg string

	switch c := detail.GetCategory(); c {
	case dnsgatev1.Error_CATEGORY_UNAUTHENTICATED:
		msg = "the Gateway refused the token"
	case dnsgatev1.Error_CATEGORY_PERMISSION_DENIED:
		msg = st.Message()
	case dnsgatev1.Error_CATEGORY_DENIED_BY_PROVIDER:
		msg = fmt.Sprintf("the Provider refused the request: %d", detail.GetProviderStatus())
	case dnsgatev1.Error_CATEGORY_INVALID_RECORD:
		msg = fmt.Sprintf("the Gateway refused TTL %d: check ttl against the Provider's range", ttl)
	default:
		msg = "the Gateway call failed: " + strings.ReplaceAll(c.Name(), "_", " ")
	}

	return &gatewayFailure{msg: msg, err: err}
}

// gatewayStatus returns the gRPC status of err. A context error that
// ended the call before the Gateway answered maps to its gRPC code.
func gatewayStatus(err error) *status.Status {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return status.FromContextError(err)
	}

	return status.Convert(err)
}

// codeName returns code in lower case with spaces, such as "deadline
// exceeded".
func codeName(code codes.Code) string {
	var b strings.Builder

	for i, r := range code.String() {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte(' ')
		}

		b.WriteRune(r)
	}

	return strings.ToLower(b.String())
}
