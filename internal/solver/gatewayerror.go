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
	"unicode"

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

// newGatewayFailure returns the error for err, the error a Gateway call
// sent with ttl ended with.
func newGatewayFailure(err error, ttl uint32) error {
	return &gatewayFailure{msg: failureMessage(callStatus(err), ttl), err: err}
}

// failureMessage returns the message for a Gateway call sent with ttl
// that ended with st. It goes by the Gateway's error category and, when
// there is none, as for a failed connection or a deadline, by the gRPC
// code.
func failureMessage(st *status.Status, ttl uint32) string {
	var cause string

	switch detail := dnsgatev1.ErrorDetail(st); detail.GetCategory() {
	case dnsgatev1.Error_CATEGORY_UNAUTHENTICATED:
		return "the Gateway refused the token"
	case dnsgatev1.Error_CATEGORY_PERMISSION_DENIED:
		return st.Message()
	case dnsgatev1.Error_CATEGORY_DENIED_BY_PROVIDER:
		if ps := detail.GetProviderStatus(); ps != 0 {
			return fmt.Sprintf("the Provider refused the request: %d", ps)
		}

		return "the Provider refused the request"
	case dnsgatev1.Error_CATEGORY_INVALID_RECORD:
		return fmt.Sprintf("the Gateway refused TTL %d: check ttl against the Provider's range", ttl)
	default:
		cause = st.Code().String()
		if detail != nil {
			cause = detail.GetCategory().Name()
		}
	}

	return "the Gateway call failed: " + words(cause)
}

// callStatus returns the gRPC status of err. A context error that ended
// the call before the Gateway answered maps to its gRPC code.
func callStatus(err error) *status.Status {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return status.FromContextError(err)
	}

	return status.Convert(err)
}

// words returns name, a CamelCase name such as "DeadlineExceeded" or an
// upper-case one such as "RATE_LIMITED", as lower-case words separated by
// spaces: "deadline exceeded", "rate limited".
func words(name string) string {
	var b strings.Builder

	prev := rune(0)
	for _, r := range name {
		switch {
		case r == '_':
			r = ' '
		case unicode.IsUpper(r) && unicode.IsLower(prev):
			b.WriteByte(' ')
		}

		b.WriteRune(unicode.ToLower(r))
		prev = r
	}

	return b.String()
}
