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

package solver_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
)

// statusError is the error the Gateway ends a call with: a gRPC status
// with code and message, carrying detail when it is not nil.
func statusError(code codes.Code, msg string, detail *dnsgatev1.Error) error {
	st := status.New(code, msg)
	if detail == nil {
		return st.Err()
	}

	st, err := st.WithDetails(detail)
	if err != nil {
		panic(err)
	}

	return st.Err()
}

// failureCases are a Gateway failure of every kind the webhook names,
// and the message each gives the cert-manager Issuer author.
var failureCases = map[string]struct {
	err  error
	want string
}{
	"unauthenticated": {
		err:  statusError(codes.Unauthenticated, "token not accepted", &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_UNAUTHENTICATED}),
		want: "the Gateway refused the token",
	},
	"permission denied": {
		err: statusError(codes.PermissionDenied, "token may not patch TXT _acme-challenge in zone example.com",
			&dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_PERMISSION_DENIED}),
		want: "token may not patch TXT _acme-challenge in zone example.com",
	},
	"denied by provider": {
		err: statusError(codes.FailedPrecondition, "provider refused",
			&dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_DENIED_BY_PROVIDER, ProviderStatus: 403}),
		want: "the Provider refused the request: 403",
	},
	"denied by provider, no provider status": {
		err:  statusError(codes.FailedPrecondition, "provider refused", &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_DENIED_BY_PROVIDER}),
		want: "the Provider refused the request",
	},
	"invalid record": {
		err:  statusError(codes.InvalidArgument, "ttl out of range", &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_INVALID_RECORD}),
		want: "the Gateway refused TTL 600: check ttl against the Provider's range",
	},
	"conflict": {
		err:  statusError(codes.Aborted, "rrset changed", &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_CONFLICT}),
		want: "the Gateway call failed: conflict",
	},
	"rate limited": {
		err:  statusError(codes.ResourceExhausted, "slow down", &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_RATE_LIMITED}),
		want: "the Gateway call failed: rate limited",
	},
	"internal": {
		err:  statusError(codes.Internal, "boom", &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_INTERNAL}),
		want: "the Gateway call failed: internal",
	},
	"unavailable, no detail": {
		err:  statusError(codes.Unavailable, "connection refused", nil),
		want: "the Gateway call failed: unavailable",
	},
	"deadline exceeded, no detail": {
		err:  statusError(codes.DeadlineExceeded, "context deadline exceeded", nil),
		want: "the Gateway call failed: deadline exceeded",
	},
	"deadline exceeded before the stream opened": {
		err:  context.DeadlineExceeded,
		want: "the Gateway call failed: deadline exceeded",
	},
}

func TestPresentNamesTheCauseOfAGatewayFailure(t *testing.T) {
	for name, tt := range failureCases {
		t.Run(name, func(t *testing.T) {
			s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))
			gw.err = tt.err

			checkError(t, s.Present(challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)), tt.want)
		})
	}
}

func TestPresentNeverRetriesAFailedGatewayCall(t *testing.T) {
	for name, tt := range failureCases {
		t.Run(name, func(t *testing.T) {
			s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))
			gw.err = tt.err

			_ = s.Present(challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`))

			checkOneRequest(t, gw, wantPresent("tok-a", "example.com", "_acme-challenge"))
		})
	}
}

func TestCleanUpNamesNoTTLWhenTheGatewayRefusesTheRecord(t *testing.T) {
	s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))
	gw.err = statusError(codes.InvalidArgument, "bad value "+validKey, &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_INVALID_RECORD})

	checkError(t, s.CleanUp(cleanUpChallenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)), "the Gateway refused the record")
}

func TestAGatewayFailureNeverShowsTheTokenOrTheKey(t *testing.T) {
	const token = "tok-secret-a"

	// echo is a Gateway failure whose own text carries the request's
	// token and key.
	echo := "request token=" + token + " value=" + validKey

	failures := map[string]error{
		"unauthenticated": statusError(codes.Unauthenticated, echo, &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_UNAUTHENTICATED}),
		"denied by provider": statusError(codes.FailedPrecondition, echo,
			&dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_DENIED_BY_PROVIDER, ProviderStatus: 400}),
		"invalid record":        statusError(codes.InvalidArgument, echo, &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_INVALID_RECORD}),
		"invalid request":       statusError(codes.InvalidArgument, echo, &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_INVALID_REQUEST}),
		"internal":              statusError(codes.Internal, echo, &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_INTERNAL}),
		"unavailable":           statusError(codes.Unavailable, echo, nil),
		"not a gRPC status":     errors.New(echo),
		"wrapped context error": fmt.Errorf("%s: %w", echo, context.DeadlineExceeded),
	}

	for name, gwErr := range failures {
		t.Run(name, func(t *testing.T) {
			s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": token}))
			gw.err = gwErr

			err := s.Present(challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`))
			if err == nil {
				t.Fatal("Present = nil, want an error")
			}

			if msg := err.Error(); strings.Contains(msg, token) || strings.Contains(msg, validKey) {
				t.Errorf("error %q shows the token or the key", msg)
			}
		})
	}
}
