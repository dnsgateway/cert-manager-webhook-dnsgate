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
	"testing"

	"google.golang.org/grpc/codes"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
)

func TestEachCallWritesTheChallengeTargetRelativeToTheConfiguredZone(t *testing.T) {
	tests := map[string]struct {
		zone     string
		fqdn     string
		wantZone string
		wantName string
	}{
		"zone above the resolved one": {
			zone: "example.com", fqdn: "_acme-challenge.www.example.com.",
			wantZone: "example.com", wantName: "_acme-challenge.www",
		},
		"zone with a trailing dot": {
			zone: "example.com.", fqdn: "_acme-challenge.www.example.com.",
			wantZone: "example.com", wantName: "_acme-challenge.www",
		},
		"zone in another case": {
			zone: "Example.COM", fqdn: "_acme-challenge.www.example.com.",
			wantZone: "Example.COM", wantName: "_acme-challenge.www",
		},
		"apex": {
			zone: "_acme-challenge.www.example.com", fqdn: "_acme-challenge.www.example.com.",
			wantZone: "_acme-challenge.www.example.com", wantName: "@",
		},
	}

	for callName, sc := range solverCalls {
		for name, tt := range tests {
			t.Run(callName+"/"+name, func(t *testing.T) {
				s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

				// cert-manager resolved a zone other than the configured one,
				// as with split-horizon DNS.
				ch := sc.challenge(`{"tokenSecretRef":{"name":"dnsgate"},"zone":"` + tt.zone + `"}`)
				ch.ResolvedFQDN, ch.ResolvedZone = tt.fqdn, "www.example.com."

				if err := sc.call(s, ch); err != nil {
					t.Fatalf("%s: %v", callName, err)
				}

				checkOneRequest(t, gw, sc.want("tok-a", tt.wantZone, tt.wantName))
			})
		}
	}
}

func TestPresentAddsTheKeyWithTheConfiguredTTL(t *testing.T) {
	tests := map[string]struct {
		config string
		want   uint32
	}{
		"ttl given":         {config: `{"tokenSecretRef":{"name":"dnsgate"},"ttl":60}`, want: 60},
		"ttl defaults":      {config: `{"tokenSecretRef":{"name":"dnsgate"}}`, want: 600},
		"largest ttl given": {config: `{"tokenSecretRef":{"name":"dnsgate"},"ttl":4294967295}`, want: 4294967295},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

			if err := s.Present(challenge(tt.config)); err != nil {
				t.Fatalf("Present: %v", err)
			}

			want := wantPresent("tok-a", "example.com", "_acme-challenge")
			want.Ttl = tt.want
			checkOneRequest(t, gw, want)
		})
	}
}

func TestCleanUpSendsNoTTLWhateverTheConfigSays(t *testing.T) {
	s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

	if err := s.CleanUp(cleanUpChallenge(`{"tokenSecretRef":{"name":"dnsgate"},"ttl":60}`)); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}

	checkOneRequest(t, gw, wantCleanUp("tok-a", "example.com", "_acme-challenge"))
}

func TestPresentNamesTheConfiguredTTLWhenTheGatewayRefusesIt(t *testing.T) {
	s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))
	gw.err = statusError(codes.InvalidArgument, "ttl out of range",
		&dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_INVALID_RECORD})

	err := s.Present(challenge(`{"tokenSecretRef":{"name":"dnsgate"},"ttl":30}`))
	checkError(t, err, "the Gateway refused TTL 30: check ttl against the Provider's range")
}

func TestEachCallRefusesAnInvalidTTL(t *testing.T) {
	tests := map[string]struct {
		config string
		want   string
	}{
		"zero": {
			config: `{"tokenSecretRef":{"name":"dnsgate"},"ttl":0}`,
			want:   "invalid solver config: ttl must be positive",
		},
		"negative": {
			config: `{"tokenSecretRef":{"name":"dnsgate"},"ttl":-1}`,
			want:   "invalid solver config: ttl cannot be a JSON number -1",
		},
		"too large": {
			config: `{"tokenSecretRef":{"name":"dnsgate"},"ttl":4294967296}`,
			want:   "invalid solver config: ttl cannot be a JSON number 4294967296",
		},
		"string": {
			config: `{"tokenSecretRef":{"name":"dnsgate"},"ttl":"600"}`,
			want:   "invalid solver config: ttl cannot be a JSON string",
		},
	}

	for callName, sc := range solverCalls {
		for name, tt := range tests {
			t.Run(callName+"/"+name, func(t *testing.T) {
				s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

				checkError(t, sc.call(s, sc.challenge(tt.config)), tt.want)
				checkNoRequest(t, gw)
			})
		}
	}
}

func TestEachCallRefusesANameOutsideTheConfiguredZone(t *testing.T) {
	tests := map[string]struct {
		zone, fqdn string
		want       string
	}{
		"other zone": {
			zone: "example.org", fqdn: "_acme-challenge.www.example.com.",
			want: "_acme-challenge.www.example.com is not in zone example.org",
		},
		"zone is only a suffix of a label": {
			zone: "ample.com", fqdn: "_acme-challenge.www.example.com.",
			want: "_acme-challenge.www.example.com is not in zone ample.com",
		},
		"zone below the name": {
			zone: "sub._acme-challenge.www.example.com", fqdn: "_acme-challenge.www.example.com.",
			want: "_acme-challenge.www.example.com is not in zone sub._acme-challenge.www.example.com",
		},
	}

	for callName, sc := range solverCalls {
		for name, tt := range tests {
			t.Run(callName+"/"+name, func(t *testing.T) {
				s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

				// The resolved zone holds the name; the configured one does not.
				ch := sc.challenge(`{"tokenSecretRef":{"name":"dnsgate"},"zone":"` + tt.zone + `"}`)
				ch.ResolvedFQDN, ch.ResolvedZone = tt.fqdn, "example.com."

				checkError(t, sc.call(s, ch), tt.want)
				checkNoRequest(t, gw)
			})
		}
	}
}
