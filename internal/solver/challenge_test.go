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
)

func TestEachCallRefusesAChallengeThatIsNotDNS01(t *testing.T) {
	for callName, sc := range solverCalls {
		for _, typ := range []string{"http-01", "DNS-01", "dns-02", ""} {
			t.Run(callName+"/"+typ, func(t *testing.T) {
				s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

				ch := sc.challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)
				ch.Type = typ

				checkError(t, sc.call(s, ch), "the challenge is not dns-01")
				checkNoRequest(t, gw)
			})
		}
	}
}

func TestEachCallRefusesAKeyThatIsNotAChallengeValue(t *testing.T) {
	tests := map[string]string{
		"empty":                   "",
		"too short":               validKey[:42],
		"too long":                validKey + "A",
		"padded":                  validKey[:42] + "=",
		"standard base64 plus":    validKey[:42] + "+",
		"standard base64 slash":   validKey[:42] + "/",
		"quote":                   validKey[:42] + `"`,
		"space":                   validKey[:42] + " ",
		"non-ASCII":               validKey[:41] + "é",
		"43 bytes with non-ASCII": validKey[:40] + "日",
	}

	for callName, sc := range solverCalls {
		for name, key := range tests {
			t.Run(callName+"/"+name, func(t *testing.T) {
				s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

				ch := sc.challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)
				ch.Key = key

				err := sc.call(s, ch)
				checkError(t, err, "challenge key is not a 43-character base64url value")
				checkNoRequest(t, gw)
			})
		}
	}
}

func TestEachCallReportsTheFirstCheckThatFails(t *testing.T) {
	// Each request fails its check and every check after it; the order
	// is type, config, zone, key, Secret.
	const (
		badConfig = `{"tokenSecretRef":{"name":"dnsgate"},"zone":"example.org","egress":"proxy"}`
		badZone   = `{"tokenSecretRef":{"name":"dnsgate"},"zone":"example.org"}`
		goodZone  = `{"tokenSecretRef":{"name":"dnsgate"}}`
	)

	tests := map[string]struct {
		typ, config, key string
		want             string
	}{
		"type":   {typ: "http-01", config: badConfig, key: "short", want: "the challenge is not dns-01"},
		"config": {typ: "dns-01", config: badConfig, key: "short", want: `invalid solver config: egress "proxy" is not gateway or agent`},
		"zone":   {typ: "dns-01", config: badZone, key: "short", want: "_acme-challenge.example.com is not in zone example.org"},
		"key":    {typ: "dns-01", config: goodZone, key: "short", want: "challenge key is not a 43-character base64url value"},
		"secret": {typ: "dns-01", config: goodZone, key: validKey, want: "secret team-a/dnsgate not found"},
	}

	for callName, sc := range solverCalls {
		for name, tt := range tests {
			t.Run(callName+"/"+name, func(t *testing.T) {
				s, gw := newSolver() // no Secret

				ch := sc.challenge(tt.config)
				ch.Type, ch.Key = tt.typ, tt.key

				checkError(t, sc.call(s, ch), tt.want)
				checkNoRequest(t, gw)
			})
		}
	}
}

func TestEachCallTakesAKeyOfTheWholeBase64urlAlphabet(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	for callName, sc := range solverCalls {
		for _, key := range []string{alphabet[:43], alphabet[len(alphabet)-43:]} {
			t.Run(callName+"/"+key, func(t *testing.T) {
				s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

				ch := sc.challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)
				ch.Key = key

				if err := sc.call(s, ch); err != nil {
					t.Fatalf("%s: %v", callName, err)
				}

				want := sc.want("tok-a", "example.com", "_acme-challenge")
				for _, v := range want.GetAdd() {
					v.Value = `"` + key + `"`
				}

				for i := range want.GetRemove() {
					want.Remove[i] = `"` + key + `"`
				}

				checkOneRequest(t, gw, want)
			})
		}
	}
}
