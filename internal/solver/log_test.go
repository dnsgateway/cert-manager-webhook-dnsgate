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
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"

	"github.com/dnsgateway/cert-manager-webhook-dnsgate/internal/solver"
)

// newLoggingSolver builds and initializes a solver whose Gateway fails
// with gwErr, when set, and which logs to the returned buffer as JSON.
func newLoggingSolver(t *testing.T, token string, gwErr error) (*solver.Solver, *bytes.Buffer) {
	t.Helper()

	var logs bytes.Buffer

	gw := &fakeGateway{err: gwErr}
	clientset := fake.NewClientset(tokenSecret("team-a", "dnsgate", map[string]string{"token": token}))
	s := solver.New(solver.Options{
		NewSecrets: func(*restclient.Config) (corev1client.SecretsGetter, error) { return clientset.CoreV1(), nil },
		NewGateway: func() (solver.Gateway, error) { return gw, nil },
		Timeout:    5 * time.Second,
		Logger:     slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})

	if err := s.Initialize(&restclient.Config{}, nil); err != nil {
		t.Fatal(err)
	}

	return s, &logs
}

// logLine returns the one log line in logs, decoded.
func logLine(t *testing.T, logs *bytes.Buffer) map[string]any {
	t.Helper()

	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want 1:\n%s", len(lines), logs)
	}

	var line map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &line); err != nil {
		t.Fatalf("log line %q is not JSON: %v", lines[0], err)
	}

	return line
}

func TestPresentLogsTheChallengeAndTheOutcome(t *testing.T) {
	const token = "tok-secret-a"

	tests := map[string]struct {
		gwErr      error
		wantLevel  string
		wantResult string
	}{
		"success": {
			wantLevel:  "INFO",
			wantResult: "ok",
		},
		"Gateway failure": {
			gwErr:      statusError(codes.Unavailable, "connection refused", nil),
			wantLevel:  "ERROR",
			wantResult: "the Gateway call failed: unavailable",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, logs := newLoggingSolver(t, token, tt.gwErr)

			_ = s.Present(challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`))

			if out := logs.String(); strings.Contains(out, token) || strings.Contains(out, validKey) {
				t.Errorf("logs carry the token or the key:\n%s", out)
			}

			line := logLine(t, logs)

			want := map[string]any{
				"level":           tt.wantLevel,
				"uid":             "6b0f7a52-0c35-4f0c-9d6c-1f5b1c4c2f55",
				"namespace":       "team-a",
				"dnsName":         "example.com",
				"challengeTarget": "_acme-challenge.example.com.",
				"zone":            "example.com",
				"action":          "present",
				"result":          tt.wantResult,
			}
			for key, val := range want {
				if line[key] != val {
					t.Errorf("log field %s = %v, want %v", key, line[key], val)
				}
			}

			if d, ok := line["duration"].(float64); !ok || d <= 0 {
				t.Errorf("log field duration = %v, want a duration", line["duration"])
			}
		})
	}
}

func TestEachCallLogsTheZoneItWritesIn(t *testing.T) {
	tests := map[string]struct {
		config string
		want   string
	}{
		"resolved zone": {
			config: `{"tokenSecretRef":{"name":"dnsgate"}}`,
			want:   "example.com",
		},
		"configured zone": {
			config: `{"tokenSecretRef":{"name":"dnsgate"},"zone":"com."}`,
			want:   "com",
		},
		"configured zone that does not hold the name": {
			config: `{"tokenSecretRef":{"name":"dnsgate"},"zone":"example.org"}`,
			want:   "example.org",
		},
		"invalid config": {
			config: `{"tokenSecretRef":{"name":"dnsgate"},"zone":"com","zones":[]}`,
			want:   "example.com",
		},
	}

	for callName, sc := range solverCalls {
		for name, tt := range tests {
			t.Run(callName+"/"+name, func(t *testing.T) {
				s, logs := newLoggingSolver(t, "tok-a", nil)

				_ = sc.call(s, sc.challenge(tt.config))

				if got := logLine(t, logs)["zone"]; got != tt.want {
					t.Errorf("log field zone = %v, want %v", got, tt.want)
				}
			})
		}
	}
}
