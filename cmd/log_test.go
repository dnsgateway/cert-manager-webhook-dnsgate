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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"k8s.io/klog/v2"
)

// envLogHelper makes the test binary run TestLogHelper as a webhook
// process with the --log-level in it.
const envLogHelper = "DNSGATE_TEST_LOG_HELPER_LEVEL"

// TestLogHelper is not a test: run by TestLogLevelAppliesToEveryLogLine
// in a process of its own, as logging can be set up once per process, it
// starts the webhook with --log-level, up to where the server has set up
// its logging and stops on a bad --secure-port, then writes a line of
// each level through klog and slog.
func TestLogHelper(t *testing.T) {
	level := os.Getenv(envLogHelper)
	if level == "" {
		t.Skip("run by TestLogLevelAppliesToEveryLogLine")
	}

	a := newApp(t.Context(), "acme.dnsgate.example")
	a.cmd.SetArgs([]string{"--gateway", "gateway.example.com:443", "--log-level", level, "--secure-port", "70000"})

	if err := a.cmd.Execute(); err == nil || !strings.Contains(err.Error(), "secure-port") {
		fmt.Printf("startup error = %v, want one about --secure-port\n", err)
		os.Exit(2)
	}

	klog.Error("klog error")
	klog.Info("klog info")
	klog.V(4).Info("klog v4")
	klog.V(5).Info("klog v5")
	slog.Error("slog error")
	slog.Warn("slog warn")
	slog.Info("slog info")
	slog.Debug("slog debug")
	klog.Flush()
	os.Exit(0)
}

func TestLogLevelAppliesToEveryLogLine(t *testing.T) {
	tests := map[string][]string{
		"error": {"klog error", "slog error"},
		"warn":  {"klog error", "slog error", "slog warn"},
		"info":  {"klog error", "klog info", "slog error", "slog warn", "slog info"},
		"debug": {"klog error", "klog info", "klog v4", "slog error", "slog warn", "slog info", "slog debug"},
	}

	for level, want := range tests {
		t.Run(level, func(t *testing.T) {
			clearEnv(t)

			var stderr bytes.Buffer

			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestLogHelper$")
			cmd.Env = append(os.Environ(), envLogHelper+"="+level)
			cmd.Stderr = &stderr

			if out, err := cmd.Output(); err != nil {
				t.Fatalf("helper: %v\n%s%s", err, out, &stderr)
			}

			if got := testLines(t, &stderr); !slices.Equal(got, want) {
				t.Errorf("lines logged = %q, want %q", got, want)
			}
		})
	}
}

// testLines returns the messages, in order, of the JSON log lines in out
// that the helper wrote, failing t on a line that is not JSON.
func testLines(t *testing.T, out *bytes.Buffer) []string {
	t.Helper()

	var msgs []string

	for line := range strings.Lines(out.String()) {
		var entry struct {
			Msg string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line %q is not JSON: %v", line, err)
		}

		if strings.HasPrefix(entry.Msg, "klog ") || strings.HasPrefix(entry.Msg, "slog ") {
			msgs = append(msgs, entry.Msg)
		}
	}

	return msgs
}
