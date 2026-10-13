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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

var envVars = []string{"DNSGATE_GATEWAY", "DNSGATE_CA_FILE", "DNSGATE_GATEWAY_TIMEOUT", "DNSGATE_WEBHOOK_LOG_LEVEL"}

// clearEnv unsets the webhook's environment variables for the test.
func clearEnv(t *testing.T) {
	t.Helper()

	for _, key := range envVars {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}
}

// startUp runs the webhook command with args up to the point where it
// would start serving, and returns the settings it resolved.
func startUp(t *testing.T, groupName string, args ...string) (settings, error) {
	t.Helper()

	a := newApp(t.Context(), groupName)
	a.cmd.RunE = func(*cobra.Command, []string) error { return nil }
	a.cmd.SetArgs(args)
	a.cmd.SetOut(&strings.Builder{})
	a.cmd.SetErr(&strings.Builder{})

	err := a.cmd.Execute()

	return a.settings, err
}

// writeCA writes a self-signed PEM CA certificate to a file and returns
// its path.
func writeCA(t *testing.T) string {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestStartupFailsOnMissingOrBadSettings(t *testing.T) {
	notPEM := filepath.Join(t.TempDir(), "ca.txt")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	missing := filepath.Join(t.TempDir(), "missing.pem")

	tests := map[string]struct {
		groupName string
		args      []string
		want      string
	}{
		"no GROUP_NAME": {
			args: []string{"--gateway", "gateway.example.com:443"},
			want: "no API group: set GROUP_NAME",
		},
		"no --gateway": {
			groupName: "acme.dnsgate.example",
			want:      "no Gateway address: set --gateway or DNSGATE_GATEWAY",
		},
		"--gateway without a port": {
			groupName: "acme.dnsgate.example",
			args:      []string{"--gateway", "gateway.example.com"},
			want:      `invalid Gateway address "gateway.example.com": give host:port`,
		},
		"--gateway with a port that is not a number": {
			groupName: "acme.dnsgate.example",
			args:      []string{"--gateway", "gateway.example.com:https"},
			want:      `invalid Gateway address "gateway.example.com:https": give host:port`,
		},
		"--gateway the gRPC client refuses": {
			groupName: "acme.dnsgate.example",
			args:      []string{"--gateway", "%zz:443"},
			want:      `invalid Gateway address "%zz:443": give host:port`,
		},
		"unreadable --ca-file": {
			groupName: "acme.dnsgate.example",
			args:      []string{"--gateway", "gateway.example.com:443", "--ca-file", missing},
			want:      "reading CA file " + missing + ": ",
		},
		"--ca-file without a certificate": {
			groupName: "acme.dnsgate.example",
			args:      []string{"--gateway", "gateway.example.com:443", "--ca-file", notPEM},
			want:      "CA file " + notPEM + " holds no PEM certificate",
		},
		"non-positive --gateway-timeout": {
			groupName: "acme.dnsgate.example",
			args:      []string{"--gateway", "gateway.example.com:443", "--gateway-timeout", "0s"},
			want:      "--gateway-timeout must be positive",
		},
		"unknown --log-level": {
			groupName: "acme.dnsgate.example",
			args:      []string{"--gateway", "gateway.example.com:443", "--log-level", "verbose"},
			want:      `unknown log level "verbose": use error, warn, info, debug`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			clearEnv(t)

			_, err := startUp(t, tt.groupName, tt.args...)
			if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Errorf("startup error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestStartupFailsOnABadTimeoutInTheEnvironment(t *testing.T) {
	clearEnv(t)
	t.Setenv("DNSGATE_GATEWAY_TIMEOUT", "soon")

	_, err := startUp(t, "acme.dnsgate.example", "--gateway", "gateway.example.com:443")

	want := `invalid DNSGATE_GATEWAY_TIMEOUT "soon": give a duration such as 20s`
	if err == nil || err.Error() != want {
		t.Errorf("startup error = %v, want %q", err, want)
	}

	// The flag replaces the environment.
	if _, err := startUp(t, "acme.dnsgate.example", "--gateway", "gateway.example.com:443", "--gateway-timeout", "5s"); err != nil {
		t.Errorf("startup with --gateway-timeout: %v", err)
	}
}

func TestStartupTakesDefaultsForOptionalSettings(t *testing.T) {
	clearEnv(t)

	got, err := startUp(t, "acme.dnsgate.example", "--gateway", "gateway.example.com:443")
	if err != nil {
		t.Fatalf("startup: %v", err)
	}

	want := settings{gateway: "gateway.example.com:443", timeout: 20 * time.Second, logLevel: slog.LevelInfo}
	checkSettings(t, got, want)
}

func TestStartupTakesSettingsFromTheEnvironment(t *testing.T) {
	clearEnv(t)

	ca1, ca2 := writeCA(t), writeCA(t)
	t.Setenv("DNSGATE_GATEWAY", "env.example.com:443")
	t.Setenv("DNSGATE_CA_FILE", ca1+string(filepath.ListSeparator)+string(filepath.ListSeparator)+ca2)
	t.Setenv("DNSGATE_GATEWAY_TIMEOUT", "7s")
	t.Setenv("DNSGATE_WEBHOOK_LOG_LEVEL", "debug")

	got, err := startUp(t, "acme.dnsgate.example")
	if err != nil {
		t.Fatalf("startup: %v", err)
	}

	want := settings{gateway: "env.example.com:443", timeout: 7 * time.Second, logLevel: slog.LevelDebug}
	checkSettings(t, got, want, ca1, ca2)
}

func TestStartupTreatsAnEmptyEnvironmentVariableAsUnset(t *testing.T) {
	clearEnv(t)

	// Helm renders an unset value as an empty one.
	for _, key := range envVars {
		t.Setenv(key, "")
	}

	got, err := startUp(t, "acme.dnsgate.example", "--gateway", "gateway.example.com:443")
	if err != nil {
		t.Fatalf("startup: %v", err)
	}

	want := settings{gateway: "gateway.example.com:443", timeout: 20 * time.Second, logLevel: slog.LevelInfo}
	checkSettings(t, got, want)

	_, err = startUp(t, "acme.dnsgate.example")

	wantErr := "no Gateway address: set --gateway or DNSGATE_GATEWAY"
	if err == nil || err.Error() != wantErr {
		t.Errorf("startup error without a Gateway = %v, want %q", err, wantErr)
	}
}

func TestStartupFlagsReplaceTheEnvironment(t *testing.T) {
	clearEnv(t)

	envCA, flagCA1, flagCA2 := writeCA(t), writeCA(t), writeCA(t)
	t.Setenv("DNSGATE_GATEWAY", "env.example.com:443")
	t.Setenv("DNSGATE_CA_FILE", envCA)
	t.Setenv("DNSGATE_GATEWAY_TIMEOUT", "7s")
	t.Setenv("DNSGATE_WEBHOOK_LOG_LEVEL", "debug")

	got, err := startUp(t, "acme.dnsgate.example",
		"--gateway", "flag.example.com:443",
		"--ca-file", flagCA1, "--ca-file", flagCA2,
		"--gateway-timeout", "3s",
		"--log-level", "warn",
	)
	if err != nil {
		t.Fatalf("startup: %v", err)
	}

	want := settings{gateway: "flag.example.com:443", timeout: 3 * time.Second, logLevel: slog.LevelWarn}
	checkSettings(t, got, want, flagCA1, flagCA2)
}

// checkSettings fails t unless got is want, with a TLS config that
// verifies the Gateway against the certificates in caFiles or, without
// one, the system's.
func checkSettings(t *testing.T, got, want settings, caFiles ...string) {
	t.Helper()

	if got.gateway != want.gateway {
		t.Errorf("gateway = %q, want %q", got.gateway, want.gateway)
	}

	if got.timeout != want.timeout {
		t.Errorf("Gateway timeout = %v, want %v", got.timeout, want.timeout)
	}

	if got.logLevel != want.logLevel {
		t.Errorf("log level = %v, want %v", got.logLevel, want.logLevel)
	}

	if got.tls == nil {
		t.Fatal("no TLS config for the Gateway")
	}

	if got.tls.InsecureSkipVerify {
		t.Error("TLS to the Gateway skips verification")
	}

	if len(caFiles) == 0 {
		if got.tls.RootCAs != nil {
			t.Error("TLS root CAs set, want the system's")
		}

		return
	}

	wantPool := x509.NewCertPool()

	for _, file := range caFiles {
		pem, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}

		wantPool.AppendCertsFromPEM(pem)
	}

	if !got.tls.RootCAs.Equal(wantPool) {
		t.Errorf("TLS root CAs are not the certificates of %q", caFiles)
	}
}
