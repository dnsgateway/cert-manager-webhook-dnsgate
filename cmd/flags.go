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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

const (
	flagGateway        = "gateway"
	flagCAFile         = "ca-file"
	flagGatewayTimeout = "gateway-timeout"
	flagLogLevel       = "log-level"

	envGroupName      = "GROUP_NAME"
	envGateway        = "DNSGATE_GATEWAY"
	envCAFile         = "DNSGATE_CA_FILE"
	envGatewayTimeout = "DNSGATE_GATEWAY_TIMEOUT"
	envLogLevel       = "DNSGATE_WEBHOOK_LOG_LEVEL"
)

const (
	defaultGatewayTimeout = 20 * time.Second
	defaultLogLevel       = "info"
)

// Flags holds the webhook's own flags. Each falls back to an environment
// variable, then to a default.
type Flags struct {
	Gateway        string
	CAFiles        []string
	GatewayTimeout time.Duration
	LogLevel       string

	// envTimeoutErr is why the timeout in the environment was not taken,
	// if it was not; it stops startup unless --gateway-timeout replaces it.
	envTimeoutErr error
}

// settings are the checked flags the webhook runs with.
type settings struct {
	gateway  string
	caFiles  []string
	tls      *tls.Config
	timeout  time.Duration
	logLevel slog.Level
}

// defaultFlags returns the flags resolved from the environment and
// defaults, before command-line parsing.
func defaultFlags() *Flags {
	f := &Flags{
		Gateway:        os.Getenv(envGateway),
		CAFiles:        envPathList(envCAFile),
		GatewayTimeout: defaultGatewayTimeout,
		LogLevel:       withDefaultEnv(envLogLevel, defaultLogLevel),
	}

	if v, ok := os.LookupEnv(envGatewayTimeout); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			f.envTimeoutErr = fmt.Errorf("invalid %s %q: give a duration such as 20s", envGatewayTimeout, v)
		}

		f.GatewayTimeout = d
	}

	return f
}

// addFlags registers the webhook's own flags.
func (f *Flags) addFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&f.Gateway, flagGateway, "", f.Gateway,
		"Gateway address as host:port; required (env "+envGateway+")")
	flags.StringArrayVarP(&f.CAFiles, flagCAFile, "", f.CAFiles,
		"PEM file of the CA certificates that verify the Gateway, instead of the system's; repeat it to trust several (env "+envCAFile+", a path list)")
	flags.DurationVarP(&f.GatewayTimeout, flagGatewayTimeout, "", f.GatewayTimeout,
		"bound on the Gateway round trip of one Present or CleanUp (env "+envGatewayTimeout+")")
	flags.StringVarP(&f.LogLevel, flagLogLevel, "", f.LogLevel,
		"lowest level of the logs written: "+logLevelNames()+" (env "+envLogLevel+")")
}

// check checks the flags, set on flags, and the API group, and returns the
// settings they give. It reads the CA files, so that a missing or broken
// one stops the webhook before it serves.
func (f *Flags) check(flags *pflag.FlagSet, groupName string) (settings, error) {
	if groupName == "" {
		return settings{}, errors.New("no API group: set " + envGroupName)
	}

	if f.Gateway == "" {
		return settings{}, errors.New("no Gateway address: set --" + flagGateway + " or " + envGateway)
	}

	if f.envTimeoutErr != nil && !flags.Changed(flagGatewayTimeout) {
		return settings{}, f.envTimeoutErr
	}

	if f.GatewayTimeout <= 0 {
		return settings{}, errors.New("--" + flagGatewayTimeout + " must be positive")
	}

	level, err := logLevel(f.LogLevel)
	if err != nil {
		return settings{}, err
	}

	tlsCfg, err := gatewayTLS(f.CAFiles)
	if err != nil {
		return settings{}, err
	}

	return settings{
		gateway:  f.Gateway,
		caFiles:  f.CAFiles,
		tls:      tlsCfg,
		timeout:  f.GatewayTimeout,
		logLevel: level,
	}, nil
}

// gatewayTLS returns the TLS config that verifies the Gateway against the
// certificates of every file in caFiles or, without one, the system's CA
// certificates. Verification cannot be turned off.
func gatewayTLS(caFiles []string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}

	if len(caFiles) == 0 {
		return cfg, nil
	}

	pool := x509.NewCertPool()

	for _, file := range caFiles {
		pem, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("reading CA file %s: %w", file, err)
		}

		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %s holds no PEM certificate", file)
		}
	}

	cfg.RootCAs = pool

	return cfg, nil
}

// logLevels are the accepted --log-level values and their slog levels,
// most severe first.
var logLevels = []struct {
	name  string
	level slog.Level
}{
	{"error", slog.LevelError},
	{"warn", slog.LevelWarn},
	{"info", slog.LevelInfo},
	{"debug", slog.LevelDebug},
}

// logLevelNames returns the accepted --log-level values, most severe first.
func logLevelNames() string {
	names := make([]string, len(logLevels))
	for i, l := range logLevels {
		names[i] = l.name
	}

	return strings.Join(names, ", ")
}

// logLevel returns the slog level that name, a --log-level, names.
func logLevel(name string) (slog.Level, error) {
	for _, l := range logLevels {
		if l.name == name {
			return l.level, nil
		}
	}

	return 0, errors.New(`unknown log level "` + name + `": use ` + logLevelNames())
}

func withDefaultEnv(key, def string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}

	return def
}

// envPathList returns the paths in the environment variable key, a path
// list, leaving out empty entries.
func envPathList(key string) []string {
	var paths []string

	for _, p := range filepath.SplitList(os.Getenv(key)) {
		if p != "" {
			paths = append(paths, p)
		}
	}

	return paths
}
