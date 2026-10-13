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
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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

// flagValues holds the webhook's own flags. Each falls back to an
// environment variable, then to a default.
type flagValues struct {
	gateway        string
	caFiles        []string
	gatewayTimeout time.Duration
	logLevel       string

	// envTimeoutErr is why the timeout in the environment was not taken,
	// if it was not; it stops startup unless --gateway-timeout replaces it.
	envTimeoutErr error
}

// settings are the checked flags the webhook runs with.
type settings struct {
	gateway  string
	tls      *tls.Config
	timeout  time.Duration
	logLevel slog.Level
}

// flagsFromEnv returns the flag values the environment gives or, for a
// variable that is unset or empty, the defaults. The command line may
// replace them.
func flagsFromEnv() *flagValues {
	f := &flagValues{
		gateway:        os.Getenv(envGateway),
		caFiles:        envPathList(envCAFile),
		gatewayTimeout: defaultGatewayTimeout,
		logLevel:       withDefaultEnv(envLogLevel, defaultLogLevel),
	}

	if v, ok := lookupEnv(envGatewayTimeout); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			f.envTimeoutErr = fmt.Errorf("invalid %s %q: give a duration such as 20s", envGatewayTimeout, v)
		}

		f.gatewayTimeout = d
	}

	return f
}

// addFlags registers the webhook's own flags.
func (f *flagValues) addFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&f.gateway, flagGateway, "", f.gateway,
		"Gateway address as host:port; required (env "+envGateway+")")
	flags.StringArrayVarP(&f.caFiles, flagCAFile, "", f.caFiles,
		"PEM file of the CA certificates that verify the Gateway, instead of the system's; repeat it to trust several (env "+envCAFile+", a path list)")
	flags.DurationVarP(&f.gatewayTimeout, flagGatewayTimeout, "", f.gatewayTimeout,
		"bound on the Gateway round trip of one Present or CleanUp (env "+envGatewayTimeout+")")
	flags.StringVarP(&f.logLevel, flagLogLevel, "", f.logLevel,
		"lowest level of the logs written: "+logLevelNames()+" (env "+envLogLevel+")")
}

// check checks the flags, set on flags, and the API group, and returns the
// settings they give. It reads the CA files, so that a missing or broken
// one stops the webhook before it serves.
func (f *flagValues) check(flags *pflag.FlagSet, groupName string) (settings, error) {
	if groupName == "" {
		return settings{}, errors.New("no API group: set " + envGroupName)
	}

	if f.gateway == "" {
		return settings{}, errors.New("no Gateway address: set --" + flagGateway + " or " + envGateway)
	}

	if !validGatewayAddress(f.gateway) {
		return settings{}, fmt.Errorf("invalid Gateway address %q: give host:port", f.gateway)
	}

	if f.envTimeoutErr != nil && !flags.Changed(flagGatewayTimeout) {
		return settings{}, f.envTimeoutErr
	}

	if f.gatewayTimeout <= 0 {
		return settings{}, errors.New("--" + flagGatewayTimeout + " must be positive")
	}

	level, err := logLevel(f.logLevel)
	if err != nil {
		return settings{}, err
	}

	tlsCfg, err := gatewayTLS(f.caFiles)
	if err != nil {
		return settings{}, err
	}

	return settings{
		gateway:  f.gateway,
		tls:      tlsCfg,
		timeout:  f.gatewayTimeout,
		logLevel: level,
	}, nil
}

// validGatewayAddress reports whether address is a host:port with a port
// number that the gRPC client takes as a DNS target, so that a malformed
// one stops startup instead of failing the first challenge.
func validGatewayAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return false
	}

	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return false
	}

	// grpc.NewClient parses the address as this URL.
	_, err = url.Parse("dns:///" + address)

	return err == nil
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

// withDefaultEnv returns the environment variable key or, when it is
// unset or empty, def.
func withDefaultEnv(key, def string) string {
	if val, ok := lookupEnv(key); ok {
		return val
	}

	return def
}

// lookupEnv returns the environment variable key and whether it is set.
// An empty variable counts as unset, as Helm renders an unset value empty.
func lookupEnv(key string) (string, bool) {
	val := os.Getenv(key)

	return val, val != ""
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
