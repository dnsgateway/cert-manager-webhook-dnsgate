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
	"io"
	"log/slog"
	"strconv"
	"sync"

	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	logsapi "k8s.io/component-base/logs/api/v1"
)

// logFormatName is the --logging-format of the webhook's own log format:
// JSON lines at --log-level and above. It is the default.
const logFormatName = "dnsgate"

// debugVerbosity is the klog verbosity --log-level debug turns on, unless
// -v is given: klog's V(n) lines are slog level -n, and debug is -4.
const debugVerbosity = 4

// The flags of the logging that cert-manager's webhook server sets up.
const (
	flagLoggingFormat = "logging-format"
	flagVerbosity     = "v"
)

// logOutput is where, and from which level, the webhook's log format
// writes. The server creates its logger from it once it has checked its
// own flags, after the webhook's flags are checked.
var logOutput struct {
	mu    sync.Mutex
	w     io.Writer
	level slog.Level
}

// logFormat is the webhook's log format. The cert-manager framework logs
// through klog, and the server points both klog and slog's default
// logger at the logger it creates, so --log-level applies to every line.
type logFormat struct{}

// Create returns the logger writing JSON lines to logOutput.
func (logFormat) Create(logsapi.LoggingConfiguration, logsapi.LoggingOptions) (logr.Logger, logsapi.RuntimeControl) {
	logOutput.mu.Lock()
	defer logOutput.mu.Unlock()

	h := slog.NewJSONHandler(logOutput.w, &slog.HandlerOptions{Level: logOutput.level})

	return logr.FromSlogHandler(h), logsapi.RuntimeControl{}
}

// registerLogFormat registers the webhook's log format, once per process
// and before the server adds its flags, which closes the registry.
var registerLogFormat = sync.OnceValue(func() error {
	return logsapi.RegisterLogFormat(logFormatName, logFormat{}, logsapi.LoggingStableOptions)
})

// defaultToLogFormat makes the webhook's log format the default
// --logging-format.
func defaultToLogFormat(flags *pflag.FlagSet) {
	f := flags.Lookup(flagLoggingFormat)
	if f == nil {
		return
	}

	f.DefValue = logFormatName
	_ = f.Value.Set(logFormatName)
}

// applyLogLevel makes the logger the server creates write to w from
// level, and, for debug, turns klog's verbosity up unless -v is given.
func applyLogLevel(flags *pflag.FlagSet, w io.Writer, level slog.Level) error {
	logOutput.mu.Lock()
	logOutput.w, logOutput.level = w, level
	logOutput.mu.Unlock()

	if level > slog.LevelDebug || flags.Changed(flagVerbosity) {
		return nil
	}

	return flags.Set(flagVerbosity, strconv.Itoa(debugVerbosity))
}
