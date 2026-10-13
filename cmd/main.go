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

// Command cert-manager-webhook-dnsgate is the cert-manager Webhook: a
// DNS-01 solver that writes challenge values through the DNS Gateway.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd/server"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"k8s.io/component-base/logs"

	"github.com/dnsgateway/dnsgate-go/client"

	"github.com/dnsgateway/cert-manager-webhook-dnsgate/internal/solver"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logs.InitLogs()
	defer logs.FlushLogs()

	a := newApp(ctx, os.Getenv(envGroupName))
	if err := a.cmd.ExecuteContext(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		logs.FlushLogs()
		os.Exit(1)
	}
}

// app is the webhook process: cert-manager's webhook server command with
// the webhook's own flags, and the solver it serves.
type app struct {
	cmd *cobra.Command

	// settings are the checked flags, set before the server starts.
	settings settings

	// solver is built once the flags are checked: the server command
	// takes its solvers before it parses flags.
	solver deferredSolver
}

// deferredSolver is the solver the server serves; Solver is set before
// the server starts.
type deferredSolver struct {
	*solver.Solver
}

// Name returns the solver name, also before the solver is built.
func (deferredSolver) Name() string { return solver.Name }

// newApp returns the webhook process serving the API group groupName.
// It checks its flags and groupName before the server starts.
func newApp(ctx context.Context, groupName string) *app {
	a := &app{}

	cmd := server.NewCommandStartWebhookServer(ctx, groupName, &a.solver)
	cmd.Use = "cert-manager-webhook-dnsgate"
	cmd.Short = "cert-manager DNS-01 webhook solver that writes challenge values through the DNS Gateway"
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	f := defaultFlags()
	f.addFlags(cmd.Flags())

	cmd.PreRunE = func(cmd *cobra.Command, _ []string) error {
		st, err := f.check(cmd.Flags(), groupName)
		if err != nil {
			return err
		}

		a.settings = st
		slog.SetDefault(slog.New(slog.NewJSONHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: st.logLevel})))

		a.solver.Solver = solver.New(solver.Options{
			NewGateway: func() (solver.Gateway, error) { return dialGateway(st.gateway, st.tls) },
			Timeout:    st.timeout,
		})

		return nil
	}

	a.cmd = cmd

	return a
}

// dialGateway returns the process's one Gateway client for the Gateway at
// address, verified with tlsCfg. It does not connect yet.
func dialGateway(address string, tlsCfg *tls.Config) (*client.Client, error) {
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("connecting to the Gateway: %w", err)
	}

	return client.New(conn), nil
}
