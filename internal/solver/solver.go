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

// Package solver is the cert-manager Webhook's DNS-01 solver: it writes
// challenge values at the Challenge Target through the Gateway, with the
// cert-manager Issuer's Service Token.
package solver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
)

// Name is the solver name a cert-manager Issuer gives as solverName.
const Name = "dnsgate"

// defaultTTL is the TTL of the challenge values added.
const defaultTTL = 600

// Gateway is the part of the dnsgate-go client the solver uses. It is
// satisfied by *client.Client.
type Gateway interface {
	PatchRecord(ctx context.Context, req *dnsgatev1.PatchRecordRequest) (*dnsgatev1.PatchRecordResponse, error)
}

// Options are the dependencies and settings of a Solver.
type Options struct {
	// NewGateway builds the process's one Gateway client. It is called
	// once, by Initialize.
	NewGateway func() (Gateway, error)
	// NewSecrets builds what reads the token Secrets from the webhook's
	// Kubernetes config. It is called once, by Initialize. Nil means a
	// client-go clientset.
	NewSecrets func(*restclient.Config) (corev1client.SecretsGetter, error)
	// Timeout bounds the Gateway round trip of one call. It starts once
	// the token Secret has been read, so the read does not count.
	Timeout time.Duration
	// Logger is where the solver logs each call. Nil means slog's default
	// logger at the time of the call.
	Logger *slog.Logger
}

// Solver implements cert-manager's webhook.Solver.
type Solver struct {
	opts Options

	// clients is set once Initialize succeeds. The webhook framework
	// runs Initialize as a post-start hook, so it may race with the first
	// requests.
	clients atomic.Pointer[clients]
}

// clients are the solver's two dependencies.
type clients struct {
	gateway Gateway
	secrets corev1client.SecretsGetter
}

// New returns a Solver with the given options. It is ready for requests
// once Initialize has been called.
func New(o Options) *Solver {
	if o.NewSecrets == nil {
		o.NewSecrets = newSecrets
	}

	return &Solver{opts: o}
}

// Name returns the solver name, dnsgate.
func (s *Solver) Name() string { return Name }

// Initialize builds the Kubernetes client that reads token Secrets and
// the process's one Gateway client.
func (s *Solver) Initialize(kubeConfig *restclient.Config, _ <-chan struct{}) error {
	secrets, err := s.opts.NewSecrets(kubeConfig)
	if err != nil {
		return fmt.Errorf("building the Kubernetes client: %w", err)
	}

	gateway, err := s.opts.NewGateway()
	if err != nil {
		return fmt.Errorf("building the Gateway client: %w", err)
	}

	s.clients.Store(&clients{gateway: gateway, secrets: secrets})

	return nil
}

func newSecrets(cfg *restclient.Config) (corev1client.SecretsGetter, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	return cs.CoreV1(), nil
}

// Present adds ch.Key at the Challenge Target.
func (s *Solver) Present(ch *whapi.ChallengeRequest) error {
	return s.call(ch, change{
		act: actionPresent,
		ttl: defaultTTL,
		add: []*dnsgatev1.RecordValue{{Value: txtValue(ch.Key)}},
	})
}

// CleanUp removes ch.Key from the Challenge Target, leaving any other
// value there alone. Removing a value the RRset does not hold changes
// nothing, so a retried CleanUp succeeds.
func (s *Solver) CleanUp(ch *whapi.ChallengeRequest) error {
	return s.call(ch, change{
		act:    actionCleanUp,
		remove: []string{txtValue(ch.Key)},
	})
}

// txtValue returns key in TXT presentation form.
func txtValue(key string) string { return `"` + key + `"` }

// change is what one call of the solver does at the Challenge Target:
// its action, as logged, and the TXT values it adds, with their TTL, or
// removes.
type change struct {
	act    action
	ttl    uint32
	add    []*dnsgatev1.RecordValue
	remove []string
}

// call makes c at the Challenge Target of ch and logs it.
func (s *Solver) call(ch *whapi.ChallengeRequest, c change) error {
	start := time.Now()
	zone, err := s.patch(ch, c)
	s.logCall(ch, c.act, zone, err, time.Since(start))

	return err
}

// patch makes c at the Challenge Target of ch: it reads the token from
// the Secret the config of ch names and sends c to the Gateway in one
// PatchRecord, bounded by the solver's timeout. It returns the zone it
// writes in, or the zone it had chosen when it failed.
func (s *Solver) patch(ch *whapi.ChallengeRequest, c change) (string, error) {
	zone := strings.TrimSuffix(ch.ResolvedZone, ".")

	deps := s.clients.Load()
	if deps == nil {
		return zone, errors.New("the webhook is not initialized yet")
	}

	cfg, err := parseConfig(ch.Config)
	if err != nil {
		return zone, err
	}

	if cfg.Zone != "" {
		zone = strings.TrimSuffix(cfg.Zone, ".")
	}

	target, err := challengeTarget(ch.ResolvedFQDN, zone)
	if err != nil {
		return zone, err
	}

	token, err := readToken(context.Background(), deps.secrets, ch.ResourceNamespace, cfg.TokenSecretRef)
	if err != nil {
		return zone, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.opts.Timeout)
	defer cancel()

	_, err = deps.gateway.PatchRecord(ctx, &dnsgatev1.PatchRecordRequest{
		Token:  token,
		Zone:   target.zone,
		Name:   target.name,
		Type:   "TXT",
		Ttl:    c.ttl,
		Add:    c.add,
		Remove: c.remove,
	})
	if err != nil {
		return zone, newGatewayFailure(err, c.ttl)
	}

	return zone, nil
}

// action is what a call of the solver does at the Challenge Target, as
// logged.
type action string

// The actions of the solver.
const (
	actionPresent action = "present"
	actionCleanUp action = "cleanup"
)

// logCall logs the outcome of act, a call for ch in zone that took d
// and ended with err. The line never carries the token or ch.Key.
func (s *Solver) logCall(ch *whapi.ChallengeRequest, act action, zone string, err error, d time.Duration) {
	logger := s.opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	level, result := slog.LevelInfo, "ok"
	if err != nil {
		level, result = slog.LevelError, err.Error()
	}

	logger.LogAttrs(context.Background(), level, "challenge "+string(act),
		slog.String("uid", string(ch.UID)),
		slog.String("namespace", ch.ResourceNamespace),
		slog.String("dnsName", ch.DNSName),
		slog.String("challengeTarget", ch.ResolvedFQDN),
		slog.String("zone", zone),
		slog.String("action", string(act)),
		slog.String("result", result),
		slog.Duration("duration", d),
	)
}
