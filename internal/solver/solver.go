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
	deps := s.clients.Load()
	if deps == nil {
		return errors.New("the webhook is not initialized yet")
	}

	cfg, err := parseConfig(ch.Config)
	if err != nil {
		return err
	}

	target, err := challengeTarget(ch.ResolvedFQDN, ch.ResolvedZone)
	if err != nil {
		return err
	}

	token, err := readToken(context.Background(), deps.secrets, ch.ResourceNamespace, cfg.TokenSecretRef)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.opts.Timeout)
	defer cancel()

	_, err = deps.gateway.PatchRecord(ctx, &dnsgatev1.PatchRecordRequest{
		Token: token,
		Zone:  target.zone,
		Name:  target.name,
		Type:  "TXT",
		Ttl:   defaultTTL,
		Add:   []*dnsgatev1.RecordValue{{Value: `"` + ch.Key + `"`}},
	})
	if err != nil {
		return gatewayFailed(err, defaultTTL)
	}

	return nil
}

// CleanUp is not implemented yet.
func (s *Solver) CleanUp(*whapi.ChallengeRequest) error {
	return errors.New("CleanUp is not implemented")
}
