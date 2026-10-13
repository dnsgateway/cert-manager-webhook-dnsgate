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

// Package e2e issues a certificate through a cert-manager Webhook already
// deployed in a cluster, against a real Gateway and ACME server. The test
// itself is built only with the e2e build tag; the pieces here are not,
// so their unit tests run with go test ./....
package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	"github.com/cert-manager/cert-manager/pkg/apis/certmanager"
	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// The environment variables the test runs with.
const (
	envToken                    = "DNSGATE_TEST_TOKEN"
	envZone                     = "DNSGATE_TEST_ZONE"
	envACMEServer               = "DNSGATE_TEST_ACME_SERVER"
	envACMEEmail                = "DNSGATE_TEST_ACME_EMAIL"
	envGroupName                = "DNSGATE_TEST_GROUP_NAME"
	envIssuerKind               = "DNSGATE_TEST_ISSUER_KIND"
	envClusterResourceNamespace = "DNSGATE_TEST_CLUSTER_RESOURCE_NAMESPACE"
	envTimeout                  = "DNSGATE_TEST_TIMEOUT"
)

// The defaults of the optional settings.
const (
	// defaultACMEServer is Let's Encrypt's staging directory, whose
	// certificates are untrusted and whose rate limits are generous.
	defaultACMEServer = "https://acme-staging-v02.api.letsencrypt.org/directory"
	// defaultGroupName is the chart's default groupName.
	defaultGroupName                = "acme.dnsgate.link"
	defaultClusterResourceNamespace = "cert-manager"
	defaultTimeout                  = 10 * time.Minute
)

// The kinds of cert-manager Issuer the test can create.
const (
	kindIssuer        = "Issuer"
	kindClusterIssuer = "ClusterIssuer"
)

// settings is what a run of the test needs.
type settings struct {
	// token is the Service Token. It is never logged.
	token string
	// zone is the zone the certificate's name is made in, without a
	// trailing dot.
	zone       string
	acmeServer string
	// acmeEmail is the ACME account's email; empty registers none.
	acmeEmail string
	// groupName is the groupName the webhook was deployed with.
	groupName string
	// issuerKind is kindIssuer or kindClusterIssuer.
	issuerKind string
	// clusterResourceNamespace is cert-manager's cluster resource
	// namespace, where a ClusterIssuer's Secrets are read from.
	clusterResourceNamespace string
	// timeout bounds the wait for the Certificate to become Ready.
	timeout time.Duration
}

// readSettings returns the run's settings from getenv and the names of
// the required variables that are unset. It returns an error for a set
// variable it cannot use.
func readSettings(getenv func(string) string) (settings, []string, error) {
	s := settings{
		token:                    getenv(envToken),
		zone:                     strings.TrimSuffix(getenv(envZone), "."),
		acmeServer:               orDefault(getenv(envACMEServer), defaultACMEServer),
		acmeEmail:                getenv(envACMEEmail),
		groupName:                orDefault(getenv(envGroupName), defaultGroupName),
		issuerKind:               orDefault(getenv(envIssuerKind), kindClusterIssuer),
		clusterResourceNamespace: orDefault(getenv(envClusterResourceNamespace), defaultClusterResourceNamespace),
		timeout:                  defaultTimeout,
	}

	if v := getenv(envTimeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return settings{}, nil, fmt.Errorf("%s: %w", envTimeout, err)
		}

		if d <= 0 {
			return settings{}, nil, fmt.Errorf("%s: %s is not positive", envTimeout, v)
		}

		s.timeout = d
	}

	if s.issuerKind != kindIssuer && s.issuerKind != kindClusterIssuer {
		return settings{}, nil, fmt.Errorf("%s: %q is not %s or %s", envIssuerKind, s.issuerKind, kindIssuer, kindClusterIssuer)
	}

	var missing []string

	for _, v := range []struct{ name, value string }{
		{envToken, s.token},
		{envZone, s.zone},
	} {
		if v.value == "" {
			missing = append(missing, v.name)
		}
	}

	return s, missing, nil
}

// names are the names of what a run creates. They share a random suffix,
// so that runs neither collide nor find values left by an earlier run.
type names struct {
	namespace string
	// issuer names the cert-manager Issuer, of either kind.
	issuer string
	// tokenSecret holds the Service Token.
	tokenSecret string
	// accountSecret holds the ACME account's private key.
	accountSecret string
	certificate   string
	tlsSecret     string
	// host is the name the certificate is issued for.
	host string
}

// suffixAlphabet is what a suffix is made of: valid in a DNS label and in
// a Kubernetes name.
const suffixAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// suffixLength is the length of a suffix.
const suffixLength = 8

// newNames returns the names of a run in zone, with a suffix made from r.
func newNames(r io.Reader, zone string) (names, error) {
	b := make([]byte, suffixLength)
	if _, err := io.ReadFull(r, b); err != nil {
		return names{}, fmt.Errorf("making a random suffix: %w", err)
	}

	for i := range b {
		b[i] = suffixAlphabet[int(b[i])%len(suffixAlphabet)]
	}

	base := "dnsgate-e2e-" + string(b)

	return names{
		namespace:     base,
		issuer:        base,
		tokenSecret:   base + "-token",
		accountSecret: base + "-account",
		certificate:   "e2e",
		tlsSecret:     "e2e-tls",
		host:          "e2e-" + string(b) + "." + zone,
	}, nil
}

// solverName is the webhook's solver name.
const solverName = "dnsgate"

// tokenKey is the key in the token Secret that holds the Service Token.
const tokenKey = "token"

// secretNamespace returns the namespace the webhook and cert-manager read
// the cert-manager Issuer's Secrets from: the Issuer's own, or for a
// ClusterIssuer, cert-manager's cluster resource namespace.
func secretNamespace(s settings, n names) string {
	if s.issuerKind == kindClusterIssuer {
		return s.clusterResourceNamespace
	}

	return n.namespace
}

// newTokenSecret returns the Secret that holds the Service Token.
func newTokenSecret(s settings, n names) *corev1.Secret {
	return &corev1.Secret{
		Name:      n.tokenSecret,
		Namespace: secretNamespace(s, n),
		Data:      map[string][]byte{tokenKey: []byte(s.token)},
	}
}

// issuerSpec returns the spec of an ACME cert-manager Issuer whose only
// solver is the webhook's DNS-01 solver, reading the Service Token from
// the token Secret.
func issuerSpec(s settings, n names) cmv1.IssuerSpec {
	// Encoding a map of strings cannot fail.
	config, _ := json.Marshal(map[string]any{
		"tokenSecretRef": map[string]string{"name": n.tokenSecret, "key": tokenKey},
	})

	return cmv1.IssuerSpec{
		ACME: &cmacme.ACMEIssuer{
			Email:  s.acmeEmail,
			Server: s.acmeServer,
			PrivateKey: cmmeta.SecretKeySelector{
				LocalObjectReference: cmmeta.LocalObjectReference{Name: n.accountSecret},
			},
			Solvers: []cmacme.ACMEChallengeSolver{{
				DNS01: &cmacme.ACMEChallengeSolverDNS01{
					Webhook: &cmacme.ACMEIssuerDNS01ProviderWebhook{
						GroupName:  s.groupName,
						SolverName: solverName,
						Config:     &apiextensionsv1.JSON{Raw: config},
					},
				},
			}},
		},
	}
}

// newIssuer returns the run's Issuer, in the run's namespace.
func newIssuer(s settings, n names) *cmv1.Issuer {
	return &cmv1.Issuer{
		Name:      n.issuer,
		Namespace: n.namespace,
		Spec:      issuerSpec(s, n),
	}
}

// newClusterIssuer returns the run's ClusterIssuer.
func newClusterIssuer(s settings, n names) *cmv1.ClusterIssuer {
	return &cmv1.ClusterIssuer{
		Name: n.issuer,
		Spec: issuerSpec(s, n),
	}
}

// newCertificate returns the run's Certificate for the host, from the
// run's cert-manager Issuer.
func newCertificate(s settings, n names) *cmv1.Certificate {
	return &cmv1.Certificate{
		Name:      n.certificate,
		Namespace: n.namespace,
		Spec: cmv1.CertificateSpec{
			DNSNames:   []string{n.host},
			SecretName: n.tlsSecret,
			IssuerRef: cmmeta.IssuerReference{
				Name:  n.issuer,
				Kind:  s.issuerKind,
				Group: certmanager.GroupName,
			},
		},
	}
}

// certificateReady reports whether crt has the condition Ready True.
func certificateReady(crt *cmv1.Certificate) bool {
	for _, c := range crt.Status.Conditions {
		if c.Type == cmv1.CertificateConditionReady {
			return c.Status == cmmeta.ConditionTrue
		}
	}

	return false
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}

	return v
}
