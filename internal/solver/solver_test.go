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
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"

	"github.com/dnsgateway/cert-manager-webhook-dnsgate/internal/solver"
)

// validKey is a challenge key of the shape cert-manager gives: 43
// characters of unpadded base64url.
const validKey = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"

// fakeGateway records every PatchRecord request it receives.
// It fails each with err, when set, and, as a real client does, with the
// context's error once the context is done.
type fakeGateway struct {
	mu   sync.Mutex
	reqs []*dnsgatev1.PatchRecordRequest
	err  error
}

func (g *fakeGateway) PatchRecord(ctx context.Context, req *dnsgatev1.PatchRecordRequest) (*dnsgatev1.PatchRecordResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.reqs = append(g.reqs, proto.CloneOf(req))
	if g.err != nil {
		return nil, g.err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &dnsgatev1.PatchRecordResponse{}, nil
}

func (g *fakeGateway) requests() []*dnsgatev1.PatchRecordRequest {
	g.mu.Lock()
	defer g.mu.Unlock()

	return append([]*dnsgatev1.PatchRecordRequest(nil), g.reqs...)
}

func tokenSecret(namespace, name string, data map[string]string) *corev1.Secret {
	s := &corev1.Secret{Namespace: namespace, Name: name, Data: map[string][]byte{}}
	for k, v := range data {
		s.Data[k] = []byte(v)
	}

	return s
}

// newSolver builds and initializes a solver over a fake clientset seeded
// with objects and a fake Gateway.
func newSolver(objects ...runtime.Object) (*solver.Solver, *fakeGateway) {
	s, gw, _ := newSolverWithClientset(objects...)

	return s, gw
}

func newSolverWithClientset(objects ...runtime.Object) (*solver.Solver, *fakeGateway, *fake.Clientset) {
	gw := &fakeGateway{}
	clientset := fake.NewClientset(objects...)
	s := solver.New(solver.Options{
		NewSecrets: func(*restclient.Config) (corev1client.SecretsGetter, error) { return clientset.CoreV1(), nil },
		NewGateway: func() (solver.Gateway, error) { return gw, nil },
		Timeout:    5 * time.Second,
	})

	if err := s.Initialize(&restclient.Config{}, nil); err != nil {
		panic(err)
	}

	return s, gw, clientset
}

// challenge returns a Present request for _acme-challenge.example.com in
// zone example.com, from an Issuer in namespace team-a, with config.
func challenge(config string) *whapi.ChallengeRequest {
	ch := &whapi.ChallengeRequest{
		UID:               "6b0f7a52-0c35-4f0c-9d6c-1f5b1c4c2f55",
		Action:            whapi.ChallengeActionPresent,
		Type:              "dns-01",
		DNSName:           "example.com",
		Key:               validKey,
		ResourceNamespace: "team-a",
		ResolvedFQDN:      "_acme-challenge.example.com.",
		ResolvedZone:      "example.com.",
	}
	if config != "" {
		ch.Config = &apiextensionsv1.JSON{Raw: []byte(config)}
	}

	return ch
}

// wantPresent is the PatchRecord that Present sends with token, zone and
// name.
func wantPresent(token, zone, name string) *dnsgatev1.PatchRecordRequest {
	return &dnsgatev1.PatchRecordRequest{
		Token: token,
		Zone:  zone,
		Name:  name,
		Type:  "TXT",
		Ttl:   600,
		Add:   []*dnsgatev1.RecordValue{{Value: `"` + validKey + `"`}},
	}
}

// checkOneRequest fails t unless gw received exactly want.
func checkOneRequest(t *testing.T, gw *fakeGateway, want *dnsgatev1.PatchRecordRequest) {
	t.Helper()

	reqs := gw.requests()
	if len(reqs) != 1 {
		t.Fatalf("Gateway got %d PatchRecord requests, want 1: %v", len(reqs), reqs)
	}

	if !proto.Equal(reqs[0], want) {
		t.Errorf("PatchRecord request = %v, want %v", reqs[0], want)
	}
}

func TestPresentAddsTheKeyAtTheChallengeTargetThroughTheGateway(t *testing.T) {
	s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

	if err := s.Present(challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)); err != nil {
		t.Fatalf("Present: %v", err)
	}

	checkOneRequest(t, gw, wantPresent("tok-a", "example.com", "_acme-challenge"))
}

func TestTheSolverIsNamedDnsgate(t *testing.T) {
	s, _ := newSolver()

	if got := s.Name(); got != "dnsgate" {
		t.Errorf("Name() = %q, want dnsgate", got)
	}
}

func TestInitializeFailsWhenTheGatewayClientCannotBeBuilt(t *testing.T) {
	s := solver.New(solver.Options{
		NewSecrets: func(*restclient.Config) (corev1client.SecretsGetter, error) { return fake.NewClientset().CoreV1(), nil },
		NewGateway: func() (solver.Gateway, error) { return nil, errors.New("bad target") },
		Timeout:    time.Second,
	})

	checkError(t, s.Initialize(&restclient.Config{}, nil), "building the Gateway client: bad target")
}

func TestInitializeBuildsTheKubernetesClientFromTheGivenConfig(t *testing.T) {
	s := solver.New(solver.Options{
		NewGateway: func() (solver.Gateway, error) { return &fakeGateway{}, nil },
		Timeout:    time.Second,
	})

	// A host that is not a URL makes client-go refuse the config.
	err := s.Initialize(&restclient.Config{Host: "http://[::1"}, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "building the Kubernetes client: ") {
		t.Errorf("error = %v, want one about building the Kubernetes client", err)
	}
}

func TestPresentFailsBeforeInitialize(t *testing.T) {
	gw := &fakeGateway{}
	s := solver.New(solver.Options{
		NewGateway: func() (solver.Gateway, error) { return gw, nil },
		Timeout:    time.Second,
	})

	checkError(t, s.Present(challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)), "the webhook is not initialized yet")
	checkNoRequest(t, gw)
}

func TestPresentReadsTheSecretOnEveryCall(t *testing.T) {
	s, gw, clientset := newSolverWithClientset(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-old"}))

	if err := s.Present(challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)); err != nil {
		t.Fatalf("first Present: %v", err)
	}

	rotated := tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-new"})
	if _, err := clientset.CoreV1().Secrets("team-a").Update(t.Context(), rotated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("rotating the token: %v", err)
	}

	if err := s.Present(challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)); err != nil {
		t.Fatalf("second Present: %v", err)
	}

	reqs := gw.requests()
	if len(reqs) != 2 {
		t.Fatalf("Gateway got %d PatchRecord requests, want 2", len(reqs))
	}

	if got := reqs[1].GetToken(); got != "tok-new" {
		t.Errorf("token after rotation = %q, want tok-new", got)
	}
}

func TestTheGatewayTimeoutDoesNotIncludeTheSecretRead(t *testing.T) {
	gw := &fakeGateway{}
	clientset := fake.NewClientset(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

	const timeout = 50 * time.Millisecond

	// The Secret read takes longer than the whole Gateway timeout.
	clientset.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		time.Sleep(2 * timeout)

		return false, nil, nil
	})

	s := solver.New(solver.Options{
		NewSecrets: func(*restclient.Config) (corev1client.SecretsGetter, error) { return clientset.CoreV1(), nil },
		NewGateway: func() (solver.Gateway, error) { return gw, nil },
		Timeout:    timeout,
	})
	if err := s.Initialize(&restclient.Config{}, nil); err != nil {
		t.Fatal(err)
	}

	if err := s.Present(challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)); err != nil {
		t.Fatalf("Present: %v", err)
	}

	checkOneRequest(t, gw, wantPresent("tok-a", "example.com", "_acme-challenge"))
}

func TestPresentWritesTheChallengeTargetRelativeToTheResolvedZone(t *testing.T) {
	tests := map[string]struct {
		fqdn, zone string
		wantZone   string
		wantName   string
	}{
		"subdomain": {
			fqdn: "_acme-challenge.www.example.com.", zone: "example.com.",
			wantZone: "example.com", wantName: "_acme-challenge.www",
		},
		"apex": {
			fqdn: "_acme-challenge.example.com.", zone: "_acme-challenge.example.com.",
			wantZone: "_acme-challenge.example.com", wantName: "@",
		},
		"no trailing dot": {
			fqdn: "_acme-challenge.www.example.net", zone: "example.net",
			wantZone: "example.net", wantName: "_acme-challenge.www",
		},
		"delegated zone": {
			fqdn: "_acme-challenge.www.example.com.", zone: "www.example.com.",
			wantZone: "www.example.com", wantName: "_acme-challenge",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

			ch := challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)
			ch.ResolvedFQDN, ch.ResolvedZone = tt.fqdn, tt.zone

			if err := s.Present(ch); err != nil {
				t.Fatalf("Present: %v", err)
			}

			checkOneRequest(t, gw, wantPresent("tok-a", tt.wantZone, tt.wantName))
		})
	}
}

func TestPresentRefusesAChallengeTargetOutsideTheResolvedZone(t *testing.T) {
	tests := map[string]struct {
		fqdn, zone string
		want       string
	}{
		"other zone": {
			fqdn: "_acme-challenge.example.org.", zone: "example.com.",
			want: "_acme-challenge.example.org is not in zone example.com",
		},
		"zone is only a suffix of a label": {
			fqdn: "_acme-challenge.myexample.com.", zone: "example.com.",
			want: "_acme-challenge.myexample.com is not in zone example.com",
		},
		"zone below the target": {
			fqdn: "example.com.", zone: "www.example.com.",
			want: "example.com is not in zone www.example.com",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

			ch := challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)
			ch.ResolvedFQDN, ch.ResolvedZone = tt.fqdn, tt.zone

			checkError(t, s.Present(ch), tt.want)
			checkNoRequest(t, gw)
		})
	}
}

func TestPresentFailsWhenTheGatewayFails(t *testing.T) {
	s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))
	gw.err = errors.New("unavailable: connection refused")

	if err := s.Present(challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)); err == nil {
		t.Error("Present = nil, want an error")
	}

	checkOneRequest(t, gw, wantPresent("tok-a", "example.com", "_acme-challenge"))
}

func TestPresentTakesTheTokenFromTheConfiguredSecretAndKey(t *testing.T) {
	tests := map[string]struct {
		config string
		want   string
	}{
		"key defaults to token": {
			config: `{"tokenSecretRef":{"name":"dnsgate"}}`,
			want:   "tok-default",
		},
		"key given": {
			config: `{"tokenSecretRef":{"name":"dnsgate","key":"prod"}}`,
			want:   "tok-prod",
		},
		"other secret": {
			config: `{"tokenSecretRef":{"name":"other"}}`,
			want:   "tok-other",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, gw := newSolver(
				tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-default", "prod": "tok-prod"}),
				tokenSecret("team-a", "other", map[string]string{"token": "tok-other"}),
			)

			if err := s.Present(challenge(tt.config)); err != nil {
				t.Fatalf("Present: %v", err)
			}

			checkOneRequest(t, gw, wantPresent(tt.want, "example.com", "_acme-challenge"))
		})
	}
}

// checkNoRequest fails t if gw received any request.
func checkNoRequest(t *testing.T, gw *fakeGateway) {
	t.Helper()

	if reqs := gw.requests(); len(reqs) != 0 {
		t.Errorf("Gateway got %d PatchRecord requests, want none: %v", len(reqs), reqs)
	}
}

// checkError fails t unless err is an error whose message is want.
func checkError(t *testing.T, err error, want string) {
	t.Helper()

	if err == nil {
		t.Fatalf("error = nil, want %q", want)
	}

	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
}

func TestPresentReadsTheSecretFromTheResourceNamespaceOnly(t *testing.T) {
	secrets := []runtime.Object{
		tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-team-a"}),
		tokenSecret("team-b", "dnsgate", map[string]string{"token": "tok-team-b"}),
		tokenSecret("cert-manager", "dnsgate", map[string]string{"token": "tok-cluster"}),
	}

	tests := map[string]struct {
		resourceNamespace string
		want              string
	}{
		"Issuer in team-a": {resourceNamespace: "team-a", want: "tok-team-a"},
		"Issuer in team-b": {resourceNamespace: "team-b", want: "tok-team-b"},
		"ClusterIssuer":    {resourceNamespace: "cert-manager", want: "tok-cluster"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, gw := newSolver(secrets...)

			ch := challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)
			ch.ResourceNamespace = tt.resourceNamespace

			if err := s.Present(ch); err != nil {
				t.Fatalf("Present: %v", err)
			}

			checkOneRequest(t, gw, wantPresent(tt.want, "example.com", "_acme-challenge"))
		})
	}
}

func TestPresentNeverUsesASecretInAnotherNamespace(t *testing.T) {
	s, gw := newSolver(
		tokenSecret("team-b", "dnsgate", map[string]string{"token": "tok-team-b"}),
		tokenSecret("cert-manager", "dnsgate", map[string]string{"token": "tok-cluster"}),
	)

	err := s.Present(challenge(`{"tokenSecretRef":{"name":"dnsgate"}}`))
	checkError(t, err, "secret team-a/dnsgate not found")
	checkNoRequest(t, gw)
}

func TestPresentRefusesAMissingOrEmptyToken(t *testing.T) {
	tests := map[string]struct {
		secret *corev1.Secret
		config string
		want   string
	}{
		"missing secret": {
			secret: tokenSecret("team-a", "other", map[string]string{"token": "tok"}),
			config: `{"tokenSecretRef":{"name":"dnsgate"}}`,
			want:   "secret team-a/dnsgate not found",
		},
		"missing default key": {
			secret: tokenSecret("team-a", "dnsgate", map[string]string{"prod": "tok"}),
			config: `{"tokenSecretRef":{"name":"dnsgate"}}`,
			want:   `secret team-a/dnsgate has no key "token"`,
		},
		"missing given key": {
			secret: tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok"}),
			config: `{"tokenSecretRef":{"name":"dnsgate","key":"prod"}}`,
			want:   `secret team-a/dnsgate has no key "prod"`,
		},
		"empty value": {
			secret: tokenSecret("team-a", "dnsgate", map[string]string{"token": ""}),
			config: `{"tokenSecretRef":{"name":"dnsgate"}}`,
			want:   `secret team-a/dnsgate key "token" is empty`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, gw := newSolver(tt.secret)

			checkError(t, s.Present(challenge(tt.config)), tt.want)
			checkNoRequest(t, gw)
		})
	}
}

func TestPresentRefusesAnInvalidConfig(t *testing.T) {
	tests := map[string]struct {
		config string
		want   string
	}{
		"unknown field": {
			config: `{"tokenSecretRefs":{"name":"dnsgate"}}`,
			want:   `invalid solver config: unknown field "tokenSecretRefs"`,
		},
		"namespace in the secret ref": {
			config: `{"tokenSecretRef":{"name":"dnsgate","namespace":"team-b"}}`,
			want:   `invalid solver config: unknown field "namespace"`,
		},
		"wrong type": {
			config: `{"tokenSecretRef":{"name":42}}`,
			want:   "invalid solver config: tokenSecretRef.name cannot be a JSON number",
		},
		"not JSON": {
			config: `tokenSecretRef: dnsgate`,
			want:   "invalid solver config: invalid character 'o' in literal true (expecting 'r')",
		},
		"no secret name": {
			config: `{"tokenSecretRef":{"key":"token"}}`,
			want:   "invalid solver config: tokenSecretRef.name is required",
		},
		"no config": {
			config: "",
			want:   "invalid solver config: tokenSecretRef.name is required",
		},
		"not an object": {
			config: `["dnsgate"]`,
			want:   "invalid solver config: not a JSON object",
		},
		"data after the object": {
			config: `{"tokenSecretRef":{"name":"dnsgate"}} {}`,
			want:   "invalid solver config: data after the config object",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

			checkError(t, s.Present(challenge(tt.config)), tt.want)
			checkNoRequest(t, gw)
		})
	}
}
