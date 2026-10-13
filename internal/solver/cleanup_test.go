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
	"testing"

	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
)

// cleanUpChallenge returns the CleanUp request for the challenge that
// challenge(config) presents.
func cleanUpChallenge(config string) *whapi.ChallengeRequest {
	ch := challenge(config)
	ch.Action = whapi.ChallengeActionCleanUp

	return ch
}

// wantCleanUp is the PatchRecord that CleanUp sends with token, zone and
// name: it removes the quoted key, with no add and no TTL.
func wantCleanUp(token, zone, name string) *dnsgatev1.PatchRecordRequest {
	return &dnsgatev1.PatchRecordRequest{
		Token:  token,
		Zone:   zone,
		Name:   name,
		Type:   "TXT",
		Remove: []string{`"` + validKey + `"`},
	}
}

func TestCleanUpRemovesTheKeyAtTheChallengeTargetThroughTheGateway(t *testing.T) {
	s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

	if err := s.CleanUp(cleanUpChallenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}

	checkOneRequest(t, gw, wantCleanUp("tok-a", "example.com", "_acme-challenge"))
}

func TestARetriedCleanUpSendsTheSameRemoveAgainAndSucceeds(t *testing.T) {
	s, gw := newSolver(tokenSecret("team-a", "dnsgate", map[string]string{"token": "tok-a"}))

	for i := range 2 {
		if err := s.CleanUp(cleanUpChallenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)); err != nil {
			t.Fatalf("CleanUp %d: %v", i+1, err)
		}
	}

	reqs := gw.requests()
	if len(reqs) != 2 {
		t.Fatalf("Gateway got %d PatchRecord requests, want 2: %v", len(reqs), reqs)
	}

	want := wantCleanUp("tok-a", "example.com", "_acme-challenge")
	for i, req := range reqs {
		if !proto.Equal(req, want) {
			t.Errorf("PatchRecord request %d = %v, want %v", i+1, req, want)
		}
	}
}

func TestCleanUpReadsTheSecretFromTheResourceNamespaceOnly(t *testing.T) {
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

			ch := cleanUpChallenge(`{"tokenSecretRef":{"name":"dnsgate"}}`)
			ch.ResourceNamespace = tt.resourceNamespace

			if err := s.CleanUp(ch); err != nil {
				t.Fatalf("CleanUp: %v", err)
			}

			checkOneRequest(t, gw, wantCleanUp(tt.want, "example.com", "_acme-challenge"))
		})
	}
}

func TestCleanUpRefusesAMissingOrEmptyToken(t *testing.T) {
	tests := map[string]struct {
		secret *corev1.Secret
		config string
		want   string
	}{
		"secret only in another namespace": {
			secret: tokenSecret("team-b", "dnsgate", map[string]string{"token": "tok"}),
			config: `{"tokenSecretRef":{"name":"dnsgate"}}`,
			want:   "secret team-a/dnsgate not found",
		},
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

			checkError(t, s.CleanUp(cleanUpChallenge(tt.config)), tt.want)
			checkNoRequest(t, gw)
		})
	}
}
