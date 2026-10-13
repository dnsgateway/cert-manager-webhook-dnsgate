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

package e2e

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

func TestReadSettingsNamesEveryMissingVariable(t *testing.T) {
	_, missing, err := readSettings(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"DNSGATE_TEST_TOKEN", "DNSGATE_TEST_ZONE"}
	if !slices.Equal(missing, want) {
		t.Errorf("missing = %v, want %v", missing, want)
	}
}

func TestReadSettingsFillsInTheDefaults(t *testing.T) {
	vars := map[string]string{
		"DNSGATE_TEST_TOKEN": "dgt_secret",
		"DNSGATE_TEST_ZONE":  "sandbox.example.org.",
	}

	got, missing, err := readSettings(func(k string) string { return vars[k] })
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing = %v, err = %v, want neither", missing, err)
	}

	want := settings{
		token:                    "dgt_secret",
		zone:                     "sandbox.example.org",
		acmeServer:               "https://acme-staging-v02.api.letsencrypt.org/directory",
		groupName:                "acme.dnsgate.link",
		issuerKind:               "ClusterIssuer",
		clusterResourceNamespace: "cert-manager",
		timeout:                  10 * time.Minute,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("settings = %+v, want %+v", got, want)
	}
}

func TestReadSettingsTakesTheOverrides(t *testing.T) {
	vars := map[string]string{
		"DNSGATE_TEST_TOKEN":                      "dgt_secret",
		"DNSGATE_TEST_ZONE":                       "sandbox.example.org",
		"DNSGATE_TEST_ACME_SERVER":                "https://acme.example.net/directory",
		"DNSGATE_TEST_ACME_EMAIL":                 "ops@example.org",
		"DNSGATE_TEST_GROUP_NAME":                 "acme.example.org",
		"DNSGATE_TEST_ISSUER_KIND":                "ClusterIssuer",
		"DNSGATE_TEST_CLUSTER_RESOURCE_NAMESPACE": "certs",
		"DNSGATE_TEST_TIMEOUT":                    "3m30s",
	}

	got, _, err := readSettings(func(k string) string { return vars[k] })
	if err != nil {
		t.Fatal(err)
	}

	want := settings{
		token:                    "dgt_secret",
		zone:                     "sandbox.example.org",
		acmeServer:               "https://acme.example.net/directory",
		acmeEmail:                "ops@example.org",
		groupName:                "acme.example.org",
		issuerKind:               "ClusterIssuer",
		clusterResourceNamespace: "certs",
		timeout:                  3*time.Minute + 30*time.Second,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("settings = %+v, want %+v", got, want)
	}
}

func TestReadSettingsRefusesBadValues(t *testing.T) {
	for name, vars := range map[string]map[string]string{
		"timeout not a duration": {"DNSGATE_TEST_TIMEOUT": "ten minutes"},
		"timeout not positive":   {"DNSGATE_TEST_TIMEOUT": "0s"},
		"unknown issuer kind":    {"DNSGATE_TEST_ISSUER_KIND": "issuer"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := readSettings(func(k string) string { return vars[k] }); err == nil {
				t.Error("err = nil, want an error")
			}
		})
	}
}

func TestNewNamesMakesEveryNameFromOneRandomSuffix(t *testing.T) {
	r := bytes.NewReader([]byte{0, 1, 25, 26, 35, 36, 71, 200})

	got, err := newNames(r, "sandbox.example.org")
	if err != nil {
		t.Fatal(err)
	}

	want := names{
		namespace:     "dnsgate-e2e-abz09a9u",
		issuer:        "dnsgate-e2e-abz09a9u",
		tokenSecret:   "dnsgate-e2e-abz09a9u-token",
		accountSecret: "dnsgate-e2e-abz09a9u-account",
		certificate:   "e2e",
		tlsSecret:     "e2e-tls",
		host:          "e2e-abz09a9u.sandbox.example.org",
	}
	if got != want {
		t.Errorf("names = %+v, want %+v", got, want)
	}
}

func TestNewIssuerSolvesDNS01WithTheWebhook(t *testing.T) {
	s := settings{
		acmeServer: "https://acme.example.net/directory",
		acmeEmail:  "ops@example.org",
		groupName:  "acme.dnsgate.link",
		issuerKind: kindIssuer,
	}
	n := names{namespace: "ns", issuer: "iss", tokenSecret: "iss-token", accountSecret: "iss-account"}

	iss := newIssuer(s, n)
	if iss.Name != "iss" || iss.Namespace != "ns" {
		t.Errorf("issuer is %s/%s, want ns/iss", iss.Namespace, iss.Name)
	}

	assertJSON(t, iss.Spec, `{
		"acme": {
			"email": "ops@example.org",
			"server": "https://acme.example.net/directory",
			"privateKeySecretRef": {"name": "iss-account"},
			"solvers": [{
				"dns01": {
					"webhook": {
						"groupName": "acme.dnsgate.link",
						"solverName": "dnsgate",
						"config": {"tokenSecretRef": {"name": "iss-token", "key": "token"}}
					}
				}
			}]
		}
	}`)
}

func TestNewClusterIssuerHasTheIssuerSpec(t *testing.T) {
	s := settings{acmeServer: "https://acme.example.net/directory", groupName: "acme.example.org", issuerKind: kindClusterIssuer}
	n := names{namespace: "ns", issuer: "iss", tokenSecret: "iss-token", accountSecret: "iss-account"}

	ciss := newClusterIssuer(s, n)
	if ciss.Name != "iss" || ciss.Namespace != "" {
		t.Errorf("cluster issuer is %q/%q, want cluster-scoped iss", ciss.Namespace, ciss.Name)
	}

	if !reflect.DeepEqual(ciss.Spec, newIssuer(s, n).Spec) {
		t.Errorf("cluster issuer spec = %+v, want the issuer's", ciss.Spec)
	}
}

func TestNewTokenSecretIsWhereTheWebhookReadsIt(t *testing.T) {
	n := names{namespace: "ns", tokenSecret: "iss-token"}

	for kind, wantNamespace := range map[string]string{
		kindIssuer:        "ns",
		kindClusterIssuer: "cert-manager",
	} {
		t.Run(kind, func(t *testing.T) {
			s := settings{token: "dgt_secret", issuerKind: kind, clusterResourceNamespace: "cert-manager"}

			sec := newTokenSecret(s, n)
			if sec.Namespace != wantNamespace || sec.Name != "iss-token" {
				t.Errorf("secret is %s/%s, want %s/iss-token", sec.Namespace, sec.Name, wantNamespace)
			}

			if got := string(sec.Data["token"]); got != "dgt_secret" {
				t.Error("secret key token does not hold the Service Token")
			}
		})
	}
}

func TestNewCertificateIsForTheHostFromTheIssuer(t *testing.T) {
	n := names{namespace: "ns", issuer: "iss", certificate: "e2e", tlsSecret: "e2e-tls", host: "e2e-x.sandbox.example.org"}

	for _, kind := range []string{kindIssuer, kindClusterIssuer} {
		t.Run(kind, func(t *testing.T) {
			crt := newCertificate(settings{issuerKind: kind}, n)
			if crt.Name != "e2e" || crt.Namespace != "ns" {
				t.Errorf("certificate is %s/%s, want ns/e2e", crt.Namespace, crt.Name)
			}

			assertJSON(t, crt.Spec, `{
				"dnsNames": ["e2e-x.sandbox.example.org"],
				"secretName": "e2e-tls",
				"issuerRef": {"name": "iss", "kind": "`+kind+`", "group": "cert-manager.io"}
			}`)
		})
	}
}

// assertJSON fails t unless v encodes to the same JSON as want.
func assertJSON(t *testing.T, v any, want string) {
	t.Helper()

	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	var got, wantV any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal([]byte(want), &wantV); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(got, wantV) {
		t.Errorf("JSON = %s, want %s", data, want)
	}
}

func TestCertificateReadyOnlyWithReadyTrue(t *testing.T) {
	for name, tc := range map[string]struct {
		conditions []cmv1.CertificateCondition
		want       bool
	}{
		"no conditions": {nil, false},
		"ready false":   {[]cmv1.CertificateCondition{{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionFalse}}, false},
		"issuing only":  {[]cmv1.CertificateCondition{{Type: cmv1.CertificateConditionIssuing, Status: cmmeta.ConditionTrue}}, false},
		"ready true": {[]cmv1.CertificateCondition{
			{Type: cmv1.CertificateConditionIssuing, Status: cmmeta.ConditionFalse},
			{Type: cmv1.CertificateConditionReady, Status: cmmeta.ConditionTrue},
		}, true},
	} {
		t.Run(name, func(t *testing.T) {
			crt := &cmv1.Certificate{Status: cmv1.CertificateStatus{Conditions: tc.conditions}}
			if got := certificateReady(crt); got != tc.want {
				t.Errorf("certificateReady = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNewNamesFailsWithoutEnoughRandomness(t *testing.T) {
	if _, err := newNames(bytes.NewReader([]byte{1, 2, 3}), "sandbox.example.org"); err == nil {
		t.Error("err = nil, want an error")
	}
}
