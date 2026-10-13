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

package solver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
)

// defaultSecretKey is the key in the token Secret when the config gives
// none.
const defaultSecretKey = "token"

// defaultTTL is the TTL of the challenge values added when the config
// gives none.
const defaultTTL = 600

// config is a cert-manager Issuer's solver config.
type config struct {
	TokenSecretRef secretRef `json:"tokenSecretRef"`
	// Zone is the zone the Challenge Target is written in; empty means
	// the zone cert-manager resolved.
	Zone string `json:"zone"`
	// TTL is the TTL of the challenge values added.
	TTL uint32 `json:"ttl"`
	// Egress is gateway, agent or empty, for the Gateway to choose.
	Egress string `json:"egress"`

	// egress is Egress as the Gateway takes it.
	egress dnsgatev1.Egress
}

// egresses are the egress values of the config and what each asks the
// Gateway for.
var egresses = map[string]dnsgatev1.Egress{
	"":        dnsgatev1.Egress_EGRESS_UNSPECIFIED,
	"gateway": dnsgatev1.Egress_EGRESS_GATEWAY,
	"agent":   dnsgatev1.Egress_EGRESS_AGENT,
}

// secretRef names the Secret, in the request's ResourceNamespace, that
// holds the Service Token.
type secretRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// parseConfig parses raw strictly, with an unknown field as an error, and
// fills in the defaults.
func parseConfig(raw *apiextensionsv1.JSON) (config, error) {
	cfg := config{TTL: defaultTTL}

	if raw != nil && len(raw.Raw) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw.Raw))
		dec.DisallowUnknownFields()

		if err := dec.Decode(&cfg); err != nil {
			return config{}, invalidConfig(decodeError(err))
		}

		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			return config{}, invalidConfig("data after the config object")
		}
	}

	if cfg.TokenSecretRef.Name == "" {
		return config{}, invalidConfig("tokenSecretRef.name is required")
	}

	egress, ok := egresses[cfg.Egress]
	if !ok {
		return config{}, invalidConfig(fmt.Sprintf("egress %q is not gateway or agent", cfg.Egress))
	}

	cfg.egress = egress

	if cfg.TTL == 0 {
		return config{}, invalidConfig("ttl must be positive")
	}

	if cfg.TokenSecretRef.Key == "" {
		cfg.TokenSecretRef.Key = defaultSecretKey
	}

	return cfg, nil
}

// decodeError says why the config did not decode, naming the field at
// fault rather than the Go types behind it.
func decodeError(err error) string {
	if typeErr, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
		if typeErr.Field == "" {
			return "not a JSON object"
		}

		return fmt.Sprintf("%s cannot be a JSON %s", typeErr.Field, typeErr.Value)
	}

	return strings.TrimPrefix(err.Error(), "json: ")
}

func invalidConfig(reason string) error {
	return fmt.Errorf("invalid solver config: %s", reason)
}
