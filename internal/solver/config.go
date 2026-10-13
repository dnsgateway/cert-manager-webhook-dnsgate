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
)

// defaultSecretKey is the key in the token Secret when the config gives
// none.
const defaultSecretKey = "token"

// config is a cert-manager Issuer's solver config.
type config struct {
	TokenSecretRef secretRef `json:"tokenSecretRef"`
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
	var cfg config

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

	if cfg.TokenSecretRef.Key == "" {
		cfg.TokenSecretRef.Key = defaultSecretKey
	}

	return cfg, nil
}

// decodeError says why the config did not decode, naming the field at
// fault rather than the Go types behind it.
func decodeError(err error) string {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
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
