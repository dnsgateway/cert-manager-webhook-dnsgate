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
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// readToken reads the Service Token that ref names from the Secret in
// namespace. It reads it on every call and never caches it, so a rotated
// token takes effect on the next challenge. The token is returned
// unchanged.
func readToken(ctx context.Context, secrets corev1client.SecretsGetter, namespace string, ref secretRef) (string, error) {
	name := namespace + "/" + ref.Name

	secret, err := secrets.Secrets(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return "", fmt.Errorf("secret %s not found", name)
	}

	if err != nil {
		return "", fmt.Errorf("reading secret %s: %w", name, err)
	}

	token, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("secret %s has no key %q", name, ref.Key)
	}

	if len(token) == 0 {
		return "", fmt.Errorf("secret %s key %q is empty", name, ref.Key)
	}

	return string(token), nil
}
