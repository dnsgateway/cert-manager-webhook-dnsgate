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
	"context"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	cmv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// pollInterval is how often the test looks at what it waits for.
const pollInterval = 5 * time.Second

// cleanupTimeout bounds each wait while cleaning up.
const cleanupTimeout = 2 * time.Minute

// TestIssueCertificate issues a certificate for a random name in the test
// zone through the cert-manager Webhook deployed in the cluster of the
// current kubeconfig, then deletes everything it created.
func TestIssueCertificate(t *testing.T) {
	s, missing, err := readSettings(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}

	if len(missing) > 0 {
		t.Skipf("set %s to issue a certificate end to end", strings.Join(missing, ", "))
	}

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		t.Fatalf("loading kubeconfig: %v", err)
	}

	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cm, err := cmclient.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	n, err := newNames(rand.Reader, s.zone)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("issuing a certificate for %s from %s %s in namespace %s", n.host, s.issuerKind, n.issuer, n.namespace)

	// Registered before anything is created, so that it runs on every
	// failure below.
	t.Cleanup(func() { cleanUp(t, kube, cm, s, n) })

	ctx := t.Context()

	if _, err := kube.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		Name: n.namespace,
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating namespace: %v", err)
	}

	sec := newTokenSecret(s, n)
	if _, err := kube.CoreV1().Secrets(sec.Namespace).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
		// The error names the Secret, never its data.
		t.Fatalf("creating token Secret: %v", err)
	}

	if s.issuerKind == kindClusterIssuer {
		_, err = cm.CertmanagerV1().ClusterIssuers().Create(ctx, newClusterIssuer(s, n), metav1.CreateOptions{})
	} else {
		_, err = cm.CertmanagerV1().Issuers(n.namespace).Create(ctx, newIssuer(s, n), metav1.CreateOptions{})
	}

	if err != nil {
		t.Fatalf("creating %s: %v", s.issuerKind, err)
	}

	if _, err := cm.CertmanagerV1().Certificates(n.namespace).Create(ctx, newCertificate(s, n), metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating Certificate: %v", err)
	}

	start := time.Now()

	err = wait.PollUntilContextTimeout(ctx, pollInterval, s.timeout, true, func(ctx context.Context) (bool, error) {
		crt, err := cm.CertmanagerV1().Certificates(n.namespace).Get(ctx, n.certificate, metav1.GetOptions{})
		if err != nil {
			t.Logf("getting Certificate: %v", err)

			return false, nil
		}

		return certificateReady(crt), nil
	})
	if err != nil {
		report(t, cm, n)
		t.Fatalf("Certificate not Ready after %s: %v", s.timeout, err)
	}

	t.Logf("Certificate Ready after %s", time.Since(start).Round(time.Second))
}

// report logs the state of the run's Certificate and of the
// CertificateRequests, Orders and Challenges cert-manager made for it.
func report(t *testing.T, cm cmclient.Interface, n names) {
	t.Helper()

	// The test's context may be done already.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), cleanupTimeout)
	defer cancel()

	if crt, err := cm.CertmanagerV1().Certificates(n.namespace).Get(ctx, n.certificate, metav1.GetOptions{}); err != nil {
		t.Logf("getting Certificate: %v", err)
	} else {
		logConditions(t, "Certificate "+crt.Name, crt.Status.Conditions)
	}

	if crs, err := cm.CertmanagerV1().CertificateRequests(n.namespace).List(ctx, metav1.ListOptions{}); err != nil {
		t.Logf("listing CertificateRequests: %v", err)
	} else {
		for _, cr := range crs.Items {
			for _, c := range cr.Status.Conditions {
				t.Logf("CertificateRequest %s: %s=%s %s: %s", cr.Name, c.Type, c.Status, c.Reason, c.Message)
			}
		}
	}

	if orders, err := cm.AcmeV1().Orders(n.namespace).List(ctx, metav1.ListOptions{}); err != nil {
		t.Logf("listing Orders: %v", err)
	} else {
		for _, o := range orders.Items {
			t.Logf("Order %s: state %q, reason %q", o.Name, o.Status.State, o.Status.Reason)
		}
	}

	if chs, err := cm.AcmeV1().Challenges(n.namespace).List(ctx, metav1.ListOptions{}); err != nil {
		t.Logf("listing Challenges: %v", err)
	} else {
		for _, ch := range chs.Items {
			t.Logf("Challenge %s for %s: state %q, presented %v, processing %v, reason %q",
				ch.Name, ch.Spec.DNSName, ch.Status.State, ch.Status.Presented, ch.Status.Processing, ch.Status.Reason)
		}
	}
}

func logConditions(t *testing.T, what string, conditions []cmv1.CertificateCondition) {
	t.Helper()

	for _, c := range conditions {
		t.Logf("%s: %s=%s %s: %s", what, c.Type, c.Status, c.Reason, c.Message)
	}
}

// cleanUp deletes what the run created, whether it got that far or not.
// It deletes the Certificate and waits for its Challenges to go before
// deleting the namespace, and deletes a ClusterIssuer's Secrets last, so
// that the webhook can still read the Service Token to clean up the
// values it presented.
func cleanUp(t *testing.T, kube kubernetes.Interface, cm cmclient.Interface, s settings, n names) {
	t.Helper()

	// The test's context is done by the time cleanups run.
	ctx := context.WithoutCancel(t.Context())

	check := func(what string, err error) {
		if err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("deleting %s: %v", what, err)
		}
	}

	check("Certificate", cm.CertmanagerV1().Certificates(n.namespace).Delete(ctx, n.certificate, metav1.DeleteOptions{}))

	waitGone(ctx, t, "Challenges", func(ctx context.Context) (bool, error) {
		chs, err := cm.AcmeV1().Challenges(n.namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		return len(chs.Items) == 0, nil
	})

	check("namespace", kube.CoreV1().Namespaces().Delete(ctx, n.namespace, metav1.DeleteOptions{}))

	waitGone(ctx, t, "namespace", func(ctx context.Context) (bool, error) {
		_, err := kube.CoreV1().Namespaces().Get(ctx, n.namespace, metav1.GetOptions{})

		return apierrors.IsNotFound(err), nil
	})

	if s.issuerKind != kindClusterIssuer {
		return
	}

	check("ClusterIssuer", cm.CertmanagerV1().ClusterIssuers().Delete(ctx, n.issuer, metav1.DeleteOptions{}))

	for _, name := range []string{n.tokenSecret, n.accountSecret} {
		check("Secret "+name, kube.CoreV1().Secrets(s.clusterResourceNamespace).Delete(ctx, name, metav1.DeleteOptions{}))
	}
}

// waitGone waits, for at most cleanupTimeout, until gone reports true,
// and fails t if it does not.
func waitGone(ctx context.Context, t *testing.T, what string, gone wait.ConditionWithContextFunc) {
	t.Helper()

	if err := wait.PollUntilContextTimeout(ctx, pollInterval, cleanupTimeout, true, gone); err != nil {
		t.Errorf("waiting for %s to go: %v", what, err)
	}
}
