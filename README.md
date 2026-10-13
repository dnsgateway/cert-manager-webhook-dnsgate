# Cert-Manager Webhook DNSGate

This project provides a webhook for Cert-Manager to integrate with DNSGate for DNS-01 challenges.

## Installation

## Usage

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt
spec:
  acme:
    email: admin@example.com
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-account
    solvers:
      - dns01:
          cnameStrategy: Follow
          webhook:
            groupName: acme.dnsgate.link
            solverName: dnsgate
            config:
              tokenSecretRef:
                name: dnsgate-acme-token
                key: token
```

## Contributing

### End-to-end test

The end-to-end test (`test/e2e/`) issues a real certificate through a webhook already deployed in a cluster. It creates a random namespace, a token Secret, an ACME cert-manager Issuer whose DNS-01 solver is the webhook, and a Certificate for a random name `e2e-<random>.<zone>`. It waits for the Certificate to become Ready, logs the state of its CertificateRequests, Orders and Challenges if it does not, and deletes everything it created, on failure too.

Prerequisites:

- A cluster with cert-manager and this webhook deployed, reached through the current kubeconfig (`$KUBECONFIG`, or `~/.kube/config`), with rights to create namespaces, Secrets and cert-manager resources.
- The webhook may read Secrets in the test's namespace. The chart lets it read Secrets only in cert-manager's cluster resource namespace (`certManager.clusterResourceNamespace`, else `certManager.namespace`), so either grant it access to the test's namespaces or set `DNSGATE_TEST_ISSUER_KIND=ClusterIssuer` (and `DNSGATE_TEST_CLUSTER_RESOURCE_NAMESPACE` if it is not `cert-manager`).
- A zone onboarded at the webhook's Gateway, delegated and served in public DNS, so that the ACME server can check the challenge.
- A Service Token with `patch` on TXT records at `_acme-challenge` names in that zone.

| Variable | Required | Meaning |
| --- | --- | --- |
| `DNSGATE_TEST_TOKEN` | yes | Service Token; the test stores it in the token Secret and never logs it |
| `DNSGATE_TEST_ZONE` | yes | Zone the certificate's name is made in, such as `sandbox.example.org` |
| `DNSGATE_TEST_ACME_SERVER` | no | ACME directory; defaults to Let's Encrypt staging, `https://acme-staging-v02.api.letsencrypt.org/directory` |
| `DNSGATE_TEST_ACME_EMAIL` | no | Email of the ACME account; none by default |
| `DNSGATE_TEST_GROUP_NAME` | no | `groupName` the webhook was deployed with; defaults to `acme.dnsgate.link`, the chart's default |
| `DNSGATE_TEST_ISSUER_KIND` | no | `Issuer` (default), in the test's namespace, or `ClusterIssuer`, whose Secrets the test creates in the cluster resource namespace |
| `DNSGATE_TEST_CLUSTER_RESOURCE_NAMESPACE` | no | cert-manager's cluster resource namespace, used with `ClusterIssuer`; defaults to `cert-manager` |
| `DNSGATE_TEST_TIMEOUT` | no | How long to wait for the Certificate, as a Go duration; defaults to `10m` |

Run it with:

```shell
export DNSGATE_TEST_TOKEN=...
export DNSGATE_TEST_ZONE=sandbox.example.org
make e2e
```

The test is built only with the `e2e` build tag, so `go test ./...` never runs it, and it skips itself when `DNSGATE_TEST_TOKEN` or `DNSGATE_TEST_ZONE` is unset. `make e2e` runs `go test` with a 30 minute timeout; raise it with `E2E_TIMEOUT` along with a longer `DNSGATE_TEST_TIMEOUT`. No CI workflow runs it.

## License

[Apache License 2.0](LICENSE).
