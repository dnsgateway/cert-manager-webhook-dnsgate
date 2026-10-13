# cert-manager Webhook for DNS Gateway

Issue and renew TLS certificates with cert-manager using DNS Gateway for DNS-01
challenges. The webhook adds and removes challenge TXT values through the Gateway
with a scoped Service Token. Provider credentials remain with the Gateway.

## Goals

- Support certificates for ordinary and wildcard domains through cert-manager.
- Limit DNS access to the zones, names and record types allowed by each token.
- Preserve other TXT values when presenting or cleaning up a challenge.
- Support CNAME delegation through cert-manager's `cnameStrategy: Follow`.
- Let operators choose Gateway Egress or Agent Egress from the webhook pod.

Each deployment connects to one Gateway over verified TLS. Calls for the same
challenge target are serialized within the webhook process, so run one replica
and use the `Recreate` deployment strategy. See [architecture and configuration](docs/webhook.md)
for details.

## Install

You need:

- A Kubernetes cluster with cert-manager installed, including its CRDs and CA injector.
- Helm and kubectl configured for that cluster.
- A DNS Gateway reachable from the webhook pod, with your zone onboarded and served in public DNS.
- A webhook container image available to the cluster.

Create `webhook-values.yaml`. Replace the image tag and Gateway address with
values for your deployment:

```yaml
# Adjust the following values for your deployment, if necessary.
certManager:
  namespace: cert-manager
  serviceAccountName: cert-manager

args:
  - --gateway=gateway.example.org:443
```

The Gateway certificate is verified against system CAs by default. For a private
CA, create a Secret in the webhook namespace:

```sh
kubectl -n cert-manager create secret generic dnsgate-gateway-ca \
  --from-file=ca.crt=/path/to/gateway-ca.pem
```

Then add the CA mount to `webhook-values.yaml` and append the flag to `args`:

```yaml
volumes:
  - name: gateway-ca
    secret:
      secretName: dnsgate-gateway-ca
volumeMounts:
  - name: gateway-ca
    mountPath: /etc/dnsgate/ca
    readOnly: true
args:
  - --gateway=gateway.example.org:443
  - --ca-file=/etc/dnsgate/ca/ca.crt
```

Install the webhook and check that its aggregated API is available:

```sh
helm upgrade --install dnsgate oci://ghcr.io/dnsgateway/cert-manager-webhook-dnsgate \
  --namespace cert-manager \
  --values webhook-values.yaml \
  --wait --timeout 5m
```

The chart uses cert-manager to issue the webhook's serving certificate. This is
separate from the CA used to verify the Gateway. Match `certManager` settings to
your cert-manager installation and use the same `groupName` in your cert-manager
Issuer configuration.

## Create a Service Token

Use `dnsgate-cli` with an existing Parent Token that permits `create` on `tokens`
and covers the requested DNS permissions. Configure the CLI for the same Gateway
as the webhook and supply the Parent Token through `DNSGATE_TOKEN`. See the
[DNS Gateway project](https://github.com/dnsgateway/dnsgate) for CLI setup and zone onboarding.

Create `permissions-cert-manager.yaml`, replacing `example.com` with your zone:

```yaml
permissions:
  - verbs: [patch]
    resources: [records]
    zones: [example.com]
    names: ["_acme-challenge", "_acme-challenge.**"]
    types: [TXT]
    egress: [gateway]
```

These permissions cover challenge names for the zone and its subdomains. For
CNAME delegation, grant access to the delegated target's zone and name. To use
Agent Egress, allow `agent` in the token and set `egress: agent` in the solver config.

Create an expiring Derived Token and store it in a Kubernetes Secret:

```sh
umask 077
dnsgate-cli token create --sub cert-manager-prod \
  --permissions permissions-cert-manager.yaml --expires 2160h > token
kubectl -n cert-manager create secret generic dnsgate-acme-token \
  --from-file=token
rm token
```

The example token expires after 90 days; rotate it before expiry. The webhook
reads the Secret on every Present and CleanUp call, so Secret updates take effect
on the next call. Keep the token file and Parent Token out of version control.

For a `ClusterIssuer`, store the token Secret in cert-manager's cluster resource
namespace (`cert-manager` in these examples). The chart grants reads there.
For a namespaced `Issuer`, store it in that Issuer's namespace and grant the
webhook ServiceAccount additional Secret-read RBAC in that namespace.

## Configure certificate issuance

Save this as `clusterissuer.yaml`, replace the email address, and apply it with
`kubectl apply -f clusterissuer.yaml`:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    email: admin@example.com
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-staging-account
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

Then create a Certificate in your application's namespace, replacing the domains
with names in your zone:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-com
  namespace: default
spec:
  secretName: example-com-tls
  issuerRef:
    name: letsencrypt-staging
    kind: ClusterIssuer
  dnsNames:
    - example.com
    - "*.example.com"
```

Apply the Certificate and check its Ready condition. cert-manager writes the
certificate and private key to `example-com-tls` in the Certificate's namespace.
The staging certificate is untrusted; once validation works, create a production
ClusterIssuer using `https://acme-v02.api.letsencrypt.org/directory` and a distinct
ACME account Secret, then update the Certificate's `issuerRef`.

## Contributing

[Contributing instructions](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE).
