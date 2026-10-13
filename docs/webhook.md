# DNS Gateway — cert-manager Webhook

## Goal

Let cert-manager complete DNS-01 challenges through the Gateway with a native webhook solver. The solver writes each challenge value with the Gateway API, removes it again once validation is over, and never sees a Provider Credential.

The webhook lives in its own repository, `github.com/dnsgateway/cert-manager-webhook-dnsgate`. It is a Gateway client, like `dnsgate-cli` and `dnsgate-acme`, and requires only `github.com/dnsgateway/dnsgate-go`, never `github.com/dnsgateway/dnsgate` ([ADR 0001](adr/0001-gateway-client-in-own-repository.md)).

Webhook terms are defined in [GLOSSARY.md](../GLOSSARY.md), Gateway terms in the [Gateway's glossary](https://github.com/dnsgateway/dnsgate/blob/main/GLOSSARY.md).

---

# Main Principle

As with the ACME Endpoint, ACME is **not** a new kind of authority. A challenge is presented as a `patch` that adds one TXT value, and cleaned up as a `patch` that removes it, both sent to the Gateway with the cert-manager Issuer's own Service Token. The Gateway authorizes them with the token's ordinary Permissions. The webhook holds no keys and no state beyond the in-memory lock of a call in flight, and never opens a token.

The token only authorizes. It never decides where a value is written: cert-manager gives the Challenge Target and its zone, and the webhook passes them on.

DNS resolution never grants permission. cert-manager may follow a CNAME to find the Challenge Target, but the write succeeds only if the token's Permissions cover that target.

---

# Architecture

```text
cert-manager controller
      │  ChallengeRequest (Present / CleanUp)
      ▼
kube-apiserver ── APIService v1alpha1.<groupName> (aggregation, TLS)
      │
      ▼
cert-manager-webhook-dnsgate (pod)
      │  reads the cert-manager Issuer's token Secret through the Kubernetes API
      │  gRPC over TLS: PatchRecord (token unchanged)
      ▼
Gateway ── revocation store
      │  Gateway Egress, or Agent Egress relayed by the webhook pod
      ▼
Provider
```

The webhook is built on cert-manager's webhook framework (`github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd`). It serves an aggregated API that kube-apiserver forwards cert-manager's `ChallengeRequest`s to, and implements the framework's `Solver` interface:

| Method | What it does |
|---|---|
| `Name()` | Returns `dnsgate`, the `solverName` a cert-manager Issuer names. |
| `Initialize(kubeConfig, stop)` | Builds the Kubernetes client used to read token Secrets, and the one Gateway client of the process. |
| `Present(ch)` | Adds `ch.Key` at the Challenge Target. |
| `CleanUp(ch)` | Removes `ch.Key` from the Challenge Target. |

---

# cert-manager Issuer configuration

An Issuer or ClusterIssuer names the webhook in its DNS-01 solver:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-account
    solvers:
      - dns01:
          cnameStrategy: Follow          # optional, for CNAME delegation
          webhook:
            groupName: acme.dnsgate.link
            solverName: dnsgate
            config:
              tokenSecretRef:
                name: dnsgate-acme-token
                key: token
              # all below are optional
              zone: example.com
              ttl: 600
              egress: gateway
```

## Solver config

| Field | Required | Default | Meaning |
|---|---|---|---|
| `tokenSecretRef.name` | yes | none | Secret holding the Service Token |
| `tokenSecretRef.key` | no | `token` | Key in that Secret |
| `zone` | no | cert-manager's `ResolvedZone` | Zone the Challenge Target is written in |
| `ttl` | no | `600` | TTL of the challenge values added. The Gateway refuses one below the Provider's minimum. |
| `egress` | no | unset: the Gateway chooses | `gateway` or `agent` |

The config is parsed strictly: an unknown field is an error, so a typo such as `tokenSecretRefs` fails the challenge instead of being ignored.

The Gateway address and its CA are **not** in the solver config. They are webhook-wide flags (see Flags), so one webhook deployment talks to one Gateway, chosen by the cluster operator and not by whoever may create a cert-manager Issuer. A cert-manager Issuer's author cannot point the webhook at an endpoint of their choice ([ADR 0003](adr/0003-gateway-address-is-deployment-wide.md)).

## Where the Secret is read

The webhook follows cert-manager's own rule for Secrets a cert-manager Issuer refers to:

- For an **Issuer**, the Secret is read from the Issuer's namespace (`ch.ResourceNamespace`).
- For a **ClusterIssuer**, cert-manager sets `ch.ResourceNamespace` to its cluster resource namespace (`cert-manager` by default), and the Secret is read from there.

A user who may create Issuers in namespace `a` can therefore only make the webhook use tokens stored in `a`. The webhook never reads a Secret from a namespace given in the config.

The Secret is read on every `Present` and `CleanUp`, never cached, so rotating or Resealing a token takes effect on the next challenge.

---

# Challenge Target and zone

cert-manager does the DNS work before it calls the webhook:

- `ch.ResolvedFQDN` is the full TXT name to write, such as `_acme-challenge.www.example.com.`. With `cnameStrategy: Follow`, cert-manager has already followed CNAMEs from `_acme-challenge.<domain>`, so CNAME delegation works with no webhook logic.
- `ch.ResolvedZone` is the zone cert-manager found for it by an SOA lookup, such as `example.com.`.

The webhook takes `ResolvedFQDN` as the Challenge Target, and writes it in:

1. `zone` from the solver config, when given. The name must lie in it, or the challenge fails before any Gateway call.
2. Otherwise, `ResolvedZone`.

The name sent to the Gateway is the FQDN made relative to that zone, without the trailing dot (`@` for the apex).

The token's Permissions play no part in this choice ([ADR 0002](adr/0002-zone-from-cert-manager-not-token.md)). This differs from the ACME Endpoint, which has no resolver telling it the zone and so takes it from the token. In every case the choice grants nothing: a wrong zone is refused by the Gateway. Where the cluster's resolvers see zones differently from the Provider (split-horizon DNS), set `zone` explicitly.

---

# How `Present` and `CleanUp` map to Gateway calls

## Present

Checks done locally, before any Gateway call:

```text
ch.Type is "dns-01"?                              → error
config parses, egress valid?                      → error
zone given and ResolvedFQDN not in it?            → error
ch.Key is 43 chars of [A-Za-z0-9_-]?              → error (refused, never written)
read Secret <ResourceNamespace>/<name>[key]      → error if missing or empty
```

The shape check on `ch.Key` is the same as `dnsgate-acme`'s on `txt`: an unpadded base64url SHA-256 digest. It keeps a webhook that is fed a crafted `ChallengeRequest` from writing arbitrary TXT values.

Then one Gateway call, with the token unchanged:

```text
PatchRecord
  token:  the Secret's token
  egress: config egress
  zone:   the zone above
  name:   ResolvedFQDN relative to the zone
  type:   TXT
  ttl:    config ttl
  add:    ["\"<ch.Key>\""]     (TXT presentation form)
```

A value already present is a no-op in `patch`, so a retried `Present` succeeds again.

`patch` applies `ttl` only to the values it adds; values already in the RRset keep their own TTL. An RRset may therefore hold values with different TTLs, which does not matter for validation.

## CleanUp

The same checks and zone, then:

```text
PatchRecord   remove: ["\"<ch.Key>\""]   (no add, no ttl)
```

Removing a value the RRset does not hold changes nothing, so a retried `CleanUp` succeeds. Removing the last value removes the RRset. Other values at the same target, such as the second value cert-manager writes when one certificate holds both `example.com` and `*.example.com`, stay as they are.

`CleanUp` needs a token whose Permissions allow `patch`, which they already do for `Present`. No `delete` verb is needed.

## Concurrent challenges at one target

cert-manager presents the values for `example.com` and `*.example.com` at the same time, at the same Challenge Target: ACME drops the `*.` of a wildcard, so both are TXT values of `_acme-challenge.example.com`. Each `patch` is a read, then a Changeset, inside the Gateway, with no lock on the RRset. On adapters that replace the whole RRset (GoDaddy, Gandi, Hetzner) or the whole domain (Namecheap), two concurrent patches can each succeed while the second write replaces the first, losing a value ([dnsprovider#61](https://github.com/dnsgateway/dnsprovider/issues/61)).

The webhook therefore holds an in-memory **lock per Challenge Target**: `Present` and `CleanUp` for the same target (the zone and relative name, case-folded) run one at a time, for the whole Gateway round trip. Calls for different targets still run in parallel. A call waits for the lock no longer than `--gateway-timeout`, and the round trip after it gets the remaining time. The lock is released when the call ends, and nothing outlives it.

The lock protects only writes made through this webhook pod, so the webhook runs as **a single replica** ([ADR 0004](adr/0004-lock-per-challenge-target-single-replica.md)). It does not protect against other writers of the same RRset; that stays with the Gateway and dnsprovider.

When the Provider's records did change between the Gateway's read and its write, and the adapter detects it, the Gateway returns `CONFLICT`; the webhook passes it on as an error and cert-manager retries. The webhook does not retry on its own.

---

# Tokens for the webhook

An ordinary Derived Token, issued with `dnsgate-cli token create`, one per cert-manager Issuer:

```yaml
# permissions-cert-manager.yaml
permissions:
  - verbs: [patch]
    resources: [records]
    zones: [example.com, example.net]
    names: ["_acme-challenge", "_acme-challenge.**"]
    types: [TXT]
    egress: [gateway]
```

```text
dnsgate-cli token create --sub cert-manager-prod \
    --permissions permissions-cert-manager.yaml --expires 2160h > token
kubectl -n cert-manager create secret generic dnsgate-acme-token --from-file=token
```

- `patch` on TXT at `_acme-challenge` names only, as for ACME Endpoint tokens. For CNAME delegation, add the delegated names instead.
- No `tokens` resource, and a mandatory expiry.

The same caveat as for ACME tokens applies: the shape check on the TXT value runs only in the webhook. Anyone who can read the Secret can call the Gateway directly and add any TXT value the Permissions allow.

---

# Egress

`egress` in the solver config is passed on every `PatchRecord`.

- `gateway`: the Provider sees the Gateway's IP.
- `agent`: the webhook pod relays the Gateway's connection as an Egress Agent, so the Provider sees the cluster's egress IP. The client is built with `client.WithEgressAgent` once, at startup, so the pod can always relay.
- unset: the Gateway chooses (Gateway Egress if the token allows it, else Agent Egress).

---

# Flags

Each flag falls back to an environment variable, then to a default. An environment variable that is set but empty counts as unset, as Helm renders an unset value empty. The Gateway client flags keep the names and environment variables of `dnsgate-cli` and `dnsgate-acme`.

| Flag | Environment variable | Default | Meaning |
|---|---|---|---|
| `--gateway` | `DNSGATE_GATEWAY` | required | Gateway address as `host:port` |
| `--ca-file` | `DNSGATE_CA_FILE` | the system's CAs | CA certificates that verify the Gateway (repeatable) |
| `--gateway-timeout` | `DNSGATE_GATEWAY_TIMEOUT` | `20s` | Bound on the Gateway round trip of one `Present` or `CleanUp`, including the wait for the lock of its Challenge Target |
| `--log-level` | `DNSGATE_WEBHOOK_LOG_LEVEL` | `info` | Lowest level written: `error`, `warn`, `info` or `debug`; applies to the framework's klog lines too, but `warn` filters only the solver's own warnings (see below), and `debug` turns klog's `-v` up to 4 unless `-v` is given |
| `GROUP_NAME` | `GROUP_NAME` | `acme.dnsgate.link` | The API group cert-manager calls; set by the Helm chart |

The webhook framework adds the usual extension API server flags (`--secure-port`, `--tls-cert-file`, `--tls-private-key-file`, and so on) and klog's logging flags. The webhook's own `--logging-format`, `dnsgate`, is the default: JSON lines on stderr at `--log-level` and above, for the webhook's lines and the framework's alike. `--log-level warn` filters only the solver's own warnings: klog hands its warnings to the logger as info lines, with nothing that marks them as warnings, so `warn` drops the framework's warnings along with its info lines, and `info` shows them as info lines. ([ADR 0005](adr/0005-own-log-format-is-the-default.md)) With `--logging-format=text` or `json`, klog's own format writes every line, and `--log-level` only turns the verbosity up for `debug`.

The webhook stops at startup when `--gateway` is missing, `--gateway` is not a `host:port`, or a `--ca-file` cannot be read.

---

# Errors

cert-manager shows a solver's error in the Challenge's status and retries with backoff. The webhook returns errors whose messages name the cause without any secret:

| Cause | Error message (example) | Retry helps |
|---|---|---|
| Challenge not DNS-01 | `the challenge is not dns-01` | no |
| Config invalid | `invalid solver config: unknown field "tokenSecretRefs"` | no |
| Name not in the configured zone | `_acme-challenge.www.example.org is not in zone example.com` | no |
| Secret or key missing | `secret cert-manager/dnsgate-acme-token has no key "token"` | after a fix |
| Key not a challenge value | `challenge key is not a 43-character base64url value` | no |
| Unauthenticated (bad, expired or revoked token) | `the Gateway refused the token` | after a fix |
| Permission denied by the Gateway, Egress included | `the token does not allow patch on TXT at _acme-challenge.www in example.com` | after a fix |
| Denied by the Provider | `the Provider refused the request: <provider status>` | maybe |
| Invalid record: TTL out of range | `the Gateway refused TTL 30: check ttl against the Provider's range` | after a fix |
| Conflict: the RRset changed at the Provider during the write | `the Gateway call failed: conflict` | yes |
| Rate limited, Provider failure, Gateway unreachable or timed out | `the Gateway call failed: <category>` | yes |
| Another call held the Challenge Target for the whole timeout | `timed out after 20s waiting for another call at _acme-challenge.www.example.com` | yes |

The Gateway's error messages never quote the token, so they may be passed on. The Challenge's status is readable by anyone who can read Challenges in the namespace, so nothing else from the request goes into it.

---

# Logging and security

- **The token is never logged**, nor any header or metadata that carries it. Log lines carry the Challenge's UID, namespace, DNS name, Challenge Target, zone, action, result and duration, never `ch.Key`.
- **Secret access.** The webhook needs `get` on Secrets. Kubernetes RBAC cannot limit that to the Secrets that cert-manager Issuers name, so the chart offers two modes:
  - a ClusterRole for `get` on Secrets in every namespace, needed when namespaced Issuers use the webhook;
  - a Role in the cert-manager namespace only, for clusters that use only ClusterIssuers. This is the default.

  This is the same trade-off every cert-manager DNS webhook makes: whoever compromises the pod can read the tokens it may read.
- **Who can call the webhook.** Only kube-apiserver reaches the webhook, through the APIService, and only principals granted `create` on `<groupName>/dnsgate` can call it. The chart grants that to cert-manager's ServiceAccount only. A crafted `ChallengeRequest` still cannot name a Secret outside its `ResourceNamespace`, and a principal who can create `ChallengeRequest`s can already create Issuers.
- **Gateway TLS** is always on. There is no flag to skip verifying the Gateway.

---

# Deployment

The repository ships a Helm chart, `charts/cert-manager-webhook-dnsgate`, shaped like cert-manager's example webhook chart:

- Deployment with exactly one replica and the `Recreate` strategy, so two pods never write at once, not even during an upgrade (see Concurrent challenges at one target); Service; ServiceAccount;
- `APIService v1alpha1.<groupName>`, its serving certificate issued by cert-manager itself (a self-signed Issuer and CA), injected with `cert-manager.io/inject-ca-from`;
- RBAC: `system:auth-delegator`, `extension-apiserver-authentication-reader`, the domain-solver ClusterRole that lets cert-manager's ServiceAccount create `<groupName>/dnsgate`, flowcontrol read, and the Secret access above;
- values for `groupName`, `gateway.address`, `gateway.caSecret`, `secretAccess: clusterIssuersOnly | allNamespaces`;
- a NetworkPolicy allowing ingress from kube-apiserver and egress to the Gateway, plus the Provider's API when `agent` egress is used.

The image is published as `ghcr.io/dnsgateway/cert-manager-webhook-dnsgate`, built with goreleaser like `dnsgate`.

---

# Repository

```text
cert-manager-webhook-dnsgate/
  cmd/                    server.NewCommandStartWebhookServer(ctx, groupName, solver) + the webhook's own flags
  internal/solver/        Solver: config, Secret lookup, zone, Present, CleanUp
  charts/cert-manager-webhook-dnsgate/
  test/e2e/               end-to-end test against a deployed webhook
  Dockerfile, .goreleaser.yaml, Makefile
```

- Licence: Apache 2.0, like dnsgate-go and cert-manager.
- Module requires `github.com/dnsgateway/dnsgate-go` and cert-manager. It must track cert-manager's supported Kubernetes versions, which drive its `k8s.io/*` versions.
- Versioned on its own, with the chart's `appVersion` following the image.

## Tests

- **Unit tests** for config parsing, the namespace rule, the zone, and the mapping of Gateway errors, against a fake `Solver` client interface around `client.Client`.
- **An end-to-end test** (`test/e2e/`, `make e2e`) against a cluster where cert-manager and the webhook are already deployed. It creates a namespace, a token Secret and an ACME cert-manager Issuer (Let's Encrypt staging by default) whose DNS-01 solver is the webhook, issues a Certificate for a random name in a test zone, waits for it to become Ready, then deletes everything it created. It needs a zone served in public DNS by a real Provider behind the Gateway, and a Service Token with `patch` on TXT records at `_acme-challenge` names in it. It is built only with the `e2e` build tag, skips itself when its settings are unset, and is run by hand; no CI workflow runs it. Its settings are in the README.

There are no integration tests against an in-process Gateway: none can be started from another module. See Open Questions.

---

# Out of scope

- HTTP-01 challenges.
- Reading the Provider Credential or calling any Provider directly. The webhook only calls the Gateway.
- Choosing the zone from the token's Permissions.
- More than one replica, or a lock shared between pods.
- Multiple Gateways per webhook deployment. Run a second deployment with its own `groupName`.
- Per-Issuer Gateway address or CA.
- Cleaning up values left at a Challenge Target by earlier clients, such as the ACME Endpoint.
- Bound Tokens and Identity Tokens. Whether and how the webhook supports them is decided in a later release, once the Gateway supports Identity Tokens.

---

# Open Questions

- **Lost values on concurrent patches from other writers.** The webhook's lock per Challenge Target covers only its own calls. The Gateway has no lock on an RRset, and adapters that replace a whole RRset or domain (GoDaddy, Gandi, Hetzner, Namecheap) can lose a value written concurrently by another client. Investigated in [dnsprovider#61](https://github.com/dnsgateway/dnsprovider/issues/61); a lock per RRset in the Gateway is the remaining defence.
- **A test Gateway for other modules.** dnsgate's in-process test Gateway (`internal/server/servertest`) cannot be imported. A public helper, such as `dnsgate/gatewaytest` backed by `dnsprovider/providertest`, would let this repository run integration tests.

---

# Decisions

- [ADR 0001](adr/0001-gateway-client-in-own-repository.md): The cert-manager Webhook is a Gateway client in its own repository.
- [ADR 0002](adr/0002-zone-from-cert-manager-not-token.md): The zone comes from the solver config or cert-manager, never from the token.
- [ADR 0003](adr/0003-gateway-address-is-deployment-wide.md): The Gateway address and CA are deployment-wide.
- [ADR 0004](adr/0004-lock-per-challenge-target-single-replica.md): A lock per Challenge Target, with a single replica.
- [ADR 0005](adr/0005-own-log-format-is-the-default.md): The webhook's own log format is the default `--logging-format`.
