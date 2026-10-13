# Development and contributing

This repository implements the cert-manager Webhook for DNS Gateway. cert-manager
calls its aggregated Kubernetes API to present and clean up DNS-01 challenge
values; the webhook reads a Service Token from a Kubernetes Secret and sends
`PatchRecord` requests to the Gateway.

Read [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution policy,
[GLOSSARY.md](../GLOSSARY.md) for terminology, and
[webhook.md](webhook.md) and the [architecture decisions](adr/) for design context.
The commands below describe the current implementation; some design notes and
the README describe behavior that differs from the checked-in code.

## Prerequisites

Run commands from the repository root. For ordinary Go development, install:

- Git and Make.
- Go compatible with `go.mod` (currently Go 1.27.0).
- golangci-lint compatible with `.golangci.yml`; CI uses v2.14.0.
- A C compiler for `go test -race`, even though the release binary disables CGO.

Additional tools depend on the work:

| Work | Tools or services |
| --- | --- |
| Chart linting and rendering | Helm; chart-testing (`ct`) for the CI chart checks |
| Commit and license-header conformance | Docker |
| Dependency license checks | `go-licenses` |
| Release configuration and snapshots | GoReleaser (CI uses v2.18.3); Docker with Buildx for images |
| End-to-end testing | A kubeconfig, a cluster with cert-manager and this webhook deployed, a real Gateway, a public DNS zone and a Service Token |

The module downloads `dnsgate-go` as a dependency; sibling Gateway, client and
Provider repositories are not required for unit tests or a normal build.
`go.work` and `go.work.sum` are ignored for optional local workspace development.

## Start developing

```sh
git clone https://github.com/dnsgateway/cert-manager-webhook-dnsgate.git
cd cert-manager-webhook-dnsgate
make help
make build
./bin/cert-manager-webhook-dnsgate --help
```

Choose a branch name appropriate to your change. `make build` writes
`bin/cert-manager-webhook-dnsgate`, disables CGO and embeds the version and commit
derived from Git. `GOOS` and `GOARCH` can override the build platform:

```sh
make build GOOS=linux GOARCH=arm64
```

`bin/` is ignored. `make clean` removes it.

## Find the relevant code

| Path | Responsibility |
| --- | --- |
| `cmd/main.go` | Server command, solver initialization and the TLS Gateway client |
| `cmd/flags.go` | Flags, environment defaults and startup validation |
| `cmd/log.go` | Shared logging format and level handling |
| `internal/solver/` | Config validation, Secret lookup, challenge target selection, Present/CleanUp, Gateway errors and locking |
| `test/e2e/` | Certificate issuance against an existing deployment and unit tests for test setup |

The solver's `Gateway` interface requires only `PatchRecord`. Its `Options`
inject Gateway and Secret clients and optionally a logger. Existing solver tests
use a fake Gateway and a fake Kubernetes clientset; use those seams to test
behavior without a live cluster. Command tests also exercise Gateway transport
and Agent Egress behavior through a local test server.

When changing behavior, preserve the established boundaries:

- Gateway address and trust configuration belong to the deployment, not to a
  cert-manager Issuer's solver config.
- The target and zone come from cert-manager or the explicit config, never from
  token Permissions. Forward the token unchanged.
- Read the token from `ChallengeRequest.ResourceNamespace` on each call.
- Present adds only the requested TXT value; CleanUp removes only that value.
- Serialize Gateway calls at the same challenge target. The lock is local to
  one process; it does not protect writes from another pod or client.
- Let cert-manager retry failures. The Gateway connection disables gRPC retries.
- Keep tokens and challenge keys out of logs and returned error messages.

Update the related tests and documentation when changing these behaviors, and
record architectural changes in `docs/adr/`.

## Format and check Go changes

`.golangci.yml` defines the linters and formatters (`gci`, `gofmt`, `gofumpt` and
`goimports`). Its import groups are standard library, other dependencies,
`github.com/dnsgateway` dependencies, then this module.

```sh
make unit
make lint
make vet
make build

# Run end-to-end tests with the ordinary credentials
env -u DNSGATE_TEST_TOKEN -u DNSGATE_TEST_ZONE make e2e
```

The formatter may touch multiple files; inspect the diff before committing.
`make unit` runs `go test -race -count=1 ./...`. `make test` combines lint and
unit tests; `make vet` is a separate target. For a focused solver test:

```sh
go test -race -count=1 ./internal/solver -run TestCallsAtOneChallengeTargetNeverOverlap
```

**Keep end-to-end credentials unset during ordinary checks.** Currently
`test/e2e/e2e_test.go` has no `e2e` build constraint. Its live test is included
in `go test ./...` and skips only when the required environment variables are
missing. Setting both variables also enables it during `make unit` or
`make test`, despite the build-tag description in the README.

All new Go files need the Apache 2.0 header specified in `.conform.yaml`; copy
the header from an existing Go file. Run `make licenses` when checking dependency
licenses, especially after dependency changes. Keep cert-manager and Kubernetes
dependencies compatible and commit both `go.mod` and `go.sum` when they change.

## Work on the Helm chart

```sh
make helm-unit
helm template dnsgate charts/cert-manager-webhook-dnsgate \
  --namespace cert-manager > /tmp/dnsgate-rendered.yaml
ct --config .github/ct.yml lint
```

`make helm-unit` currently runs only `helm lint` and `helm template`; it does
not test installation in a cluster or verify multiple Secret access modes.
Inspect rendered resources for changes to RBAC, certificates or deployment
settings. Chart-testing targets `main` and requires a chart version increment
for chart changes. Update `Chart.yaml` and the values documentation template
when appropriate.

For a development deployment, use a reachable image tag and provide the Gateway
through `args` (for example `--gateway=gateway.example.org:443`) or `env`
(`DNSGATE_GATEWAY`). For a private CA, mount a Secret through `volumes` and
`volumeMounts` and pass its PEM path with `--ca-file`. These are separate from
the webhook's serving certificate for kube-apiserver. The chart's
`ci/values.yaml` illustrates the wiring but contains environment-specific
addresses, a CA Secret name and scheduling settings; adapt them to your cluster.

The current chart grants Secret reads only in
`certManager.clusterResourceNamespace`, falling back to `certManager.namespace`.
Namespaced Issuers elsewhere require additional RBAC. There is currently no
`secretAccess` chart value or `gateway.address` value, despite the design notes.

The design requires one active webhook pod. The current chart defaults to one
replica but uses `RollingUpdate` and does not enforce this constraint. For a
development deployment that follows the design, keep `replicaCount: 1`, leave
autoscaling disabled and set `updateStrategy` to `{type: Recreate}` without the
`rollingUpdate` field. See [ADR 0004](adr/0004-lock-per-challenge-target-single-replica.md).

## Run the end-to-end test

`make e2e` tests an already deployed webhook; it does not build an image,
provision a cluster or deploy the chart. The test creates a random namespace,
token Secret, cert-manager Issuer and Certificate for `e2e-<random>.<zone>`.
It waits for Ready, reports cert-manager resource states on failure and attempts
cleanup on success and failure. A successful run requires public DNS and real
ACME validation.

Ensure your kubeconfig selects the intended cluster and that you can create and
delete namespaces and cert-manager resources and manage Secrets in the required
namespace. The zone must be served by a Provider behind the deployed Gateway.
The token must permit `patch` on TXT records at the zone's challenge names;
[permissions-cert-manager.yaml](permissions-cert-manager.yaml) shows the pattern.

| Environment variable | Default or requirement |
| --- | --- |
| `DNSGATE_TEST_TOKEN` | Required Service Token; stored in a Secret and never logged by the test |
| `DNSGATE_TEST_ZONE` | Required public zone, e.g. `sandbox.example.org` |
| `DNSGATE_TEST_ACME_SERVER` | Let's Encrypt staging directory |
| `DNSGATE_TEST_ACME_EMAIL` | Empty |
| `DNSGATE_TEST_GROUP_NAME` | `acme.dnsgate.link`; match the deployment |
| `DNSGATE_TEST_ISSUER_KIND` | `ClusterIssuer` in the current code; `Issuer` is also supported |
| `DNSGATE_TEST_CLUSTER_RESOURCE_NAMESPACE` | `cert-manager`; match cert-manager's cluster resource namespace |
| `DNSGATE_TEST_TIMEOUT` | `10m`, for waiting for Certificate Ready |

Supply the token through your local secret-management workflow, then run:

```sh
export DNSGATE_TEST_ZONE=sandbox.example.org
export DNSGATE_TEST_ISSUER_KIND=ClusterIssuer
make e2e
unset DNSGATE_TEST_TOKEN DNSGATE_TEST_ZONE
```

`ClusterIssuer` matches the chart's default Secret access. `Issuer` places the
token in the random test namespace and needs corresponding webhook RBAC.
`make e2e` passes `-tags e2e -count=1 -timeout 30m -v`; override its overall
timeout with `make e2e E2E_TIMEOUT=45m` if needed. Set `DNSGATE_TEST_TIMEOUT`
separately to change the certificate wait. No CI workflow currently runs the
live certificate test with credentials.

## Prepare a contribution

Use the [issue templates](../.github/ISSUE_TEMPLATE/) for bug reports and feature
requests. Include reproduction steps for bugs and keep the Community Note.
Link the issue from your PR when applicable.

Every PR must contain one commit with a DCO `Signed-off-by:` footer. Use
`git commit --signoff`, and squash intermediate commits before review. Keep
the commit header and PR title aligned: lowercase, imperative, no trailing
period, at most 90 characters overall and at most 80 for the description.

The current `.conform.yaml` permits `feat`, `chore`, `docs`, `refactor`, `revert`,
`style` and `test`, with `charts` as its only configured scope. For example:

```sh
git add docs/development.md
git commit --signoff -m "docs: add development and contributing instructions"
make conformance
git diff --check
```

`CONTRIBUTING.md` also recommends `fix` and other scopes, but those are absent
from the current conformance allowlist. Resolve that policy mismatch before
using a header outside the configured list. `make conformance` uses Docker to
check commit policy and Go license headers.

Use [.github/PULL_REQUEST_TEMPLATE.md](../.github/PULL_REQUEST_TEMPLATE.md):
explain what changed and why, link the issue, report relevant checks and disclose
AI usage honestly. Follow the additional conformance requirement in
`CONTRIBUTING.md`. Keep the description current as the diff changes, address
review feedback on the same branch and ensure applicable CI checks pass.

CI runs Go lint, race tests and a build for matching Go/build paths on non-draft
PRs targeting `main`; chart changes run chart-testing and `make helm-unit`.
Conformance runs for non-draft PRs targeting `main`. Path filters mean a green
PR may not have run every local check, especially for documentation-only or
`test/e2e/`-only changes.

## Release tooling

`make release-check` validates `.goreleaser.yml`. `make snapshot` creates an
unpublished snapshot under `bin/`; the Dockerfile consumes GoReleaser's
platform-specific binaries rather than compiling source itself. GoReleaser
builds Linux amd64 and arm64 binaries and images.

Release Please manages release PRs from `main`. The release workflow publishes
on `v*` tag pushes and supports manual invocation. `make release` publishes
release artifacts, and `make helm-release` packages, pushes and signs the OCI
chart. Use those publishing targets only as part of a maintainer release.
