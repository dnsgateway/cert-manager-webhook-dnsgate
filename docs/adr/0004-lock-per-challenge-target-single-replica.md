# A lock per Challenge Target, with a single replica

cert-manager presents the two values of `example.com` and `*.example.com` at once, at one Challenge Target, and on adapters that replace a whole RRset (GoDaddy, Gandi, Hetzner, Namecheap) two concurrent `patch` calls can lose one. Until the Gateway or dnsprovider closes that race, the webhook serializes its own `Present` and `CleanUp` calls per Challenge Target with an in-memory lock, and therefore runs as exactly one replica with the `Recreate` strategy; a lock shared between pods (a Kubernetes Lease) was rejected as more machinery than one cluster's challenge traffic needs.

## Consequences

- Scaling the webhook beyond one replica reopens the race; do not raise `replicas` without a shared lock.
- During an upgrade there is a short window with no webhook pod; cert-manager retries the challenge.
- Writers other than this webhook are not covered.
