# The cert-manager Webhook is a Gateway client in its own repository

The cert-manager Webhook lives in `github.com/dnsgateway/cert-manager-webhook-dnsgate` and requires only `dnsgate-go`, never `dnsgate`, so it tracks cert-manager's Kubernetes versions without pulling them into the Gateway. Like the ACME Endpoint it holds no keys and never opens a token; unlike it, the webhook cleans up what it presents, because cert-manager hands it the token again at `CleanUp`.
