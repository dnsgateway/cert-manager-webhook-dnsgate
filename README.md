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

## License

[Apache License 2.0](LICENSE).
