# DNS Gateway — cert-manager Webhook

The cert-manager Webhook lets cert-manager complete DNS-01 challenges through the DNS Gateway. Terms of the Gateway itself (Gateway, Service Token, Permission, Challenge Target, Egress, and so on) are defined in the Gateway's glossary, [dnsgate GLOSSARY.md](https://github.com/dnsgateway/dnsgate/blob/main/GLOSSARY.md), and are not repeated here.

## Language

**cert-manager Webhook**:
A client of the Gateway that cert-manager calls through the Kubernetes API to present and clean up DNS-01 challenge values, using the cert-manager Issuer's Service Token. It is not part of the Gateway, and it is not the ACME Endpoint.
_Avoid_: webhook solver, dnsgate solver, issuer plugin

**cert-manager Issuer**:
An Issuer or ClusterIssuer whose DNS-01 solver names the cert-manager Webhook. It is not a Trusted Issuer.
_Avoid_: issuer (bare), CA, ACME account
