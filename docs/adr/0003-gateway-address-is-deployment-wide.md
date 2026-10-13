# The Gateway address and CA are deployment-wide

The Gateway address and its CA are webhook flags set by the cluster operator, never fields of the solver config. Whoever may create a cert-manager Issuer could otherwise point the webhook, and the Secret it reads, at an endpoint of their choice; a cluster that needs a second Gateway runs a second deployment with its own `groupName`.
