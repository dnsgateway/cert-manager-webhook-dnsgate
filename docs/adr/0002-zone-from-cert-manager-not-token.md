# The zone comes from the solver config or cert-manager, never from the token

The webhook writes the Challenge Target in the solver config's `zone`, or else cert-manager's `ResolvedZone`; it never calls `InspectToken` to pick a zone from the token's Permissions. This deliberately differs from the ACME Endpoint, which has no resolver and so must take the zone from the token: cert-manager already resolves it, the token only authorizes the write, and one Gateway call per `Present` or `CleanUp` is enough.
