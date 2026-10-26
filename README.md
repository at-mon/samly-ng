# Samly

SAML 2.0 single sign-on for Plug and Phoenix applications.
Samly connects your application to an Identity Provider (IdP), validates SAML responses, and exposes the authenticated user's assertion.

This checkout contains the Samly 2 pure-Elixir implementation.
It does not depend on esaml, Xmerl, or Cowboy, and works with Phoenix's Bandit adapter.
Your application still owns user provisioning, authorization, and session policy.

## Get started

1. Follow the [Phoenix setup guide](docs/phoenix_setup.md) to configure your IdP, keys, endpoint, and sessions.
2. Use the [configuration reference](docs/configuration.md) for every supported setting, default, and possible value.
3. Complete the [production checklist](docs/phoenix_setup.md#production-checklist) before deployment.

Using Azure AD? Follow the [Microsoft Entra ID example](docs/microsoft_entra_id.md) for matching portal and Phoenix settings.

After setup, link users to `/sso/auth/signin/workforce` and read the assertion from a connection with its session fetched:

```elixir
assertion = Samly.get_active_assertion(conn)
name_id = Samly.get_nameid(assertion)
email = Samly.get_attribute(assertion, "email")
```

Replace `workforce` with your configured IdP ID.
An absent or expired assertion returns `nil`; attributes depend on your IdP's mapping.

## Production readiness

Use HTTPS, trusted IdP metadata, signed SAML messages, secure browser sessions, and a patched OTP runtime.
Restart-safe or multi-node deployments need a durable shared replay store with atomic `consume_many/1`; the built-in replay cache is node-local and in-memory.
Authenticated sessions use fresh opaque per-login identifiers rather than NameIDs, and old session cookies require reauthentication.
Use an authoritative shared assertion store for cross-node logout and revocation; the stateless Session adapter cannot revoke copied cookies or sessions missing from a cookie-less logout request.
This update changes the replay-key namespace, so follow the coordinated cutover requirements in the [migration notes](docs/MIGRATION.md) rather than running mixed versions.
Raw SAML and CSP diagnostics remain available only through explicit, disabled-by-default flags, with bounded output; enable them temporarily only with restricted log access and retention.
Independent signature, canonicalization, and encryption tests supplement the regression suite but are not comprehensive production assurance.
Real-IdP interoperability, browser behavior, and broader security validation remain required for this rewritten implementation.
See the [security review](docs/SECURITY_REVIEW.md) and [migration notes](docs/MIGRATION.md) before adopting it as a replacement.

## Development

```sh
mix deps.get
mix quality.verify
mix test.json --quiet --cover --cover-threshold 90 --no-retry
mix security.check
```

These are this repository's tasks, not tasks automatically installed in a consuming Phoenix application.
The full quality gate includes tests, Sobelow, Credo, Dialyzer, compilation, formatting, and dependency checks.
