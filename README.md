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
Restart-safe or multi-node deployments need a durable shared replay store; the built-in replay cache is node-local and in-memory.
Real-IdP interoperability and broader security validation remain required for this rewritten implementation.
See the [security review](SECURITY_REVIEW.md) and [migration notes](MIGRATION.md) before adopting it as a replacement.

## Development

```sh
mix deps.get
mix quality.verify
mix security.check
```

These are this repository's tasks, not tasks automatically installed in a consuming Phoenix application.
The full quality gate includes tests, Sobelow, Credo, Dialyzer, compilation, formatting, and dependency checks.
