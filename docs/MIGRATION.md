# Migrating to Samly 2.0

Samly 2.0 requires Elixir 1.20 and supports OTP 27 through OTP 29.
It replaces the external esaml and SweetXml stack with a native Elixir SAML core.
Cowboy, Ranch, and Cowlib are no longer transitive dependencies.

## Dependency and endpoint changes

Update the dependency requirement to `{:samly, "~> 2.0"}`.
The existing `forward "/", Samly.Router` integration remains available.
New applications should add `Samly.Plug` after their body parsers and before their application router.
Samly does not select or start an HTTP server, so Bandit can be used without a Cowboy compatibility dependency.

## Security changes

XML documents containing a DTD or entity declaration are rejected before parsing.
Decoded and inflated SAML payloads have bounded sizes.
XML signatures require SHA-256 or stronger by default and reject duplicate signed IDs, unsupported transforms, untrusted certificates, and wrapping attempts.
SHA-1 can be enabled for a specific legacy IdP with `allow_legacy_sha1: true`.
Do not enable that option for IdPs that support SHA-256.

SP-initiated responses must match both RelayState and the original SAML request ID.
Response and assertion IDs are single-use through `Samly.ReplayCache`.
Configure a cluster-wide implementation of that behaviour when nodes do not share an ETS table.

Request-controlled redirect targets must be site-relative paths.
Protocol-relative URLs, control characters, and absolute URLs are rejected unless the absolute URL exactly matches the IdP's `allowed_target_urls` list.
Debug mode no longer reflects raw SAML responses into HTML error pages.
Relative `base_url` configurations must set an absolute `:external_base_url` or explicitly list the request host under `:trusted_hosts`.
This prevents a forged Host header from changing generated SAML endpoints.

Encrypted assertions require RSA-OAEP and AES-GCM.
Legacy RSA PKCS#1 v1.5 and AES-CBC encryption are rejected because they do not provide the required modern security properties.

## New integration features

Use `custom_consume_uri` and `custom_logout_uri` when an IdP has fixed legacy endpoint registrations.
Use `force_authn: true` when an IdP must reauthenticate the user.
Use `post_session_cleanup_pipeline` for logout cleanup and `on_logout` for a two-argument logout callback.
Use `Samly.IdpData.from_config/2` to build an IdP at runtime.
For tenant-specific resolution, implement `Samly.ConfigProvider` and configure it under `:config_provider`.
Use `Samly.get_nameid/1` when the NameID itself is the required subject identifier.
