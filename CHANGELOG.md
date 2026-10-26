# CHANGELOG

### [Unreleased]

#### 🔒 Fixed
#### 💡 Added
#### 🪄 Changed
#### 📃 Documentation



### v2.0.1 - 2026-10-26


#### ⚠️ Breaking

+   ✨ feat!: Replace identity-keyed browser sessions with versioned, random per-login locators; custom `Samly.State.Store` keys now mean `{idp_id, opaque_session_id}` instead of `{idp_id, NameID}`.
+   ✨ feat!: Require custom assertion stores to implement `revoke_assertions/3` for IdP-initiated logout, matching the qualified subject and any supplied SessionIndexes atomically.
+   ✨ feat!: Introduce trust-scoped replay keys and require atomic `Samly.ReplayCache.consume_many/1` for multi-ID messages; migrate live history or quiesce every accepting node through the remaining validity window before upgrading.
+   🔒 security: Reject ambiguous IdP metadata, unusable RSA credentials, configurations disabling both incoming signature requirements, malformed SAML claims, unsupported XML structures, and unsafe URL configurations that earlier versions could accept.

#### 🔒 Fixed

+   🔒 security: Prevent unrelated entity or SP-role certificates in aggregate metadata from authenticating as the selected IdP while preserving its signing-certificate rollover support.
+   🔒 security: Prevent concurrent logins for one NameID from replacing another browser's claims or reviving revoked ETS sessions after a later login.
+   🔒 security: Retain replay protection through the latest bearer-confirmation expiry plus clock skew, with microsecond precision, preventing reuse through a later-expiring confirmation.
+   🔒 security: Consume only authenticated message IDs with all-or-nothing replay insertion, preventing rejected unsigned-envelope variations from filling the cache.
+   🔒 security: Validate authentication and logout-response browser correlation before replay commitment so an unrelated browser cannot prematurely consume a valid response.
+   🔒 security: Require authentication statements, supported assertion conditions, unambiguous scalar identities and audiences, and consistent bearer recipient, correlation, and expiry checks.
+   🔒 security: Validate XML characters, references, namespace bindings, duplicate expanded attributes, signature cardinality, and encryption parameters; reject unsupported processing instructions rather than silently discarding them.
+   🐛 fix: Preserve signature-relevant character references and whitespace across XML serialization and canonicalization, including inherited namespaces and default-namespace resets.
+   🔒 security: Bind Redirect verification and decoding to the same parameters, reject conflicting message types and query/body security fields, and enforce scalar parameter shapes.
+   🔒 security: Reject encoded control characters, backslashes, malformed URL escapes, inappropriate userinfo/query/fragment components, and invalid ports in return-target and endpoint configuration.
+   🔒 security: Revoke local sessions before logout callbacks, preserve qualified NameIDs and all SessionIndexes, and keep callback failures from restoring authentication.
+   🔒 security: Restrict CSP reporting to bounded POST bodies with partial/error-read handling; redact credential-bearing provider inspection, configuration errors, and sensitive OTP status.

#### 💡 Added

+   💡 feat: Retain bounded raw authentication diagnostics behind per-IdP `debug_mode: true` and CSP diagnostics behind `debug_csp_reports: true`, both disabled by default and also requiring Logger's debug level.
+   🔒 security: Cap raw diagnostic messages at 8000 rendered bytes and CSP request bodies at 16 KiB; private keys and session secrets remain excluded, and HTTP errors never reflect raw payloads.
+   🧪 tests: Add real HTTP session-isolation, login/logout, metadata-trust, replay, routing, and diagnostic regressions, plus parser, concurrency, atom-growth, and independent signature/encryption vectors.
+   🧪 tests: Enforce a separate 90% coverage gate in CI and install `xmllint` and OpenSSL for independent cryptographic test cases.

#### 🪄 Changed

+   🪄 refactor: Move assertion ETS tables to supervised protected owners with serialized writes, fail-closed reads, expiry/index cleanup, and configurable `max_entries` and `cleanup_interval_ms` defaults of 10,000 sessions and 60,000 ms.
+   🚀 perf: Process XML lexical input in binary chunks instead of allocating a list element per byte, reducing heap amplification near the payload limit.
+   🔒 security: Update the CI OTP matrix to 27.3.4.18, 28.5.0.7, and 29.1.2 to include the ASN.1 decoder fixes for CVE-2026-65634.
+   📦 package: Update locked Bandit to 1.14.0, Plug.Crypto to 2.2.1, Thousand Island to 1.6.0, Sobelow and ExQuality to 0.16.0, and add development/test JSON tooling for ExUnit and Dialyzer.
+   🔥 clean: Remove the unused `xml_builder` runtime dependency after introducing signature-preserving XML serialization.
+   🧪 tests: Isolate tests that mutate application configuration and bind HTTP listeners directly to port zero to avoid port-reservation races.

#### 📃 Documentation

+   📃 docs: Document session reauthentication, custom-store key and revocation contracts, atomic replay adapters, and coordinated replay-namespace migration in [MIGRATION.md](docs/MIGRATION.md).
+   📃 docs: Refresh the [security review](docs/SECURITY_REVIEW.md), [configuration reference](docs/configuration.md), and [Phoenix setup guide](docs/phoenix_setup.md) with reproduced findings, diagnostic controls, patched runtime requirements, and verification limits.
+   📃 docs: Clarify that node-local replay history does not survive restarts or span replicas, cookie-only assertion storage cannot revoke copied cookies, and real-IdP interoperability still requires deployment validation.
+   🐛 fix: Correct README and ExDoc/package references to the migration and security documents under `docs/`.

### v2.0.0 - 2026-09-27

Major release.
Samly now ships a native Elixir SAML core and drops the external esaml/SweetXml stack.
See [MIGRATION.md](docs/MIGRATION.md) for upgrade steps and [SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) for the security assessment.

#### ⚠️ Breaking

+   ✨ feat!: Replaced the esaml and SweetXml stack with a native Elixir SAML core built on `saxy` and `xml_builder`.
+   ✨ feat!: Requires Elixir 1.20 and supports OTP 27 through OTP 29.
+   ✨ feat!: Removed `cowboy`, `ranch`, and `cowlib` as transitive dependencies; Samly no longer selects or starts an HTTP server, so servers such as Bandit work without a Cowboy compatibility shim.
+   🔒 security: XML signatures require SHA-256 or stronger by default; SHA-1 is only accepted per-IdP via `allow_legacy_sha1: true` and should stay disabled for IdPs that support SHA-256.
+   🔒 security: Encrypted assertions require RSA-OAEP and AES-GCM; legacy RSA PKCS#1 v1.5 and AES-CBC encryption are rejected.
+   🔒 security: Request-controlled redirect targets must be site-relative paths; protocol-relative, control-character, and absolute URLs are rejected unless they exactly match the IdP's `allowed_target_urls`.
+   🔒 security: Relative `base_url` configurations must set an absolute `:external_base_url` or list the request host under `:trusted_hosts`, preventing a forged Host header from changing generated SAML endpoints.
+   🔒 security: SP-initiated responses must match both RelayState and the original SAML request ID.
+   🪄 refactor: New applications should add `Samly.Plug` after their body parsers and before the application router; the existing `forward "/", Samly.Router` integration remains available.

#### 💡 Added

+   💡 feat: `Samly.get_nameid/1` returns the NameID from an assertion when the NameID itself is the required subject identifier.
+   💡 feat: `Samly.IdpData.from_config/2` builds an IdP at runtime, and the `Samly.ConfigProvider` behaviour (configured under `:config_provider`) enables tenant-specific resolution.
+   💡 feat: `custom_consume_uri` and `custom_logout_uri` config for IdPs with fixed legacy endpoint registrations.
+   💡 feat: `force_authn: true` config to require the IdP to reauthenticate the user.
+   💡 feat: `post_session_cleanup_pipeline` for logout cleanup and a two-argument `on_logout` logout callback.
+   🔒 security: `Samly.ReplayCache` makes response and assertion IDs single-use; configure a cluster-wide implementation for multi-node deployments.
+   🔒 security: XML input hardening rejects DTD/entity declarations before parsing, bounds decoded and inflated payload sizes, and limits element count and nesting depth.
+   🧪 tests: Added security, ingress-security, replay/atom, and Bandit end-to-end test suites, plus a c14n namespace-context vector cross-checked with libxml2.
+   📦 package: Added `bandit`, `stream_data`, `mix_audit`, `sobelow`, `styler`, `ex_quality`, and `credo` (dev/test only) for the quality and security gates.

#### 🔒 Fixed

+   🔒 security: CVE-2026-28809 - external esaml/xmerl parsing is removed and XML entities and doctypes are rejected before parsing.
+   🔒 security: CVE-2026-53424 - accepted message IDs are consumed once via a supervised, bounded, fail-closed replay cache.
+   🔒 security: CVE-2026-53425 - AuthnRequest IDs are stored in the browser session and checked against signed SubjectConfirmationData so unsolicited responses cannot replace a pending SP flow.
+   🐛 fix: Debug mode no longer reflects raw SAML responses into HTML error pages.
+   🐛 fix: SP configuration and logout callback failures no longer log full configuration maps or callback exception text.

#### 🪄 Changed

+   📦 package: Bumped `plug` from 1.15.3 to 1.20.3 (`plug_crypto` 2.2.0).
+   🪄 refactor: Rewrote SAML binding, protocol, encryption, redirect-signature, XML, and XMLDSig handling as dedicated `Samly.SAML.*` modules.
+   ⚙️ skip-ci: Added Credo, Sobelow, mix_audit, and Styler configuration and a CI quality/security gate across OTP 27/28/29 with Elixir 1.20.

#### 📃 Documentation

+   📃 docs: Added `MIGRATION.md` upgrade guide and `SECURITY_REVIEW.md` security assessment.
+   📃 docs: Added Phoenix setup, configuration, and Microsoft Entra ID guides under `docs/`.
+   📃 docs: Rewrote `README.md` for the 2.0 native-core architecture.

### v1.4.0
+   remove uri double encoding thanks to @DiaanEngelbrecht
+   fix esaml initialization thanks to @bopm
+   check and enforce session expiration (CVE-2024-25718) thanks to @idyll

### v1.3.0
+   Added dialyzer checks
+   Changed internal function layout to report errors more granularly
+   Verified with updates to esaml dependency
+   Client can refresh the runtime provider config without restarting the app from [bernardd](https://github.com/dropbox/samly/pull/7)

### v1.2.0
+   Metadata can be specified directly in the IdP config rather than requiring a file
+   Bumps dependencies

### v1.1.0
+   Updated minor version due to dependency updates requiring potential language version bumps
+   Removed Inch CI
+   Updated dependencies for project
+   Removed strict required dependency on `sweet_xml`
+   Use updated version of `esaml` to reduce strict requirements on `cowboy`
+   Updated license copyright

### v1.0.0

+   `target_url` query parameter for the sign-in/sign-out requests must be
    `x-www-form-urlencoded`.

+   Redirect URLs are properly encoded.

+   Switched to `report-to` in content security policy.

+   `cache-control` header value updated.

+   Issue: #33 - Content Security Policy
    Enabled `Content-Security-Policy` in the HTTP response.

+   PR: #41 - Config support for nameid format
    `Samly` uses the nameid format from the IdP metadata XML file.
    It is possible now to override this using `nameid_fomat` config setting.
    If this format information is not present in the IdP metadata XML and not
    specified in the config setting, it defaults to `:transient`.
    Thanks to [calvinb](https://github.com/calvinb) for the PR.

+   Uptake `esaml 4.2` bringing in support for encrypted assertions.
    Check [Assertion Encryption](https://github.com/handnot2/esaml#assertion-encryption)
    for supported encryption algorithms. Use this information to enable assertion
    encryption on IdP. Thanks to [tcrossland](https://github.com/tcrossland)
    for the `esaml` PR.

### v0.10.1

+   Issues: #39, #40 - Downcase response header names
    (PR from [calvinb](https://github.com/calvinb))

### v0.10.0

+   Issue: #31 - Support for Cowboy 2.x
    Uptake `esaml` v4.0.0 which includes support for Cowboy 2.x.
    If support for Cowboy 1.x is needed, you need an override with
    `esaml` v3.6.x in your application `mix.exs` file.

+   Issue: #32 - Support for custom State Storage
    Includes support for ETS and Plug Sessions based authenticated SAML
    assertion storage. It is possible to create custom stores by
    implementing `Samly.State.Store`.

+   Issue: #34 - Included filename in error messages
    Include metadata/cert/key filenames when there is an error relevant to
    those files.

### v0.9.3

+   Uptake `esaml` v3.6.0 that includes fixes for schema validation errors.

### v0.9.2

+   PR merged fixing reopened Issue #16 (from @peterox)

### v0.9.1

+   Remove the need for supplying certificate and key files if the requests are
    not signed (Issue #16). Useful during development when the corresponding
    Identity Provider is setup for unsigned requests/responses. Use signing
    for production deployments. The defaults expect signed requests/responses.

### v0.9.0

+   Issue: #12. Support for IDP initiated SSO flow.

+   Original auth request ID when returned in auth response is made available
    in the assertion subject (SP initiated SSO flows). For IDP initiated
    SSO flows, this will be an empty string.

+   Issue: #14. Remove built-in referer check.
    Not specific to `Samly`. It is better handled by the consuming application.

### v0.8.4

+   Shibboleth Single Logout session match related fix. Uptake `esaml v3.3.0`.

### v0.8.3

+   Generates SP metadata XML that passes XSD validation

### v0.8.2

+   Handle namespaces in Identity Provider Metadata XML file

### v0.8.0

+   Added support for multiple Identity Providers. Check issue: #4.
    Instructions for migrating from v0.7.x available in github project wiki.

### v0.7.2

+   Added `use_redirect_for_idp_req` config parameter. By default `Samly` uses HTTP POST when sending requests to IdP. Set this config parameter to `true` if HTTP redirection should be used instead.

### v0.7.1

+   Added config option (`entity_id`). OOTB uses metadata URI as entity ID. Can be specified (`urn` entity ID for example) to override the default.

### v0.7.0

+   Added config options to control if requests and/or responses are signed or not

### v0.6.3

+   Added Inch CI
+   Corresponding doc updates

### v0.6.2

+   Doc updates
+   Config handling changes and corresponding tests

### v0.6.1

+   `target_url` query parameter form url encoded

### v0.6.0

+   Plug Pipeline config `:pre_session_create_pipeline`
+   Computed attributes available in `Samly.Assertion`
+   Updates to `Samly.Provider` `base_url` config handling
