# Migrating to Samly 2.0

Samly 2.0 requires Elixir 1.20 and supports OTP 27 through OTP 29.
Use a maintained, security-patched OTP release rather than treating a major version alone as sufficient.
It replaces the external esaml and SweetXml stack with a native Elixir SAML core.
Cowboy, Ranch, and Cowlib are no longer transitive dependencies.

This update changes browser-session representation, assertion-store keys, logout-store callbacks, and the replay-key namespace.
Read the cutover requirements before deploying it over an existing installation, including an earlier checkout of the 2.0 rewrite.
See the [configuration reference](configuration.md), [Phoenix guide](phoenix_setup.md), and [security review](SECURITY_REVIEW.md) for deployment requirements and remaining limits.

## Dependency and endpoint changes

Use a reviewed immutable revision or a release containing these changes; the checkout's version number alone does not establish that a corresponding Hex release is available.
The existing `forward "/", Samly.Router` integration remains available.
New applications should add `Samly.Plug` after their body parsers and session plug, and before their application router.
Samly does not select or start an HTTP server, so Bandit can be used without a Cowboy compatibility dependency.
Keep browser CSRF protection on normal application routes and local initiation, not on the IdP's SAML POST callbacks.

## Browser sessions and assertion stores

The Plug session entry `"samly_session"` now contains `{:v1, idp_id, random_session_id}`.
Every accepted login gets a fresh opaque identifier rather than using the subject's NameID as its storage key.
Old two-element session entries are not interpreted as the new format and require reauthentication.
Plan for user sign-ins after deployment and retire old assertion rows according to your storage policy.
Do not rewrite a legacy NameID into a purported random session ID to preserve a session.

Custom `Samly.State.Store` implementations still receive two-element assertion keys, but their meaning is now `{idp_id, opaque_session_id}`.
Update schemas and code that assumed the second component was a NameID, and preserve independent concurrent logins for the same subject.
Enforce valid expiry at storage and read time; failed writes must raise before the handler establishes authentication.
Built-in stores enforce the subject deadline and any earlier authentication-session deadline, independently of the host cookie's lifetime.

The default ETS store now has a supervised owner and protected table, a default capacity of 10,000 sessions, and expired-entry cleanup every 60,000 ms.
Configure positive `:max_entries` and `:cleanup_interval_ms` values under `Samly.State`'s `:opts` when needed.
Capacity exhaustion rejects new sessions instead of evicting live sessions.
Do not access the internal ETS row layout directly or create the table from application code.
Owner or VM restarts discard the node-local sessions and require reauthentication.

### IdP logout revocation

Custom authoritative stores must implement `revoke_assertions(conn, selector, config)` for IdP-initiated logout.
Missing callback support raises an explicit migration error instead of pretending that logout succeeded.
The selector is `%{idp_id: idp_id, subject: subject, session_indexes: indexes}`.
Atomically revoke matching sessions and return `{updated_conn, [{assertion_key, assertion}]}` for the revoked entries.
Match IdP and qualified NameID, including name, format, NameQualifier, and SPNameQualifier, normalizing absent qualifiers consistently.
A nonempty index list matches any supplied SessionIndex; an empty list selects all sessions for that qualified subject.
Authoritative revocation must work without a browser cookie and must not revoke unrelated sessions sharing only the bare NameID.

`Samly.State.Session` remains stateless and has no independent server-side revocation authority.
With cookie storage, deleting one browser's entry cannot invalidate a copied cookie, and cookie-less IdP logout cannot revoke entries in other browsers.
Use an authoritative shared store when reliable logout, central revocation, or multi-node sessions are required.
The built-in ETS store can revoke sessions only on its own node.

## Replay storage and coordinated cutover

Custom replay stores must provide atomic `consume_many([{key, expires_at}])` for responses that consume more than one authenticated identifier.
The entire batch must succeed once or fail without inserting any entries, including when one entry is a duplicate or capacity is exhausted.
A loop of independent `consume/2` calls is not a valid implementation because it can partially consume a rejected response.
The old `consume(key, expires_at)` callback is used only as a singleton fallback; multi-entry calls without batch support return `:atomic_replay_cache_required`.
Both callbacks receive already-hashed 32-byte binary keys and `DateTime` expiries including clock skew.
Retain entries until expiry, reject duplicates as `:replayed`, and fail closed if the backend is unavailable.
Assertion protection covers the latest bearer-confirmation expiry plus clock skew, not just the confirmation selected for the current login.
Preserve microsecond precision or round storage deadlines upward, never downward.

Replay insertion now happens after authentication, protocol validation, and request correlation.
Only authenticated identifiers contribute entries; an unsigned outer response ID does not become replay authority in an assertion-signed-only profile.
The new key encodes `{:samly_replay_v2, sp_entity_id, idp_entity_id, message_kind, message_id}` with Erlang term serialization before SHA-256 hashing.
This scopes history by stable trust identities rather than rotating certificates and avoids ambiguous delimiter-based keys.

**The replay namespace changed, so a shared backend alone does not make a rolling mixed-version upgrade safe.**
Old hashed entries are not equivalent to the new entries, and replay history must not silently reset while old messages remain acceptable.
Choose one coordinated strategy:

1. Migrate all still-live replay history into the new namespace using the original trust identities, message kinds, and identifiers, and validate atomic batch behavior before enabling new traffic.
   If the old store retains only irreversible hashes, do not assume this migration is possible.
2. Quiesce SAML acceptance on every node, drain in-flight requests, and wait at least the maximum remaining lifetime of any old accepted assertion plus the acceptance clock skew before restarting acceptance on the new version.
   Use the actual largest remaining validity window, not an arbitrary short deployment delay.

Do not run old and new versions accepting SAML concurrently during this cutover.
Plan rollback with the same replay-history constraints, and coordinate all nodes and regions using the service.
The default replay cache remains node-local and volatile; restart-safe or multi-node deployments require a durable shared atomic implementation.

## Metadata, credentials, XML, and HTTP validation

Metadata must identify exactly one eligible SAML 2.0 IdP role, even inside an aggregate document.
Ambiguous IdP entities or roles fail closed; keys, NameID formats, and endpoints come only from that role and its parent entity.
Unrelated SP roles, extensions, and encryption-only certificates no longer contribute signing trust.
Multiple valid signing certificates in the selected role still support rollover.
Malformed certificates, unsupported public keys, and mismatched SP RSA certificate/private-key pairs reject provider loading.

Review base URLs, callbacks, metadata endpoints, and redirect allowlists for the stricter URL validation.
Userinfo, fragments, malformed escapes, controls, backslashes, and protocol-relative URLs are rejected.
Base and callback URLs also reject query strings, and metadata endpoints must be absolute HTTP(S) URLs without duplicate service/binding choices.
Relative `base_url` configurations still require an absolute `:external_base_url` or an explicit request host under `:trusted_hosts`.
Prefer a reviewed absolute HTTPS base rather than request-derived origins.

XML processing rejects DTDs, entity declarations, unsupported processing instructions, invalid XML characters, duplicate attributes, and malformed namespace bindings.
The parser normalizes XML line endings and attribute whitespace without losing character-reference meaning, and enforces bounded payload size, nesting, and element count.
Security-critical XML structures must be unambiguous and correctly namespace-qualified.
Signed claims require supported structure, matching issuer/audience/destination, valid bearer confirmation and expiry, and request correlation where applicable.
Unsupported canonicalization transforms, signature structures, and encryption parameters fail closed rather than falling back to a permissive interpretation.

Incoming RSA/SHA-256 signatures are supported by default; only a specific legacy IdP may opt into RSA/SHA-1 with `allow_legacy_sha1: true`.
Do not enable SHA-1 for an IdP that supports SHA-256.
Encrypted assertions require the supported RSA-OAEP and AES-GCM profile; RSA PKCS#1 v1.5 and AES-CBC are rejected.
Binding validation rejects conflicting or duplicate security parameters, nonscalar values, inconsistent query/body parameters, and unsupported encoding combinations.
SP-initiated responses must match both RelayState and the original SAML request ID before replay entries or authenticated session state are committed.

## Raw diagnostic logging

Raw logging is retained, but disabled by default and controlled independently of Logger's level.
Set `debug_mode: true` on the specific resolved IdP to enable raw SAML, status-detail, and request/URL diagnostics at debug level.
Only the boolean `true` enables it; unresolved requests cannot inherit another IdP's configuration.
Enable CSP diagnostics separately with `config :samly, :debug_csp_reports, true`.
The CSP endpoint accepts only POST and bounds report reads to 16 KiB, with explicit handling of oversized, partial, and failed reads.

Raw diagnostic messages are lazily constructed, capped at 8000 rendered bytes, marked when truncated, and safe for invalid input bytes.
Enabled raw assertions can reveal personal information and replayable authentication material, so use a short diagnostic window with restricted access and retention.
Private keys, cookie secrets, complete connection/configuration structs, and OTP status/crash state remain excluded regardless of flags.
Raw payloads are never reflected in HTTP error responses, and disabled flags leave only fixed nonsensitive rejection categories.

## Integration features and validation limits

Use `custom_consume_uri` and `custom_logout_uri` only after testing the documented URI-resolution caveats with your endpoint mount.
`force_authn: true` applies when a new AuthnRequest is generated; an existing local assertion can still short-circuit sign-in.
Use `post_session_cleanup_pipeline` for applicable logout cleanup and `on_logout` for a two-argument callback, not as the sole revocation transaction.
Use `Samly.IdpData.from_config/2` and a trusted `Samly.ConfigProvider` for runtime provider definitions.
Use `Samly.get_nameid/1` when the NameID itself is needed, while retaining IdP and qualifier context in application identity mapping.

Independent signature, canonicalization, and encryption cases supplement HTTP and adversarial regression tests.
They do not constitute exhaustive SAML conformance, broad real-IdP interoperability, browser-policy validation, or comprehensive production security assurance.
Test your supported IdP profiles, encrypted assertions, certificate rollover, copied-cookie behavior, cookie-less logout, restarts, capacity limits, and multi-node replay rejection before production acceptance.
