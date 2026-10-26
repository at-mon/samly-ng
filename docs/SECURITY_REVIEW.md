# Security review - 2026-10-26

## Scope and conclusion

This review covers the pure-Elixir Samly implementation, its current locked dependencies, SAML trust selection, XML signatures and encryption, HTTP bindings, request correlation, replay protection, assertion storage, diagnostics, and OTP lifecycle behavior.
Confirmed defects were reproduced before their fixes with real localhost HTTP tests where practical and focused signed-message, concurrency, and parser regressions elsewhere.
The implementation now passes 311 tests and the complete configured quality gate, with 90.26% line coverage.
This is not a certification that every possible vulnerability has been eliminated or a substitute for production IdP interoperability testing.

The pre-existing dependency updates in `mix.exs` and `mix.lock` were retained and reconciled with the lockfile.
Three accidental compiler-output lines at the top of `mix.exs` were removed to restore a runnable baseline.
No commits, public disclosures, live-system probes, machine-wide runtime changes, or hand-edited generated documentation were made.

## Confirmed findings and fixes

Severity is qualitative and depends on the stated prerequisites; no CVSS score or new CVE assignment is claimed.

### High: metadata keys crossed entity and role trust boundaries

The loader previously selected the first entity ID but gathered signing certificates from all descendant key descriptors, including unrelated service-provider roles in aggregate metadata.
A real HTTP reproduction loaded an IdP with its own certificate and an unrelated SP certificate, then accepted an authentication response signed by the SP key as the IdP, returning HTTP 302 and a session cookie.

Metadata loading now selects exactly one SAML 2.0 IdP role and scopes issuer, endpoints, signing certificates, and NameID formats to that role and its owning entity.
Ambiguous multi-IdP documents are rejected; aggregate metadata containing one IdP plus unrelated SP entities remains supported.
Rollover signing certificates within the selected IdP remain valid.
RSA material and configured SP key/certificate pairing are validated at configuration load.

Primary code: `lib/samly/idp_data.ex`, `lib/samly/saml/key.ex`, `lib/samly/sp_data.ex`.
Regression evidence: `test/samly_metadata_http_test.exs`, `test/samly_metadata_security_test.exs`, `test/samly_sp_data_test.exs`.
The same unrelated-key request now returns HTTP 403, while the selected IdP rollover certificate still authenticates and accesses the protected resource.

### High: shared identity keys crossed browser-session boundaries

Assertions were stored under the stable pair `{idp_id, NameID}`.
With ETS, a second login replaced the first browser's assertion, including its attributes, and a subsequent login could revive a stale browser cookie after logout or expiry.
The HTTP reproduction showed a browser authenticated with the `member` claim returning the `admin` claim after a different browser logged in for the same NameID.

Every login now receives a cryptographically random session ID and a versioned `samly_session` locator.
Storage uses `{idp_id, opaque_session_id}`; old identity-only locators are not upgraded and require reauthentication.
Qualified subject and SessionIndex indexes support targeted or subject-wide IdP logout without coupling independent browser assertions.
Local logout revokes before callbacks or redirecting to the IdP, and callback exceptions do not restore access.

Primary code: `lib/samly.ex`, `lib/samly/state/`, `lib/samly/auth_handler.ex`, `lib/samly/sp_handler.ex`.
Regression evidence: `test/samly_bandit_e2e_test.exs`, `test/samly_state_test.exs`.
Independent browser claims remain isolated, cookie-less indexed logout preserves unrelated sessions, and an old ETS cookie stays rejected after logout and a fresh login.
Cookie-only storage has a separate residual limitation described below.

### High: replay retention did not cover alternative bearer confirmations

A signed assertion with multiple valid bearer confirmations was cached only until the currently selected confirmation expired plus clock skew.
After that cache entry was pruned, the identical signed response could select a later-expiring confirmation and authenticate again.
The review reproduced this using an actual 123-second wait and cache pruning, with both acceptances producing locally live assertions.

Replay retention now covers the latest parsed bearer-confirmation expiry in the authenticated assertion plus the full 120-second skew window.
The ETS backend preserves microsecond precision rather than rounding deadlines down.

Primary code: `lib/samly/saml/protocol.ex`, `lib/samly/replay_cache.ex`.
Regression evidence: the deterministic multi-confirmation retention test in `test/samly_protocol_validation_test.exs` and deadline precision tests in `test/samly_atom_and_replay_test.exs`.

### Medium: rejected messages polluted or prematurely consumed replay state

Response IDs were consumed before assertion IDs through independent operations.
In assertion-only signing mode, replaying one signed assertion with changed unsigned outer response IDs grew the replay cache even though every replay was rejected.
A bounded HTTP reproduction increased entries from two to five using three rejected submissions.

Only IDs covered by successful authentication now contribute replay entries.
Related identifiers are consumed atomically, so duplicate or full-cache rejection inserts nothing.
Stable SP/IdP trust identities and message type scope replay keys.
Authentication and logout-response browser correlation occur before replay commitment, preventing an unrelated browser from prematurely burning a valid response.
An independently reproduced logout-response ordering failure is covered by dedicated regressions.

Primary code: `lib/samly/replay_cache.ex`, `lib/samly/saml/protocol.ex`, `lib/samly/helper.ex`, `lib/samly/sp_handler.ex`.
Regression evidence: `test/samly_atom_and_replay_test.exs`, `test/samly_bandit_e2e_test.exs`, `test/samly_logout_correlation_test.exs`.
Custom replay stores must implement real atomic batch consumption for multi-ID messages.

### Medium: malformed or unsupported signed claims were accepted

The HTTP endpoint accepted assertions without an authentication statement and assertions containing an unknown mandatory condition.
Additional signed-message tests demonstrated recursive flattening of malformed audience text and ignored conflicting confirmation identity fields.

The supported browser-SSO profile now requires appropriate authentication statements, exact scalar identities/audiences, singleton security elements, supported conditions, valid times, and one consistent bearer confirmation satisfying recipient, correlation, and expiry checks.
NameID values are preserved without trimming or recursive flattening.
Logout retains qualified NameIDs and all SessionIndexes rather than selecting one descendant value.

Primary code: `lib/samly/saml/protocol.ex`.
Regression evidence: `test/samly_protocol_validation_test.exs`, `test/samly_bandit_e2e_test.exs`.
These are profile-validation defects and hardening improvements; acceptance of malformed trusted signatures is not represented as a demonstrated unsigned authentication bypass.

### Medium: XML interpretation diverged from the cryptographic profile

Regression tests reproduced acceptance of duplicate attributes, namespace ambiguity, forbidden characters/entities, discarded processing instructions, unsupported signature/encryption structures, and ignored encryption parameters.
Saxy does not perform all XML 1.0 lexical normalization required for canonicalization, and the former serializer could change referenced whitespace during a signing round trip.

The parser now validates XML characters, references, qualified names, namespace bindings, and duplicate expanded attributes while retaining binary names and byte/depth/element bounds.
Literal line endings and attribute whitespace are normalized before parsing without changing character-reference meaning.
Unsupported processing instructions are rejected instead of silently discarded.
Signature processing uses direct-child cardinality and exact scalar fields; exclusive canonicalization handles namespace resets and implicit XML namespace ordering.
Encryption validates namespaces and the exact supported OAEP/GCM structure and parameters before private-key use.
The XML serializer now preserves signature-relevant whitespace references; the unused `xml_builder` runtime dependency was removed.

A near-limit lexical scan was also tested in a heap-limited process.
Per-byte list construction exceeded the budget before the fix; chunked binary processing passes the same regression.

Primary code: `lib/samly/saml/xml/`, `lib/samly/saml/xml.ex`, `lib/samly/saml/xml_dsig.ex`, `lib/samly/saml/encryption.ex`.
Regression evidence: `test/samly_xml_security_test.exs`, `test/samly_xml_encryption_security_test.exs`, `test/samly_xml_protocol_encryption_test.exs`.
These findings include interoperability and fail-closed validation defects; they are not all independently demonstrated signature forgeries.

### Medium: raw diagnostics were enabled without an explicit security boundary

The CSP-report endpoint logged unauthenticated bodies directly and did not correctly handle partial reads or restrict methods.
Default-off raw diagnostics now require an exact per-IdP `debug_mode: true` or the separate application `debug_csp_reports: true` flag.
Logger must also permit debug messages.
Raw content is intentionally retained for enabled debugging, bounded to 8000 rendered bytes with truncation markers and safe invalid-byte rendering.
Private keys, session secrets, whole connection/configuration structs, and raw HTTP error reflection remain excluded.

CSP reports accept POST only and use a 16 KiB body limit with bounded reads and explicit partial/error handling.
Rejected HTTP/1 connections are closed rather than draining arbitrary unread bodies.

Primary code: `lib/samly/diagnostics.ex`, `lib/samly/cspr_router.ex`, `lib/samly/config_error.ex`, handler callsites.
Regression evidence: `test/samly_diagnostics_test.exs` includes real HTTP content-length and chunked-streaming cases.
HTTP/2 hop-by-hop-header behavior is covered through an adapter, not a full HTTP/2 browser integration.

### Additional boundary and OTP hardening

- Redirect signatures and payload decoding use the same verified parameter values; conflicting message types and structured/duplicate query aliases are rejected.
- POST security fields cannot be supplied through conflicting query parameters, and malformed scalar shapes fail closed.
- Return targets and external base URLs share strict validation, including encoded controls/backslashes, malformed escapes, userinfo, fragments, and invalid ports where applicable.
- Shared HTML escaping replaces duplicate attribute-escaping code.
- ETS assertion storage has a supervised protected owner, serialized mutations, a default 10,000-session bound, direct fail-closed reads, and expiry/index pruning.
- Stable owners survive individual request exits, and owner restart invalidates stored sessions.
- Sensitive OTP status/messages and configuration errors are redacted.
- Global-state tests are serialized and restore application configuration; HTTP tests bind directly to port zero rather than reserve and release a port.
- The warmed 10,000-distinct-name XML regression confirms no dynamic atom growth.

## Verification

Local environment: Elixir 1.20.4, OTP 29.1.2, Darwin arm64.

- Original baseline: 79 tests passed after the Mix-file repair and dependency reconciliation.
- Final regression suite: 311 tests passed, including a property test.
- Explicit coverage check: `mix test.json --quiet --cover --cover-threshold 90 --no-retry` passed at 90.26%.
- `mix quality.verify` passed formatting, warning-as-error compilation, strict Credo, Dialyzer, Sobelow, dependency analysis, and the full test suite.
- Structured Dialyzer returned zero warnings.
- `mix deps.audit` and `mix hex.audit` reported no known vulnerabilities or retired/security-advisory packages in the lockfile on the review date.
- Multiple complete runs and fixed-seed runs were used; external-tool and environment limitations are not treated as passing checks.
- XML signature reference material is independently canonicalized with `xmllint` and signed with OpenSSL, not generated by Samly's signer.
- A checked-in RSA-OAEP/SHA-256/MGF1-SHA-256 and AES-GCM vector was independently generated with Python cryptography 50.0.2.
- Complete encrypted protocol tests cover envelope verification before decryption, reconstructed assertion-signature verification, authentication-tag tampering, missing keys, and replay.

ExQuality 0.16's native-coverage parser does not recognize Elixir 1.20's Markdown-style coverage table.
Consequently coverage is enforced by a separate explicit structured-coverage CI step instead of pretending that ExQuality measures it.
The threshold remains 90%; it was not lowered to obtain a green result.
Optional ExQuality Doctor, documentation, documentation-link, README, Diataxis, and Gettext stages are not enabled and are not counted as passing checks.
Generated ExDoc files were not edited.

## Runtime and dependency advisories

Current authoritative records were checked at the [EEF CNA index](https://cna.erlef.org/cves/index.json).
[CVE-2026-65634](https://cna.erlef.org/cves/CVE-2026-65634.html) affects OTP ASN.1 OID decoding and is fixed in OTP 27.3.4.18, 28.5.0.7, and 29.1.1 or later on their respective release lines.
The prior CI matrix included affected versions, so it now uses 27.3.4.18, 28.5.0.7, and 29.1.2.
The local 29.1.2 runtime is outside the published affected ranges for this advisory and [CVE-2026-75538](https://cna.erlef.org/cves/CVE-2026-75538.html).
The remote Linux matrix was not executed locally.

Dependency audits do not audit this checkout as a dependency and do not establish comprehensive runtime safety.
Upstream Samly advisories, including [CVE-2026-53424](https://cna.erlef.org/cves/CVE-2026-53424.html) and [CVE-2026-53425](https://cna.erlef.org/cves/CVE-2026-53425.html), are separate from the local fixes and do not become officially resolved merely because this checkout has changed.

## Required migration and remaining risks

1. Existing identity-keyed browser sessions require reauthentication.
   Custom state adapters must treat the second key component as an opaque session ID and implement subject/index revocation for IdP logout.
2. Replay key namespaces and batch contracts changed.
   Follow the coordinated migration or all-node quiesce/drain procedure in [MIGRATION.md](MIGRATION.md); do not run old and new accepting nodes together or discard still-live replay history.
3. The default replay cache remains node-local and volatile.
   Durable, atomic shared replay storage is required across node/cache restarts or replicas; assertion storage likewise needs shared authority for cross-node logout.
4. `Samly.State.Session` remains stateless.
   Signed/encrypted cookies cannot revoke already-copied cookies server-side, and cookie-less IdP logout cannot reach other browsers' cookies.
   Use ETS or a shared authoritative state adapter when reliable revocation is required.
5. Enabled raw diagnostics can expose personal information and replayable SAML material.
   Enable only temporarily with restricted access and short retention, then disable them and handle collected logs as sensitive.
6. Metadata sources, key paths, callback modules, and configuration are privileged inputs.
   Pinned RSA certificate checks do not implement a general PKIX certificate-chain or expiration policy.
7. Host applications must enforce HTTPS, secure session cookies, trusted proxy/Host configuration, appropriate body limits, and endpoint rate limits.
   Retain CSRF on local initiation while keeping IdP callbacks governed by signature and correlation validation.
8. The parser/cryptographic code implements a strict supported subset, not general XML Schema validation or every SAML/IdP profile.
   XMLsec1 and real enterprise IdPs were not exercised; independent vectors improve assurance but do not prove full interoperability or absence of cryptographic defects.
