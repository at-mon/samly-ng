# Security review - 2026-09-07

## Scope and conclusion

This review covers the current pure-Elixir Samly implementation, its locked dependencies, SAML input processing, atom creation, replay protection, request correlation, redirects, and build checks.
It is not a certification that all possible vulnerabilities have been eliminated.
Do not treat this review as production sign-off until the deployment requirements and validation gaps below are resolved.

## Refreshed advisories

| Advisory | Assessment |
| --- | --- |
| [CVE-2026-28809](https://cna.erlef.org/cves/CVE-2026-28809.html) | External esaml and xmerl parsing are absent from the runtime dependency graph; XML entities and doctypes are rejected before parsing, with unit and HTTP regression tests. |
| [CVE-2026-53424](https://cna.erlef.org/cves/CVE-2026-53424.html) | Accepted message IDs are consumed once; the request-owned ETS bug was reproduced and replaced with a supervised, bounded cache; real HTTP replay and concurrent-consumption tests cover this. |
| [CVE-2026-53425](https://cna.erlef.org/cves/CVE-2026-53425.html) | AuthnRequest IDs are stored in the browser session and checked against signed SubjectConfirmationData; the response and selected confirmation must agree; unsolicited responses cannot replace a pending SP flow. |
| [CVE-2026-75538](https://cna.erlef.org/cves/CVE-2026-75538.html) | The local OTP 29.0.5 runtime is affected; upgrade to 29.0.6 or later before deployment; CI uses patched OTP releases. |

The dependency advisory repository was checked against its remote HEAD at `5246bccd929b29309a014670b41ed2f2c6918c39` on the review date.
Hex package advisory data was checked separately for Samly and Plug because dependency audits do not audit this checkout as a dependency, and advisory feeds can differ.
Plug 1.20.3 is locked, outside its currently published vulnerable ranges.
The upstream Samly advisory ranges remain open-ended; local fixes do not change the upstream advisory database or constitute an official patched release.

## Hardening and regression coverage

- Replay entries survive the accepting request process, consumption is serialized, and a full or unavailable cache fails closed.
- Replay keys are SHA-256 hashes to bound per-entry identifier storage, and entries remain protected through the accepted clock-skew window.
- XML uses binary names and values, rejects entities, and limits bytes, element count, and nesting depth.
- An atom-count regression warms the parser then parses 10,000 distinct attacker-controlled element names, attribute names, and values without creating atoms.
- Unqualified security attributes cannot be supplied under attacker-controlled prefixes.
- SAML and signature element namespaces, versions, signed-reference uniqueness, and supported signature structures are checked.
- Unsupported canonicalization algorithms and transform parameters are rejected rather than silently interpreted as supported algorithms.
- Validation, identity extraction, request correlation, and replay expiry use the same bearer confirmation.
- Plaintext assertions are rejected when encryption is mandatory; decrypted assertions are verified in the reconstructed document after envelope verification.
- POST logout signatures are mandatory at the HTTP boundary; Redirect logout signatures are verified over the original query before bypassing XML-signature requirements.
- Logout validates issuer, destination, age, expiry, and replay; responses must match the stored logout request ID.
- IdP logout respects SessionIndex and does not drop an unrelated browser session.
- Relative and explicitly allowed return URLs share validation; ASCII controls and backslashes are rejected; absent IdP-initiated allowlists do not permit arbitrary external redirects.
- Already-decoded RelayState is not decoded a second time, and session RelayState comparison uses constant-time comparison.
- Sign-in HTML escapes interpolated attributes and preserves the intended target path.
- Invalid metadata and unknown service providers cannot activate an identity provider.
- SP configuration and logout callback failures no longer log full configuration maps or callback exception text.

## Build gates

`mix quality.verify` runs formatting checks, warning-as-error compilation, strict Credo, Dialyzer, Sobelow, dependency checks, and tests.
`mix security.check` runs dependency vulnerability checks, Hex retirement/security checks, and Sobelow.
CI invokes the full quality gate plus Hex auditing on pushes, pull requests, manual runs, and weekly scheduled runs.
CI tests OTP 27.3.4.17, 28.5.0.6, and 29.0.6 with Elixir 1.20.

Sobelow exits nonzero for findings at every confidence level, including low confidence.
Only function-local exceptions are used, each with an adjacent rationale: configuration-owned certificate/key/metadata file reads, escaped HTML form rendering, and XML metadata responses.
No entire finding class or source file is globally ignored.
Samly is a Plug library without a Phoenix router, so Sobelow's Phoenix-router-specific CSRF/header/CSP checks do not run; the hosting application must run its own scanner as well.
The existing Styler formatter configuration is retained, its missing dependency is installed, and Credo's line-length check matches the configured 200-column format.

## Deployment requirements and remaining validation

The local test runtime was Elixir 1.20.4 with OTP 29.0.5; its machine-wide installation was not modified.
OTP 29.0.6 or a patched supported release line is required before deployment.
The TCP-driver advisory requires an exposed inet-driver socket using packet-4 framing; this review did not establish that exposure through Samly's HTTP endpoints.
The patched Linux OTP matrix has not been executed locally.

The default replay cache is node-local and in-memory, with a 100,000-entry limit and periodic expiry cleanup.
It does not preserve replay history across VM/cache restarts or share history across replicas.
For restart-safe or multi-node deployments, configure a durable shared `Samly.ReplayCache` implementation with atomic consume semantics and fail-closed behavior.
Until such a store is deployed, previously accepted assertions may be reusable following cache loss or on another node.
Rate-limit SAML endpoints and bound HTTP request bodies in the hosting application and reverse proxy.

Provider configuration, metadata sources, signing certificates, key paths, and callback modules are privileged inputs and must not be editable by unauthenticated users.
Use HTTPS, secure session cookies, protected signing keys, trusted external-base/Host configuration, and current host/runtime security updates.
Keep legacy SHA-1 compatibility disabled unless explicitly required by a reviewed IdP integration.

The signature tests include adversarial inputs, real HTTP login flows, and a namespace/escaping canonicalization vector cross-checked with libxml2's `xmllint --exc-c14n`.
Signed-message fixtures are still primarily generated by the same implementation they verify.
Broader independent XMLDSig vectors and interoperability tests against real IdPs are still required before claiming full drop-in compatibility or production cryptographic assurance.
The explicit `mix test --cover` measurement was approximately 64% and failed Mix's default 90% threshold; that threshold was not lowered to hide the gap.
The quality gate currently runs tests but does not enforce coverage, and green scanners do not substitute for closing this gap.
