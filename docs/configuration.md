# Configuration reference

[README](../README.md) · [Phoenix setup](phoenix_setup.md) · [Security review](../SECURITY_REVIEW.md)

This reference is checked against this checkout's configuration loaders and request handlers.
Defaults below are loader defaults, not necessarily the values of a freshly constructed internal struct.
Use atom keys for trusted Elixir configuration and string values for external identifiers and URLs.
Boolean options require actual `true` or `false`, not environment-variable strings such as `"true"`.
Unknown map keys are not a supported extension mechanism and may be silently ignored.

## Configuration locations

```elixir
import Config

config :samly, Samly.Provider,
  idp_id_from: :path_segment,
  service_providers: [],
  identity_providers: []

config :samly, Samly.State,
  store: Samly.State.ETS,
  opts: []

config :samly, :config_provider, Samly.ConfigProvider.Application
config :samly, :replay_cache, Samly.ReplayCache.ETS
```

The empty provider lists above illustrate structure only; they do not configure a working login.
Use the [complete runtime example](phoenix_setup.md#3-configure-samly-at-runtime) for setup.

## Application-level settings

| Key under application `:samly` | Default | Possible values | Purpose and constraints |
| --- | --- | --- | --- |
| `Samly.Provider` | `[]` | Keyword list in the next table | Provider definitions and IdP resolution mode. |
| `Samly.State` | `[]` | Keyword list with `store` and `opts` | Authenticated assertion storage; distinct from replay prevention. |
| `:config_provider` | `Samly.ConfigProvider.Application` | Module implementing `Samly.ConfigProvider` | Calls `get_idp(conn, idp_id)` during route resolution; returns a valid provider struct or `nil`. |
| `:replay_cache` | `Samly.ReplayCache.ETS` | Module implementing `Samly.ReplayCache` | Atomic one-time-use checks; configure a durable shared implementation for restart safety or multiple nodes. |
| `:external_base_url` | `nil` | Absolute HTTP/HTTPS URL string, e.g. `"https://app.example.com/sso"` | Trusted fallback base, including mount path, when the SP metadata URI is relative; use HTTPS in production and omit query, fragment, and userinfo. |
| `:trusted_hosts` | `[]` | List of exact hostname strings | Fallback may use the request scheme/host/port only if `conn.host` matches; not a general Host allowlist or wildcard mechanism. |

With an absolute IdP `base_url`, the URI resolver returns the constructed SP URIs unchanged: `external_base_url` does not override them.
Prefer that explicit absolute configuration over relying on request-derived URLs.

## Provider settings

These belong inside `config :samly, Samly.Provider, ...`.

| Setting | Default | Possible values | Purpose and requirements |
| --- | --- | --- | --- |
| `idp_id_from` | `:path_segment` | `:path_segment`, `:subdomain` | Select IdP by final route segment or first hostname label; invalid values log a warning and fall back to path segments. |
| `service_providers` | `[]` | List of atom-keyed maps | SP definitions; at least one usable definition is required for configured IdPs. |
| `identity_providers` | `[]` | List of atom-keyed maps | IdP definitions referencing SP IDs; normally at least one usable definition is required for endpoint mounting. |

Start `{Samly.Provider, []}` in the supervision tree.
The argument to `start_link/1` is a GenServer options list, not the provider configuration; a standard option such as `name: Samly.Provider` registers the process but does not configure IdPs.
Provider state is stored in application environment, not isolated per GenServer instance.

## Service-provider settings

Each entry in `service_providers` accepts these settings.

| Setting | Default | Possible values | Purpose and requirements |
| --- | --- | --- | --- |
| `id` | `""` | Unique nonempty string | Required local SP identifier; referenced by an IdP's `sp_id`; not sent as the SAML entity ID. |
| `entity_id` | `""` | Stable string, commonly a URN or HTTPS identifier | SP SAML entity ID and expected audience; empty uses the metadata URI; explicitly set in production. |
| `certfile` | `""` | Path string to one PEM certificate | Public SP signing certificate; required with default signing settings; use absolute deployment paths. |
| `keyfile` | `""` | Path string to an unencrypted PEM private key | Matching RSA signing/decryption key; required with default signing settings; no passphrase option. |
| `contact_name` | `"Samly SP Admin"` | String | Technical contact retained in internal configuration; current metadata generator does not emit it. |
| `contact_email` | `"admin@samly"` | String | Technical contact email retained internally; currently not emitted in metadata. |
| `org_name` | `"Samly SP"` | String | Organization name retained internally; currently not emitted in metadata. |
| `org_displayname` | `"SAML SP built with Samly"` | String | Organization display name retained internally; currently not emitted in metadata. |
| `org_url` | `"https://github.com/handnot2/samly"` | URL string | Organization URL retained internally; currently not emitted in metadata. |

The key is `entity_id`, not the old README's `identity_id` typo.
Read failures or invalid key/certificate loading can exclude an SP and therefore its IdPs.
Samly does not expose inline SP key/certificate, key password, or certificate-chain settings through this loader.

## Identity-provider settings

Each entry in `identity_providers` accepts the following settings.

| Setting | Default | Possible values | Purpose and requirements |
| --- | --- | --- | --- |
| `id` | No usable default | Unique nonempty string, e.g. `"workforce"` | Required local IdP identifier; use simple URL-safe identifiers and keep them stable. |
| `sp_id` | No usable default | String matching an SP `id` | Required reference to the SP credentials and entity ID used for this IdP. |
| `base_url` | `nil` | Absolute HTTP/HTTPS base string or relative mount string | Public SAML base, including `/sso` or another mount path; explicitly set absolute HTTPS in production; see URL caveats below. |
| `metadata_file` | `"idp_metadata.xml"` | File path string, or `nil` with inline metadata | IdP XML source; use a trusted absolute path; ignored whenever `metadata` is non-nil. |
| `metadata` | `nil` | XML string or `nil` | Inline trusted metadata, taking precedence over `metadata_file`; not a URL; empty or malformed XML does not activate a provider. |
| `use_redirect_for_req` | `false` | Boolean | `false` sends HTTP-POST; `true` sends HTTP-Redirect for outbound SAML requests/responses; explicitly choose a binding supported by the metadata. |
| `sign_requests` | `true` | Boolean | Signs outgoing authentication/logout messages; requires SP credentials; keep enabled in production. |
| `sign_metadata` | `true` | Boolean | Signs the served SP metadata; requires SP credentials; independent of `sign_requests`. |
| `signed_assertion_in_resp` | `true` | Boolean | Requires an XML signature on the authentication assertion. |
| `signed_envelopes_in_resp` | `true` | Boolean | Requires an XML signature on the authentication response envelope; both incoming signature flags cannot be `false`. |
| `allow_idp_initiated_flow` | `false` | Boolean | Allows unsolicited login only when no SP request is pending; review login-CSRF implications before enabling. |
| `allowed_target_urls` | `nil` in loader | List of exact URL strings, `[]`, or `nil` | Adds permitted return destinations for local sign-in/sign-out and IdP-initiated login; safe relative paths are always allowed; `nil` and `[]` do not allow arbitrary external URLs. |
| `nameid_format` | First metadata `NameIDFormat`, otherwise `:unknown` | `:email`, `:x509`, `:windows`, `:krb`, `:persistent`, `:transient`, or URI string | Overrides outgoing NameIDPolicy format; omitted or `""` retains metadata selection; see mapping table. |
| `force_authn` | `false` | Boolean | Adds `ForceAuthn="true"` when a new AuthnRequest is generated; an existing active local assertion still short-circuits sign-in, so this is not a complete reauthentication guarantee. |
| `allow_legacy_sha1` | `false` | Boolean | Explicit per-IdP opt-in to legacy SHA-1 signature verification; keep disabled; outgoing signatures remain SHA-256. |
| `pre_session_create_pipeline` | `nil` | Plug module or `nil` | Invoked after assertion validation and before storage; receives `conn.private[:samly_assertion]`; modify `computed` or halt with a response. |
| `post_session_cleanup_pipeline` | `nil` | Plug module or `nil` | Invoked during applicable validated logout cleanup; receives a connection; can halt; not a universal expiry hook. |
| `on_logout` | `nil` | Function of arity 2 or `nil` | Called with `(idp_id, assertion)` during local initiation/matching IdP logout; return ignored and exceptions caught; invalid callback types reject provider loading. |
| `custom_consume_uri` | `nil` | URL string or `nil` | Compatibility ACS path override; converted internally to a charlist; limited URI resolution behavior described below. |
| `custom_logout_uri` | `nil` | URL string or `nil` | Compatibility SLO path override; same limitations as the ACS override. |
| `debug_mode` | `false` | Boolean | Accepted compatibility field; current handlers do not use it to enable payload reflection or debug output. |

At least one trusted metadata source and usable signing certificate are necessary.
Leaving SP key/certificate files empty requires both outbound signing options disabled and is unsuitable for the recommended production profile.
Invalid boolean values are ignored in favor of defaults; invalid nonboolean settings can reject a provider or fail later, so do not rely on implicit coercion.
Lists in `allowed_target_urls` are filtered to binary strings, not validated as a complete URL policy by the loader.
Configure only reviewed HTTP(S) external destinations; avoid exotic schemes even in an explicit allowlist.

### NameID mappings

| Value | SAML format URI |
| --- | --- |
| `:email` | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |
| `:x509` | `urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName` |
| `:windows` | `urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName` |
| `:krb` | `urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos` |
| `:persistent` | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` |
| `:transient` | `urn:oasis:names:tc:SAML:2.0:nameid-format:transient` |
| Nonempty string | Passed as the format URI, allowing an IdP-specific value. |
| Omitted / `""` | Uses metadata selection; if unknown, outgoing NameIDPolicy omits `Format`. |

Unknown atom values log an error and retain the metadata-derived format.
`nil` is not the documented way to request omission; use an omitted setting or `""`.
The current metadata generator advertises `unspecified` independently of this outgoing AuthnRequest setting.

### URL and binding caveats

- Include a non-root mount path in `base_url`, such as `https://app.example.com/sso`, and omit a trailing slash.
- With `base_url: nil`, the endpoint plug does not discover a normal mount and the URI helper does not provide a reliable automatic-origin fallback; do not omit it.
- For a relative base such as `"/sso"`, set `config :samly, :external_base_url, "https://app.example.com/sso"`; without it, fallback requires an exact `trusted_hosts` match and derives the request origin with `/sso`.
- `Samly.Plug` matches configured URI paths, not their hosts; enforce public Host restrictions separately, especially in multi-tenant deployments.
- Custom ACS/SLO paths are intercepted by `Samly.Plug`, but the current SP URI resolver applies custom URI overrides only in the relative-base branch; an absolute `base_url` can therefore advertise and validate the standard path instead of the custom path.
- Treat custom URIs as a compatibility feature requiring an integration test, not a guaranteed absolute-base replacement; the standard absolute-base routes are recommended.
- Custom paths and overlapping base mounts must not collide between IdPs; route selection iterates the loaded provider map and is not a declared routing-priority policy.
- Omission of `use_redirect_for_req` leaves the sender in POST mode while endpoint selection prefers POST and may fall back to a Redirect endpoint; explicitly configure the intended binding to avoid this mismatch.

## Assertion-state settings

These belong in `config :samly, Samly.State, ...`.

| Setting | Default | Possible values | Purpose |
| --- | --- | --- | --- |
| `store` | `Samly.State.ETS` | `Samly.State.ETS`, `Samly.State.Session`, or module implementing `Samly.State.Store` | Selects authenticated assertion storage. |
| `opts` | `[]` | Keyword list understood by the selected store | Passed to `store.init/1`; the returned options are passed to subsequent operations. |
| `opts[:table]` for ETS | `:samly_assertions_table` | Predefined atom | Named public ETS table; binary names are rejected; never create atoms from tenant/request input. |
| `opts[:key]` for Session | `"samly_assertion"` | String or predefined atom | Plug session key holding `{assertion_key, assertion}`. |

Only the selected store consumes its options.
Both built-in stores check the subject's `NotOnOrAfter` when reading an assertion; neither offers a configurable Samly session TTL.
A longer Phoenix cookie lifetime does not extend assertion validity.
The ETS table is initialized by the provider and is not durable or shared across BEAM nodes.
The session store is not a separate session middleware: configure `Plug.Session` in Phoenix as well.

Custom stores implement `init/1`, `get_assertion/3`, `put_assertion/4`, and `delete_assertion/3`.
Reads return `Samly.Assertion` or `nil`; writes/deletes return the updated `Plug.Conn`.
Enforce expiry, proper isolation of `{idp_id, name_id}`, and safe failure handling in custom implementations.

## Replay storage and fixed protocol limits

These values describe the current implementation; they are not all public application settings.

| Control | Current value / possible values | Configuration status |
| --- | --- | --- |
| Replay provider | `Samly.ReplayCache.ETS` or custom behavior module | Public `:replay_cache` application setting. |
| Replay callback | `consume(binary_key, DateTime)` returning `:ok` or `{:error, reason_atom}` | Behavior contract; duplicate reason is `:replayed`; binary key is already SHA-256 hashed by the facade. |
| Default replay capacity | 100,000 entries | Built-in child `init/1` accepts `:max_entries`, but the application starts it with no options; no public application setting forwards this value. |
| Default replay cleanup | Every 60 seconds | Fixed implementation interval. |
| Replay lifetime | Accepted assertion expiry plus 120 seconds | Derived from validated messages; custom stores must not shorten it. |
| XML input limit | 1,048,576 bytes | Internal `XML.parse/2` accepts `:max_bytes`; not exposed through public provider configuration. |
| XML nesting | 128 levels | Fixed parser limit. |
| XML element count | 10,000 | Fixed parser limit. |
| Encoded SAML payload | 1,398,104 bytes | Internal binding decoder option `:max_encoded_bytes`; no provider-level override. |
| Inflated SAML payload | 1,048,576 bytes | Internal binding decoder option `:max_inflated_bytes`; no provider-level override. |
| Assertion clock skew | 120 seconds | Fixed protocol validation allowance; synchronize clocks rather than trying an unsupported skew option. |
| Logout age | IssueInstant may be up to 120 seconds ahead; age must be less than 420 seconds | Fixed validation window; supplied expiry is also checked. |
| Outgoing signature | RSA/SHA-256 | No public algorithm-selection setting. |
| Incoming signature | RSA/SHA-256; legacy RSA/SHA-1 by explicit opt-in | Only `allow_legacy_sha1` changes this profile. |
| Canonicalization | Exclusive C14N, no comments, supported enveloped/exclusive transforms | No configurable transform or InclusiveNamespaces support. |
| Assertion encryption | RSA-OAEP key wrapping and AES-128/256-GCM | Uses the SP key; no public encryption-algorithm selector. |

An internal `encrypt_mandatory` record field exists, but the public IdP loader does not populate it from configuration.
Do not claim that setting `encrypt_mandatory: true` in an IdP map enforces encryption; it is not a supported public option in this checkout.
Do not configure internal record fields to bypass signature checks or tune security limits without changing and testing the implementation.

## Phoenix settings relevant to Samly

These belong to Phoenix or Plug, not to `config :samly`.
They are the integration-critical subset, not an exhaustive list of every Phoenix or Bandit option.

| Setting / location | Required or recommended value | Purpose |
| --- | --- | --- |
| Endpoint `adapter` | `Bandit.PhoenixAdapter` | Uses Bandit; Samly does not select the application's HTTP server. |
| Endpoint `url` | Public HTTPS `host`, `scheme`, and `port` | Phoenix public URL generation; does not replace Samly's `base_url`. |
| Endpoint `secret_key_base` | Strong deployment secret | Signs/encrypts browser sessions; must be compatible across replicas. |
| Endpoint `force_ssl` | Appropriate HTTPS policy in compile-time production config | HTTPS enforcement and HSTS; trust forwarded headers only from controlled proxies. |
| `Plug.Parsers` `parsers` | Include `:urlencoded` | Decodes SAML form bodies before Samly. |
| `Plug.Parsers` `length` | Explicit bounded size appropriate to your routes | Prevents oversized bodies before SAML decoding; preserve host upload requirements. |
| `Plug.Session` `store` | `:cookie` or an appropriate server-side store | Browser request-correlation state; required before Samly. |
| `Plug.Session` `key` | Application-specific cookie name | Separates sessions from unrelated applications. |
| Cookie `signing_salt` | Application-specific stable salt | Cookie-store key derivation, together with `secret_key_base`. |
| Cookie `encryption_salt` | Distinct stable salt when using cookie storage | Encrypts session contents instead of merely signing them. |
| Cookie `same_site` | `"None"` for cross-site SAML POST integration | Allows the pending browser session on the IdP POST; test browser policy. |
| Cookie `secure` | `true` in production | Requires HTTPS; needed with `SameSite=None`. |
| Cookie `http_only` | `true` | Prevents JavaScript reading the session cookie. |
| Cookie `path` | Usually `"/"` | Must cover application and SAML routes. |
| Cookie `domain` | Prefer omitted / host-only | Avoids unnecessary cross-subdomain exposure. |
| Cookie `max_age` | Host application's explicit policy | Cookie lifetime; not an extension of SAML assertion expiry. |
| Phoenix browser CSRF pipeline | Enabled on normal application routes | The dedicated Samly mount must stay outside that pipeline. |

See the official [Phoenix.Endpoint](https://hexdocs.pm/phoenix/Phoenix.Endpoint.html), [Plug.Session](https://hexdocs.pm/plug/Plug.Session.html), and [Bandit.PhoenixAdapter](https://hexdocs.pm/bandit/Bandit.PhoenixAdapter.html) references for complete host-server options.

## Managed state and unsupported settings

Do not configure the application keys `:service_providers`, `:identity_providers`, `:idp_id_from`, or `:state_store` directly.
They are populated by `Samly.Provider` and `Samly.State`; configure the documented nested keys instead.

The fields `entity_id`, `certs`, `fingerprints`, `sso_redirect_url`, `sso_post_url`, `slo_redirect_url`, and `slo_post_url` on an IdP struct are derived from metadata, not public overrides in an IdP configuration map.
Likewise `cert`, `key`, `valid?`, `esaml_sp_rec`, and `esaml_idp_rec` are loaded/internal state.
There are no public settings for metadata URL fetching, automatic refresh intervals, replay-cache TTL overrides, signature transform lists, inline SP private keys, or disabling POST logout verification.
The endpoint plug's initialization returns its input but its request handler ignores options; `plug Samly.Plug, path: "/custom"` does not change the mount.
Use the IdP `base_url` or the router-forward mount instead.

## Reload semantics

| Change | How to apply it |
| --- | --- |
| SP files, IdP metadata, IdP options | Update application configuration/files and call `Samly.Provider.refresh_providers/0` on each node; verify all required IDs loaded. |
| `idp_id_from` | Configure under `Samly.Provider` and restart provider/application initialization. |
| Assertion store or its options | Reinitialize through a controlled provider/application restart and plan for existing session migration or invalidation. |
| Custom replay/config-provider module | Read from application environment at use time; start dependencies first and coordinate transitions without losing replay history. |
| Endpoint module attributes / plug order | Recompile and deploy the host application. |

Changing replay stores without transferring still-live entries creates a replay window.
Changing signing secrets or storage policy can invalidate existing sessions; perform these changes deliberately.
