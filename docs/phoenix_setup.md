# Phoenix setup and production guide

[README](../README.md) · [Configuration reference](configuration.md) · [Security review](../SECURITY_REVIEW.md)

This guide describes this checkout's Samly 2 implementation, not the older published Samly 1.x behavior.
Examples use the Phoenix application `:my_app`, endpoint `MyAppWeb.Endpoint`, SP ID `web`, and IdP ID `workforce`.
Replace these names and all example domains and paths with your own values.

For Azure AD, use the [Microsoft Entra ID example](microsoft_entra_id.md), including its different outbound binding setting.

## Production checklist

These requirements are not satisfied simply by adding the dependency.

| Requirement | What you must do |
| --- | --- |
| Patched runtime | Use Elixir 1.20.x and a maintained, security-patched OTP release; the review's minimum patched versions are 27.3.4.17, 28.5.0.6, or 29.0.6 on their respective release lines. |
| Stable public identity | Set an explicit SP `entity_id` and absolute HTTPS IdP `base_url`, including the mounted path, without a trailing slash. |
| Trusted metadata | Obtain IdP metadata through an authenticated administrator workflow or TLS-verified source; verify its entity ID, endpoints, and signing certificates out of band. |
| SP credentials | Configure readable PEM `certfile` and matching RSA `keyfile`; protect the private key and register the certificate with the IdP. |
| Signed messages | Keep `sign_requests`, `sign_metadata`, `signed_assertion_in_resp`, and `signed_envelopes_in_resp` enabled unless a specific signed-response profile has been reviewed. |
| Modern cryptography | Configure RSA/SHA-256 signatures and keep `allow_legacy_sha1: false`; review encryption compatibility separately. |
| Cross-site SAML POST cookies | Make the session cookie available on the IdP's cross-site POST using `same_site: "None"`, `secure: true`, and `http_only: true`; test supported browsers. |
| Session secrets | Supply a strong `secret_key_base`; use an encrypted cookie or server-side session store for sensitive contents; share required secrets consistently across replicas. |
| Correct endpoint order | Body parsers and `Plug.Session` must precede Samly; Samly must precede the application router. |
| CSRF boundary | Keep Phoenix CSRF protection on application routes; do not put IdP callback endpoints through Phoenix's browser CSRF pipeline. |
| Replay protection | For cache restart safety or multiple nodes, deploy a durable shared atomic `Samly.ReplayCache` implementation; an assertion store is not a replay store. |
| Authorization | Map a trusted IdP-scoped identity to your application's user and permissions; successful SAML login is not administrative authorization. |
| Infrastructure limits | Bound request bodies and request rates, reject unexpected public Hosts, protect proxy headers, synchronize clocks, and avoid logging SAML payloads or secrets. |
| Deployment validation | Test real login, logout, certificate rollover, replay rejection, expiry, proxy URLs, cookies, and multi-node behavior before production traffic. |

The [security review](../SECURITY_REVIEW.md) records coverage and interoperability gaps.
The older implementation's history with a particular IdP is not evidence that the rewritten implementation has been tested with that IdP.

## 1. Install this implementation and choose Bandit

Use the reviewed checkout or an immutable commit of your own fork until a release containing this implementation is available.
Do not assume the package version declared in this checkout means Samly 2 is already published on Hex.

For a sibling checkout during development:

```elixir
defp deps do
  [
    {:samly, path: "../samly"},
    {:bandit, "~> 1.12.5"}
  ]
end
```

Keep the Phoenix dependencies already in your application.
For reproducible CI and releases, replace the path dependency with your fork's actual Git URL and an immutable reviewed `ref`, and commit `mix.lock`.
Do not duplicate Bandit if it is already a dependency.
Samly requires Plug 1.20.3 or compatible later 1.20.x releases; resolve any older direct Plug constraint in the host application.

Select the adapter explicitly:

```elixir
# config/config.exs
import Config

config :my_app, MyAppWeb.Endpoint,
  adapter: Bandit.PhoenixAdapter
```

Remove direct `:plug_cowboy` only after checking that nothing else in the host requires it.
Do not start a separate `Bandit` child for a Phoenix endpoint; the endpoint manages its server.
See the official [Phoenix adapter configuration](https://hexdocs.pm/phoenix/Phoenix.Endpoint.html#module-adapter-configuration).

## 2. Prepare keys and IdP metadata

The SAML signing certificate is separate from your website's TLS certificate.
Use a dedicated RSA key pair whose lifetime and rotation policy your IdP accepts.
The loader expects an unencrypted private-key PEM and a single certificate PEM; encrypted-key passwords and certificate-chain configuration are not public options here.
Protect an unencrypted key on disk with filesystem permissions and your secret-management system.

Mount credentials read-only with access restricted to the application identity.
Do not put private keys in Git, browser assets, container build layers, logs, or documentation examples.
Development keys must never be promoted to production.

Export the IdP's XML metadata and store it at a known absolute path, for example `/run/secrets/saml/idp.xml`.
Samly reads a file or inline XML; it does not fetch metadata URLs or periodically refresh remote metadata.
Never bypass TLS certificate verification when acquiring production trust metadata.
Use a single intended IdP entity document rather than relying on selection from an aggregate federation document.

## 3. Configure Samly at runtime

Put deployment-specific configuration in `config/runtime.exs`, before `Samly.Provider` starts:

```elixir
import Config

config :samly, Samly.Provider,
  idp_id_from: :path_segment,
  service_providers: [
    %{
      id: "web",
      entity_id: "urn:example:my-app",
      certfile: System.fetch_env!("SAML_SP_CERTFILE"),
      keyfile: System.fetch_env!("SAML_SP_KEYFILE")
    }
  ],
  identity_providers: [
    %{
      id: "workforce",
      sp_id: "web",
      base_url: "https://app.example.com/sso",
      metadata_file: System.fetch_env!("SAML_IDP_METADATA_FILE"),
      use_redirect_for_req: false,
      sign_requests: true,
      sign_metadata: true,
      signed_assertion_in_resp: true,
      signed_envelopes_in_resp: true,
      allow_idp_initiated_flow: false,
      allow_legacy_sha1: false,
      allowed_target_urls: []
    }
  ]

config :my_app, MyAppWeb.Endpoint,
  url: [scheme: "https", host: "app.example.com", port: 443],
  secret_key_base: System.fetch_env!("SECRET_KEY_BASE")
```

The environment-variable names are conventions for this example, not names Samly reads automatically.
`System.fetch_env!/1` intentionally fails startup when a required value is missing.
Use separate keys, metadata, entity IDs, and URLs for development, staging, and production.

`use_redirect_for_req: false` requires HTTP-POST endpoints in the IdP metadata for the flows you use.
If the IdP requires HTTP-Redirect, explicitly set it to `true` and validate both login and logout with that IdP.
The ACS receives HTTP-POST responses regardless of the outbound request binding.

If an IdP signs assertions but cannot sign envelopes, `signed_envelopes_in_resp: false` is an explicit interoperability exception while `signed_assertion_in_resp` remains `true`.
Review this configuration rather than turning off verification to hide an error.
Both flags being `false` is rejected by the protocol layer.

## 4. Choose assertion and replay storage

Three different storage concerns are involved:

| Storage | Purpose | Important limitation |
| --- | --- | --- |
| Phoenix `Plug.Session` | Pending request ID, RelayState, target, and active assertion key for the browser. | Required even with server-side assertions. |
| `Samly.State.Store` | Authenticated assertions for `Samly.get_active_assertion/1`. | Built-in ETS is node-local; the session store inherits the host session backend's properties. |
| `Samly.ReplayCache` | One-time use of accepted SAML message IDs. | The default cache is neither shared nor restart-durable. |

For single-node development, default `Samly.State.ETS` needs no configuration.
An explicit equivalent is:

```elixir
config :samly, Samly.State,
  store: Samly.State.ETS,
  opts: [table: :samly_assertions_table]
```

The alternative puts assertions in the existing Plug session:

```elixir
config :samly, Samly.State,
  store: Samly.State.Session,
  opts: [key: "samly_assertion"]
```

With cookie sessions, large assertions can exceed browser cookie limits, and copied cookies cannot be centrally revoked by deleting another browser's cookie.
Do not choose the cookie-backed assertion store solely because the deployment has multiple nodes.
Prefer a shared server-side assertion store for central revocation, large assertions, or cross-browser IdP logout.
Built-in stores key assertions by `{idp_id, name_id}`, not a unique browser session; assess concurrent logins for the same subject.

For durable replay protection, implement and deploy a module before configuring it:

```elixir
# This module must be supplied by your application.
config :samly, :replay_cache, MyApp.SAML.ReplayCache
```

`consume(key, expires_at)` receives a 32-byte SHA-256 binary key and a `DateTime` expiry already including acceptance clock skew.
Atomically return `:ok` exactly once, return `{:error, :replayed}` for duplicates, retain entries until expiry, and fail closed on failures.
Use an atomic conditional insert or transaction; separate read-then-write operations are unsafe.
Preserve history through cache-process and VM restarts, and use the same backend and namespace on every node.
Samly does not start your custom storage clients or supply a Redis/database adapter.

## 5. Start the provider before the endpoint

Insert Samly into the existing supervision tree after required storage clients and before the endpoint:

```elixir
children = [
  MyApp.Repo,
  # Retain existing PubSub and start any custom storage clients here.
  {Samly.Provider, []},
  MyAppWeb.Endpoint
]
```

The Samly OTP application starts its built-in replay-cache supervisor automatically.
Do not add a second Samly application supervisor or default replay-cache child.
Provider configuration is application-wide; several differently configured providers in one BEAM are not isolated.

Invalid providers may be logged and omitted rather than failing application startup.
Check required IDs during readiness, for example `Samly.Helper.get_idp("workforce") != nil`, and test metadata endpoints.
Do not print provider structs, which contain credential-related material.

## 6. Wire the Phoenix endpoint and browser cookie

Adapt the relevant part of the generated endpoint; retain existing sockets, static-file, telemetry, and development plugs.
Configure one session plug, not two:

```elixir
# Inside MyAppWeb.Endpoint; this cookie configuration assumes HTTPS.
@session_options [
  store: :cookie,
  key: "_my_app_session",
  signing_salt: "my-app-session-signing-v1",
  encryption_salt: "my-app-session-encryption-v1",
  same_site: "None",
  secure: true,
  http_only: true,
  path: "/"
]

plug Plug.Parsers,
  parsers: [:urlencoded, :multipart, :json],
  pass: ["*/*"],
  json_decoder: Phoenix.json_library(),
  length: 1_500_000

plug Plug.MethodOverride
plug Plug.Head
plug Plug.Session, @session_options
plug Samly.Plug
plug MyAppWeb.Router
```

The parser limit is an example for SAML-sized requests, not a universal upload limit.
If your application accepts larger uploads, use route-specific limits or enforce the SAML limit at the proxy.
Keep `:urlencoded` parsing enabled so the SAML POST body is available.
Salts distinguish cryptographic uses; the strong secret is the endpoint's `secret_key_base`.
See [Plug.Session](https://hexdocs.pm/plug/Plug.Session.html) for session and cookie options.

Cross-site HTTP-POST callbacks often arrive without `SameSite=Lax` or `Strict` cookies, breaking correlation.
Use HTTPS in development to test this production cookie policy; `Secure` cookies do not work over ordinary local HTTP.
Verify actual callback requests include the pending session cookie, especially with privacy controls or embedded login pages.
Prefer host-only cookies; do not share parent-domain session cookies across untrusted tenant subdomains.

Do not put endpoint-wide `Plug.CSRFProtection` before Samly.
Samly's `/auth` routes protect local POSTs with CSRF tokens, while `/sp/consume` and `/sp/logout` receive authenticated SAML messages and cannot supply Phoenix's CSRF token.
Keep CSRF, authorization, and security-header protection in your normal Phoenix `:browser` pipeline.

### Alternative: router forwarding

Use this instead of `plug Samly.Plug`, not in addition to it:

```elixir
# MyAppWeb.Router, ahead of catch-all scopes.
scope "/sso" do
  forward "/", Samly.Router
end
```

Do not attach `pipe_through :browser`, authentication gates, or other host pipelines to this scope.
Parsers and `Plug.Session` must still precede `MyAppWeb.Router` in the endpoint.
Custom path interception is specific to `Samly.Plug`; forwarding alone does not provide it.

## 7. Register the SP with the IdP

Verify these exact values in the IdP administration UI:

| IdP field or application action | Value |
| --- | --- |
| SP entity ID / audience | `urn:example:my-app` |
| SP metadata URL | `https://app.example.com/sso/sp/metadata/workforce` |
| ACS / reply URL, HTTP-POST | `https://app.example.com/sso/sp/consume/workforce` |
| SLO / logout callback | `https://app.example.com/sso/sp/logout/workforce` |
| Application sign-in link | `/sso/auth/signin/workforce` |
| Application sign-out link | `/sso/auth/signout/workforce` |

Import the actual served metadata and register the SP signing certificate.
Verify imported ACS, audience, and logout values match the public origin.
Inspect emitted metadata rather than assuming every historical option is serialized.
Configure NameID and attributes to match your application's identity model.
For encryption, test RSA-OAEP with AES-GCM; RSA PKCS#1 v1.5 and AES-CBC encrypted assertions are rejected.

## 8. Add login links and authorize requests

Use normal browser navigation to the sign-in or sign-out URL.
Samly serves a CSRF-bearing form that performs the local POST before sending the browser to the IdP.
Build optional return URLs using form encoding:

```elixir
signin_url =
  "/sso/auth/signin/workforce?" <>
    URI.encode_query(%{"target_url" => "/dashboard"})
```

Use `href` for full navigation, not a LiveView patch or navigation expecting a LiveView response.
Relative return paths are accepted; external destinations require exact `allowed_target_urls` entries.
An empty allowlist does not restrict navigation to selected internal paths: safe relative paths remain allowed.

In an application Plug after `fetch_session`:

```elixir
case Samly.get_active_assertion(conn) do
  nil ->
    conn
    |> Plug.Conn.send_resp(401, "authentication_required")
    |> Plug.Conn.halt()

  assertion ->
    Plug.Conn.assign(conn, :saml_assertion, assertion)
end
```

Enforce application-specific authorization separately.
Scope identity by IdP and NameID; do not link accounts solely by email without an explicit trusted account-linking policy.
Attributes and computed values use string keys and may contain strings or lists.
Never turn arbitrary SAML group or attribute names into atoms.

For LiveView, derive the application's user from its trusted session and validate it in `on_mount` and sensitive events.
Samly does not supply a LiveView authentication hook, and an initial HTTP assign does not authorize later socket events.

## 9. Customize user mapping and logout

`pre_session_create_pipeline` receives the validated assertion at `conn.private[:samly_assertion]` before storage.
Use it for vetted mapping, authorization, or idempotent provisioning:

```elixir
defmodule MyAppWeb.SAMLAttributes do
  use Plug.Builder

  plug :map_attributes

  defp map_attributes(conn, _opts) do
    assertion = conn.private[:samly_assertion]

    case Map.get(assertion.attributes, "email") do
      email when is_binary(email) and email != "" ->
        computed = Map.put(assertion.computed, "email", email)
        Plug.Conn.put_private(conn, :samly_assertion, %{assertion | computed: computed})

      _ ->
        conn |> send_resp(403, "required_attribute_missing") |> halt()
    end
  end
end
```

Set `pre_session_create_pipeline: MyAppWeb.SAMLAttributes` in the IdP map.
The handler preserves changes to `computed`, not replacements of signed subject or attribute fields.
Pipelines are invoked as `module.call(conn, [])`; there is no pipeline-options setting or separate automatic `init/1` invocation.

`post_session_cleanup_pipeline` receives the connection during applicable validated logout cleanup.
Do not assume it receives `:samly_assertion` or runs for every logout targeting another user's server-side assertion.
`on_logout: &MyApp.SAMLAudit.logged_out/2` receives `(idp_id, assertion)` and requires an exported function available in the release.
It runs during local sign-out initiation and matching IdP-initiated logout, not as a session-expiry callback or confirmation of completed remote logout.
Its return is ignored and exceptions are caught; it must not be the sole transaction guaranteeing authorization revocation.

## 10. Proxies and multiple tenants

Absolute `base_url` is recommended.
`external_base_url` and `trusted_hosts` are fallback URL-construction controls, not universal Host filters.
Reject unexpected Hosts at ingress or an application Plug before Samly.
Configure Phoenix's public `url` independently; Samly does not read it to populate providers.
Only honor forwarded headers from trusted proxies that strip or replace client-supplied values.
Enable HTTPS enforcement in Phoenix's compile-time production configuration and verify it does not redirect or lose IdP POST bodies.

For multiple IdPs, use unique string IDs referencing the appropriate SP definitions.
With `idp_id_from: :subdomain`, the first hostname label is the ID: `workforce.example.com` selects `workforce`, and routes omit the final IdP segment.
Configure tenant-specific absolute base URLs, DNS, TLS, Host restrictions, and session isolation.

Dynamic resolution uses `Samly.ConfigProvider.get_idp(conn, idp_id)`, returning a valid `Samly.IdpData` or `nil` from trusted configuration.
`Samly.Plug` discovers paths from loaded application-environment providers; a custom resolver does not automatically register endpoint paths.
Use a known router-forward mount for dynamic resolution or explicitly maintain mounted provider configuration.
Never populate `conn.private[:samly_idp]` from untrusted data; a pre-populated valid provider bypasses normal lookup.

## Rotation, readiness, and troubleshooting

Update configuration or mounted metadata, then call `Samly.Provider.refresh_providers/0` on every node to reload SP credentials and IdP definitions.
Refresh does not reinitialize assertion storage or change `idp_id_from`; restart through your deployment process for those changes.
Check required IDs after refresh, then test metadata and login.
Coordinate IdP and SP signing-certificate rollover before retiring old trust material.

| Symptom | Check |
| --- | --- |
| `404` on Samly paths | Endpoint ordering, mounted path, non-nil `base_url`, and loaded providers. |
| Unknown IdP | Provider logs, IDs, certificate files, metadata, and path versus subdomain mode. |
| CSRF exception on callback | Remove Phoenix's browser pipeline from the dedicated SAML scope, not from the rest of the application. |
| RelayState/request ID mismatch | Cookie flags, domain/path, shared secrets, session expiry, and competing login attempts in one browser session. |
| Audience/destination rejection | Exact entity ID, ACS URL, proxy origin, trailing slashes, and IdP registration. |
| Signature rejection | Trusted metadata, rollover certificates, SHA-256, and supported canonicalization; do not disable checks as a workaround. |
| Replay/cache error | Duplicate submissions, cache availability/capacity, and shared-store consistency. |
| Immediate expiry | Clock synchronization and IdP validity windows; built-in stores use subject expiry, not cookie lifetime alone. |
| Logout fails | SLO binding, issuer/destination, request correlation, SessionIndex, signature, and message age. |
| Encryption fails | RSA-OAEP/AES-GCM compatibility, correct SP key, and independent testing of your IdP profile. |

Protocol errors are operational diagnostics, not browser response content.
Run this repository's quality gates and the host application's own tests and security scanners; Samly's development dependencies are not inherited by consumers.
Include real browser/IdP and multi-node replay tests in release acceptance rather than relying solely on self-generated signatures.
