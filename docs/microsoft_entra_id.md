# Microsoft Entra ID (Azure AD) example

[README](../README.md) · [Phoenix setup](phoenix_setup.md) · [All configuration options](configuration.md)

This guide configures a single-tenant Microsoft Entra workforce enterprise application with this checkout's Samly 2 implementation and Phoenix/Bandit.
It is not an Azure AD B2C custom-policy, External ID customer-tenant, or OpenID Connect guide.
No OAuth client secret or Microsoft Graph permission is required for this SAML example.
Microsoft documentation was checked on September 7, 2026; portal labels can change.
These are configuration examples, not evidence of a completed live Entra interoperability test.
Complete the acceptance tests below before production use.

## 1. Choose the values for your environment

The application below is `:my_app`, with endpoint `MyAppWeb.Endpoint`.
Replace every example domain, identifier, and filesystem path consistently.
Use separate enterprise applications and credentials for staging and production.

| Value | Example | Where it is used |
| --- | --- | --- |
| Public application origin | `https://app.example.com` | Phoenix public URL and browser access. |
| Local Samly SP ID | `web` | SP `id` and IdP `sp_id`; not an Entra application ID. |
| Local Samly IdP ID | `entra` | IdP `id` and every SAML route suffix. |
| SP entity ID | `https://app.example.com/saml` | Samly `entity_id` and Entra Identifier; an identifier, not a required HTTP route. |
| SAML base URL | `https://app.example.com/sso` | Samly `base_url`; include `/sso`, with no trailing slash. |
| Tenant ID | `11111111-2222-3333-4444-555555555555` | Verify the tenant in downloaded metadata; never use this illustrative GUID. |
| SP certificate file | `/run/secrets/saml/sp-signing.crt` | Public RSA certificate read by Samly and uploaded to Entra for request verification. |
| SP private key file | `/run/secrets/saml/sp-signing.key` | Matching unencrypted PEM private key; keep only on the application side. |
| Entra metadata file | `/run/secrets/saml/entra-idp.xml` | Application-specific federation metadata downloaded from the portal. |

Use a dedicated RSA key pair provisioned by your organization's certificate/secret workflow.
The SP certificate is not the website's TLS certificate or Entra's token-signing certificate.
Mount secrets read-only and restrict the private key to the application's operating-system identity.

## 2. Create and configure the enterprise application

In the [Microsoft Entra admin center](https://entra.microsoft.com/), open **Entra ID > Enterprise apps**, create your own non-gallery application for the Phoenix service, then select **Single sign-on > SAML**.
Use an authorized application administrator and a nonproduction tenant/application first.
See Microsoft's [SAML enterprise application setup](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal-setup-sso).

Enter these values in **Basic SAML Configuration**:

| Portal field | Exact example value | Requirement |
| --- | --- | --- |
| Identifier (Entity ID) | `https://app.example.com/saml` | Must match SP `entity_id`, including case and trailing-slash policy. |
| Reply URL (Assertion Consumer Service URL) | `https://app.example.com/sso/sp/consume/entra` | Register as the default ACS for this environment; accepts POST. |
| Sign on URL | `https://app.example.com/sso/auth/signin/entra` | Starts login at Samly so browser request correlation exists. |
| Relay State | Leave blank | Samly manages RelayState for SP-initiated login. |
| Logout URL | `https://app.example.com/sso/sp/logout/entra` | SAML protocol callback, not the local sign-out initiation URL. |

The SP metadata is served at `https://app.example.com/sso/sp/metadata/entra` after the provider starts successfully.
Manual portal configuration above avoids assuming metadata import sets every policy.
Do not use the SP metadata URL as Entra's Reply URL.

For this restricted workforce example, set **Properties > Assignment required?** to **Yes**, then assign the intended test users or groups under **Users and groups**.
Apply your organization's Conditional Access and MFA policies, subject to tenant licensing.
User assignment controls access to the enterprise app; application authorization still belongs to Phoenix.

### Token signing and request verification

Under **SAML Certificates**, edit the token-signing configuration:

| Portal setting | Value | Matching Samly setting |
| --- | --- | --- |
| Signing Option | Sign SAML response and assertion | Both `signed_envelopes_in_resp: true` and `signed_assertion_in_resp: true`. |
| Signing Algorithm | SHA-256 | `allow_legacy_sha1: false`. |
| Verification certificates | Upload the public SP certificate | `certfile` must match the private `keyfile`. |
| Require verification certificates | Enable after uploading the SP certificate | `sign_requests: true`; test that unsigned requests are rejected. |

Entra supports signing both the response and assertion; selecting only the assertion does not satisfy this example's envelope requirement.
See [Microsoft's signing options](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/certificate-signing-options) and [signed-request enforcement](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/howto-enforce-signed-saml-authentication).
Request verification and token signing are opposite trust directions, so they use different certificates.
Never upload the SP private key to Entra or replace Samly's SP certificate with Entra's signing certificate.

### Download trusted metadata

Download **Federation Metadata XML** from this enterprise application's SAML certificate section and deploy it as `/run/secrets/saml/entra-idp.xml`.
If using the portal's **App Federation Metadata Url**, download through verified HTTPS using your controlled deployment workflow and preserve its application-specific query parameters.
Do not substitute generic tenant metadata when application-specific signing keys are in use.
Samly accepts XML or a file path, not a metadata URL, and does not automatically fetch or refresh remote metadata.

Compare the metadata with the portal's **Microsoft Entra Identifier**, **Login URL**, and **Logout URL**.
In the public cloud, common shapes are `https://sts.windows.net/<tenant-id>/` for the issuer and `https://login.microsoftonline.com/<tenant-id>/saml2` for endpoints, but use the actual trusted values rather than constructing them.
Other Microsoft clouds may use different hosts.
These values are loaded from metadata, not supplied as `tenant_id`, `login_url`, or `client_id` Samly options.
See [Microsoft federation metadata](https://learn.microsoft.com/en-us/entra/identity-platform/federation-metadata).

## 3. Configure NameID and attributes

This example explicitly requests `nameid_format: :persistent` for a stable opaque NameID.
Treat it as scoped to the trusted provider/application, not as an email address or globally portable user ID.
Entra supports this requested format as a pairwise identifier; request policy can affect the output even when portal defaults differ.
Inspect the actual NameID and repeat-login stability during acceptance testing.
See [Entra's NameIDPolicy behavior](https://learn.microsoft.com/en-us/entra/identity-platform/single-sign-on-saml-protocol#nameidpolicy).

Under **Attributes & Claims**, add these optional application-friendly claims with the **Namespace left blank** so their names match the example code:

| Claim name | Source attribute | Illustrative value | Application use |
| --- | --- | --- | --- |
| `object_id` | `user.objectid` | `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee` | Stable directory object identifier, scoped to this trusted tenant/provider. |
| `email` | `user.mail` | `alex@example.com` | Contact/display information; may be absent. |
| `given_name` | `user.givenname` | `Alex` | Optional display information. |
| `family_name` | `user.surname` | `Morgan` | Optional display information. |

Microsoft documents the claims editor and source attributes in [Customize SAML token claims](https://learn.microsoft.com/en-us/entra/identity-platform/saml-claims-customization).
Existing default claims may have URI names, such as `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`; Samly does not automatically rename those to `email`.
Either configure the short names above or read the exact emitted URI names.
Do not assume `user.mail` exists, that a UPN is a deliverable email address, or that an email-domain suffix proves application authorization.
Do not automatically link an existing privileged account solely by a matching email.

Prefer explicit application permissions rather than granting privileges from arbitrary group display names.
If adding group or role claims, define and test an exact allowlist and missing/oversized-claim handling; Samly does not fetch omitted group membership from Microsoft Graph.
Keep claim names and values as strings, never dynamically convert them to atoms.

## 4. Configure the Phoenix application

Install this reviewed Samly checkout and configure Bandit as explained in [Phoenix installation](phoenix_setup.md#1-install-this-implementation-and-choose-bandit).
The following environment names are example conventions read by `runtime.exs`, not variables Samly reads automatically:

```sh
export SAML_SP_CERTFILE=/run/secrets/saml/sp-signing.crt
export SAML_SP_KEYFILE=/run/secrets/saml/sp-signing.key
export SAML_IDP_METADATA_FILE=/run/secrets/saml/entra-idp.xml
# Supply SECRET_KEY_BASE through your deployment secret manager.
# For a new secret, generate it using: mix phx.gen.secret
```

```elixir
# config/runtime.exs
import Config

config :samly, Samly.Provider,
  idp_id_from: :path_segment,
  service_providers: [
    %{
      id: "web",
      entity_id: "https://app.example.com/saml",
      certfile: System.fetch_env!("SAML_SP_CERTFILE"),
      keyfile: System.fetch_env!("SAML_SP_KEYFILE")
    }
  ],
  identity_providers: [
    %{
      id: "entra",
      sp_id: "web",
      base_url: "https://app.example.com/sso",
      metadata_file: System.fetch_env!("SAML_IDP_METADATA_FILE"),
      use_redirect_for_req: true,
      nameid_format: :persistent,
      sign_requests: true,
      sign_metadata: true,
      signed_assertion_in_resp: true,
      signed_envelopes_in_resp: true,
      allow_legacy_sha1: false,
      allow_idp_initiated_flow: false,
      allowed_target_urls: [],
      force_authn: false
    }
  ]

config :my_app, MyAppWeb.Endpoint,
  url: [scheme: "https", host: "app.example.com", port: 443],
  secret_key_base: System.fetch_env!("SECRET_KEY_BASE")
```

**Use `use_redirect_for_req: true` for Entra**, unlike the generic guide's POST example.
Entra's documented login flow uses outgoing Redirect and incoming POST, and its SAML logout supports Redirect rather than POST.
See Microsoft's [SSO protocol](https://learn.microsoft.com/en-us/entra/identity-platform/single-sign-on-saml-protocol) and [single logout protocol](https://learn.microsoft.com/en-us/entra/identity-platform/single-sign-out-saml-protocol).
This option does not turn the ACS into a GET endpoint.

Set the adapter in `config/config.exs`:

```elixir
import Config

config :my_app, MyAppWeb.Endpoint, adapter: Bandit.PhoenixAdapter
```

Insert `{Samly.Provider, []}` into your existing application children after storage clients and before `MyAppWeb.Endpoint`.
Preserve the existing Repo, PubSub, and other application children.
Check `Samly.Helper.get_idp("entra") != nil` during readiness because invalid providers can be omitted without stopping the application.

In your existing endpoint, configure one session plug and retain unrelated sockets, static assets, and telemetry plugs:

```elixir
# Inside MyAppWeb.Endpoint; HTTPS is required for this cookie profile.
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

The stable salts above are not substitutes for a strong `secret_key_base`.
Adapt the body limit if other application routes accept larger uploads, while retaining appropriate SAML/proxy limits.
The Entra POST must carry the same browser session that started login, including across load-balanced replicas.
Keep Phoenix CSRF protection on normal application routes, but do not put the SAML callbacks through the browser CSRF pipeline.
Do not mount a duplicate router forward when using this endpoint plug.
Enforce HTTPS and the allowed public Host at the deployment boundary; trust forwarded headers only from controlled proxies.

### Storage is a separate production requirement

The default assertion store and replay cache are local in-memory ETS stores, suitable for isolated integration testing but not a complete restart-safe production design.
Follow [assertion and replay storage setup](phoenix_setup.md#4-choose-assertion-and-replay-storage).
For durable or multi-node deployments, supply a shared atomic replay backend, preserving accepted IDs until their supplied expiry even through restarts.
Use shared server-side assertion storage where cross-node access and central revocation are required.
These are application-supplied modules, not included Redis/database adapters.
Cookie encryption and sticky sessions do not make the replay cache durable.

## 5. Start login and consume the identity

Use an ordinary browser link to `/sso/auth/signin/entra?target_url=%2Fdashboard` rather than a LiveView patch/navigation event.
The target `/dashboard` must exist in your application.
With `allowed_target_urls: []`, safe relative return paths are allowed but arbitrary external targets are not.

Read a validated assertion in an authenticated application flow with the Plug session fetched:

```elixir
case Samly.get_active_assertion(conn) do
  nil ->
    {:error, :not_authenticated}

  assertion ->
    identity_key = {"entra", Samly.get_nameid(assertion)}
    email = Samly.get_attribute(assertion, "email")
    {:ok, %{identity_key: identity_key, email: email}}
end
```

This fragment returns data; it is not a complete Phoenix authentication plug or provisioning implementation.
Validate required claim types and map the provider-scoped identity to an authorized local account before establishing application access.
For multiple providers, derive the trusted provider scope from your authenticated integration rather than hardcoding `"entra"`.
Use a configured pre-session pipeline if claims must be checked before assertion storage, as shown in the [Phoenix guide](phoenix_setup.md).
LiveView mounts need their own server-side authentication/authorization checks.

## 6. Logout, launch behavior, and encryption

Start local logout through `/sso/auth/signout/entra?target_url=%2F`.
The Entra **Logout URL** remains `/sso/sp/logout/entra`, which receives protocol messages rather than initiating logout.
Test the complete Redirect logout exchange, including signed messages, issuer/destination checks, session index, and request correlation.
If Entra's actual logout message does not satisfy this implementation's signature requirements, record it as an interoperability blocker rather than disabling verification.
Do not assume a successful local redirect proves all Entra or other application sessions have ended.

Keep `allow_idp_initiated_flow: false` for the baseline.
Portal test/My Apps launch behavior must lead through the configured SP sign-on URL; an unsolicited response is intentionally rejected.
If unsolicited login is a business requirement, review login-CSRF risks and explicitly enable it with tested target restrictions and no pending SP request.

Do not enable Entra **Token encryption** as part of this baseline without a separate compatibility test.
This checkout supports a limited RSA-OAEP/AES-GCM profile and has no public setting that mandates encrypted assertions.
Microsoft's general AES-256 description alone does not establish algorithm-mode compatibility with this implementation.
If policy requires assertion encryption, block production rollout until actual encrypted Entra fixtures pass validation and the enforcement requirement is implemented.
See [Microsoft's token encryption guidance](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/howto-saml-token-encryption) and the [supported protocol limits](configuration.md#replay-storage-and-fixed-protocol-limits).

## 7. Rotation and acceptance checklist

Monitor expiry for Entra token-signing certificates and the separate SP request-signing certificate.
Stage trusted rollover metadata on every node, refresh providers using `Samly.Provider.refresh_providers/0`, and verify that `entra` loaded successfully before activating the new IdP signing key.
Samly does not poll the federation metadata URL.
For SP rotation, register the new public verification certificate in Entra before switching the matching application key/certificate files; test the overlap and retire old trust deliberately.
Never fetch trust certificates from an incoming assertion or silence signature failures during rollover.

| Test | Expected result |
| --- | --- |
| Metadata/readiness | `entra` is loaded; served metadata contains the configured entity ID, ACS, and logout URL. |
| Fresh SP login | Assigned user reaches the target through Entra and the cross-site POST retains correlation. |
| Repeat login | The same user's provider-scoped NameID is stable; a different user does not map to the same local identity. |
| User policy | Unassigned users and users blocked by configured tenant policy cannot gain application access. |
| Invalid messages | Tampered signatures, wrong audience/issuer/destination, expired assertions, and wrong/missing SP correlation are rejected. |
| Replay | The same accepted response cannot authenticate twice, including across nodes and controlled restarts with the production replay backend. |
| Claims | Missing email, guest accounts, and unexpected/multiple claim values do not bypass authorization or crash the application. |
| Logout | SP-initiated and supported IdP logout clear the intended local session; invalid/unsigned protocol messages remain rejected. |
| Rotation | Newly signed responses validate after the staged metadata update without removing required old trust prematurely. |
| Browser/proxy | Supported browsers work through the actual public HTTPS origin and production proxy/session topology. |

Use sanitized fixtures and private diagnostic tooling; do not paste live assertions, cookies, or keys into online SAML decoders or logs.
Complete the [production checklist](phoenix_setup.md#production-checklist), including patched OTP and security checks.
Green repository tests do not replace these live Entra acceptance tests.

## Troubleshooting

| Symptom | Check first |
| --- | --- |
| Entra reports unknown application or wrong audience | Identifier matches Samly `entity_id`, and the intended tenant/application metadata is deployed. |
| Entra rejects Reply URL | Exact HTTPS ACS is registered, including `/sso/sp/consume/entra`; no unexpected proxy host or trailing slash. |
| Samly returns 404 | Provider loaded, `base_url` includes `/sso`, and the route ends with local IdP ID `entra`. |
| Login returns 403 after Entra authentication | Dual signing, trusted metadata certificate, browser correlation cookie, SP-initiated entry, and synchronized clocks. |
| Request verification fails in Entra | Uploaded verification certificate matches the SP signing key, and Redirect query parameters were not rewritten by a proxy. |
| Logout fails while login works | Redirect binding, registered protocol Logout URL, and actual logout signature/correlation compatibility. |
| Email is `nil` | `user.mail` exists and claim Name/Namespace match the exact name read by the application. |
| Portal test fails but SP login works | Determine whether the test issued an unsolicited response; do not weaken the baseline just to satisfy a launch shortcut. |
| Failures begin after rollover | Metadata was refreshed on every node and contains the intended current signing certificate. |

For all accepted settings and unsupported options, use the [configuration reference](configuration.md).
