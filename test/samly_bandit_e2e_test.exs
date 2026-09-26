defmodule Samly.BanditEndpoint do
  use Plug.Builder

  plug :put_secret_key_base
  plug Plug.Parsers, parsers: [:urlencoded], pass: [], length: 1_500_000

  plug Plug.Session,
    store: :cookie,
    key: "_samly_test",
    signing_salt: "samly-test-signing-salt"

  plug Samly.Plug

  plug :not_found

  defp put_secret_key_base(conn, _opts) do
    %{conn | secret_key_base: String.duplicate("samly-e2e-secret-", 4)}
  end

  defp not_found(conn, _opts), do: Plug.Conn.send_resp(conn, 404, "not_found")
end

defmodule Samly.BanditE2ETest do
  use ExUnit.Case, async: false

  alias Samly.SAML.Key
  alias Samly.SAML.XMLDSig

  setup do
    {:ok, socket} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(socket)
    :ok = :gen_tcp.close(socket)

    previous = Application.get_env(:samly, Samly.Provider)
    previous_runtime = Map.new([:identity_providers, :service_providers, :state_store], &{&1, Application.fetch_env(:samly, &1)})
    Samly.State.init(Samly.State.Session)
    {:ok, certificate} = Key.load_certificate("test/data/test.crt")

    metadata = """
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="urn:test:idp"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>#{Base.encode64(certificate)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>
    """

    Application.put_env(:samly, Samly.Provider,
      service_providers: [
        %{
          id: "sp1",
          entity_id: "urn:test:sp1",
          certfile: "test/data/test.crt",
          keyfile: "test/data/test.pem"
        }
      ],
      identity_providers: [
        %{
          id: "idp1",
          sp_id: "sp1",
          base_url: "http://127.0.0.1:#{port}/sso",
          metadata: metadata,
          allow_idp_initiated_flow: true
        }
      ]
    )

    {:ok, _state} = Samly.Provider.refresh_providers()
    {:ok, server} = Bandit.start_link(plug: Samly.BanditEndpoint, port: port, ip: {127, 0, 0, 1})
    :inets.start()

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :shutdown)

      if previous do
        Application.put_env(:samly, Samly.Provider, previous)
      else
        Application.delete_env(:samly, Samly.Provider)
      end

      for {key, value} <- previous_runtime do
        case value do
          {:ok, value} -> Application.put_env(:samly, key, value)
          :error -> Application.delete_env(:samly, key)
        end
      end
    end)

    %{port: port}
  end

  test "a bearer assertion cannot create sessions through two independent HTTP requests", %{port: port} do
    payload = signed_response(port)
    assert {:ok, {{_, 302, _}, headers, _body}} = post_response(port, payload, "/")
    assert List.keyfind(headers, ~c"set-cookie", 0)
    assert {:ok, {{_, 403, _}, _headers, ~c"access_denied"}} = post_response(port, payload, "/")
  end

  test "IdP-initiated login rejects external RelayState without an allowlist", %{port: port} do
    assert {:ok, {{_, 403, _}, _headers, ~c"access_denied"}} =
             post_response(port, signed_response(port), "https://evil.example")
  end

  test "rejects XML entities at the HTTP assertion endpoint", %{port: port} do
    xml = ~s(<!DOCTYPE Response [<!ENTITY x SYSTEM "file:///etc/hostname">]><Response>&x;</Response>)
    assert {:ok, {{_, 403, _}, _headers, ~c"access_denied"}} = post_response(port, xml, "/")
  end

  defp post_response(port, xml, relay) do
    body = URI.encode_query(%{"SAMLResponse" => Base.encode64(xml), "RelayState" => relay})
    :httpc.request(:post, {~c"http://127.0.0.1:#{port}/sso/sp/consume/idp1", [], ~c"application/x-www-form-urlencoded", body}, [autoredirect: false], body_format: :string)
  end

  test "SP-initiated responses must match the request ID stored in the browser session", %{port: port} do
    for {response_to, expected_status} <- [{"_pending", 302}, {"_other", 403}, {nil, 403}] do
      conn =
        :post
        |> Plug.Test.conn("/sso/sp/consume/idp1", %{"SAMLResponse" => Base.encode64(signed_response(port, response_to)), "RelayState" => "state"})
        |> Plug.Test.init_test_session(%{"req_id" => "_pending", "relay_state" => "state", "idp_id" => "idp1", "target_url" => "/"})
        |> Plug.Conn.put_private(:samly_idp, Samly.Helper.get_idp("idp1"))
        |> Samly.SPHandler.consume_signin_response()

      assert conn.status == expected_status
    end
  end

  test "signed logout responses must match the stored logout request", %{port: port} do
    alias Samly.Esaml

    require Esaml

    {:ok, key} = Key.load_private_key("test/data/test.pem")
    {:ok, cert} = Key.load_certificate("test/data/test.crt")
    signing_sp = Esaml.esaml_sp(entity_id: ~c"urn:test:idp", key: key, certificate: cert, sp_sign_requests: true)

    for {response_to, expected} <- [{"_logout_pending", 302}, {"_wrong", 403}, {nil, 403}] do
      xml = Samly.SAML.Protocol.logout_response("http://127.0.0.1:#{port}/sso/sp/logout/idp1", signing_sp, :success, response_to)

      conn =
        :post
        |> Plug.Test.conn("/sso/sp/logout/idp1", %{"SAMLResponse" => Base.encode64(xml), "RelayState" => "state"})
        |> Plug.Test.init_test_session(%{"logout_req_id" => "_logout_pending", "relay_state" => "state", "idp_id" => "idp1", "target_url" => "/"})
        |> Plug.Conn.put_private(:samly_idp, Samly.Helper.get_idp("idp1"))
        |> Samly.SPHandler.handle_logout_response()

      assert conn.status == expected
      if expected == 302, do: assert(conn.private.plug_session_info == :drop)
    end
  end

  defp signed_response(port, response_to \\ nil) do
    {:ok, key} = Key.load_private_key("test/data/test.pem")
    {:ok, cert} = Key.load_certificate("test/data/test.crt")
    id = System.unique_integer([:positive])
    issued = DateTime.to_iso8601(DateTime.utc_now())
    expires = DateTime.to_iso8601(DateTime.shift(DateTime.utc_now(), minute: 5))
    recipient = "http://127.0.0.1:#{port}/sso/sp/consume/idp1"
    correlation = if response_to, do: ~s( InResponseTo="#{response_to}"), else: ""

    assertion = """
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a#{id}" Version="2.0" IssueInstant="#{issued}"><saml:Issuer>urn:test:idp</saml:Issuer><saml:Subject><saml:NameID>person@example.test</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="#{recipient}"#{correlation} NotOnOrAfter="#{expires}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotOnOrAfter="#{expires}"><saml:AudienceRestriction><saml:Audience>urn:test:sp1</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>
    """

    {:ok, assertion} = XMLDSig.sign(assertion, key, cert)

    response = """
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r#{id}"#{correlation} Version="2.0" IssueInstant="#{issued}" Destination="#{recipient}"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:test:idp</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>#{assertion}</samlp:Response>
    """

    {:ok, signed} = XMLDSig.sign(response, key, cert)
    signed
  end

  test "serves signed SP metadata through Bandit", %{port: port} do
    assert {:ok, {{_, 200, _}, headers, body}} = request(port, "/sso/sp/metadata/idp1")
    assert {~c"content-type", content_type} = List.keyfind(headers, ~c"content-type", 0)
    assert to_string(content_type) =~ "text/xml"
    body = to_string(body)
    assert body =~ "EntityDescriptor"
    assert body =~ "SignatureValue"
  end

  test "rejects an external target URL at the HTTP boundary", %{port: port} do
    path = "/sso/auth/signin/idp1?target_url=https%3A%2F%2Fevil.example"
    assert {:ok, {{_, 400, _}, _headers, ~c"invalid target_url"}} = request(port, path)
  end

  defp request(port, path) do
    :httpc.request(:get, {~c"http://127.0.0.1:#{port}#{path}", []}, [], body_format: :string)
  end
end
