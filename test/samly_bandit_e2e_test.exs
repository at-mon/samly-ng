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

  defp not_found(%{request_path: "/protected"} = conn, _opts) do
    conn = Plug.Conn.fetch_session(conn)

    case Samly.get_active_assertion(conn) do
      nil -> Plug.Conn.send_resp(conn, 401, "unauthenticated")
      assertion -> Plug.Conn.send_resp(conn, 200, assertion.attributes["role"] || "authenticated")
    end
  end

  defp not_found(conn, _opts), do: Plug.Conn.send_resp(conn, 404, "not_found")
end

defmodule Samly.BanditE2ETest do
  use ExUnit.Case, async: false

  alias Samly.SAML.Key
  alias Samly.State.ETS
  alias Samly.Test.SAMLFixture

  setup context do
    server = start_supervised!({Bandit, plug: Samly.BanditEndpoint, port: 0, ip: {127, 0, 0, 1}})
    {:ok, {_address, port}} = ThousandIsland.listener_info(server)

    previous = Application.get_env(:samly, Samly.Provider)
    previous_runtime = Map.new([:identity_providers, :service_providers, :state_store], &{&1, Application.fetch_env(:samly, &1)})
    Samly.State.init(Map.get(context, :store, Samly.State.Session))
    {:ok, certificate} = Key.load_certificate("test/data/test.crt")

    metadata = """
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="urn:test:idp"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>#{Base.encode64(certificate)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/sso"/><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/logout"/></md:IDPSSODescriptor></md:EntityDescriptor>
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
          allow_idp_initiated_flow: true,
          signed_envelopes_in_resp: Map.get(context, :signed_envelopes, true),
          on_logout: logout_callback(context)
        }
      ]
    )

    {:ok, _state} = Samly.Provider.refresh_providers()
    :inets.start()

    on_exit(fn ->
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

  @tag store: ETS
  test "separate browser logins for the same subject cannot replace each other's claims", %{port: port} do
    first = SAMLFixture.response("http://127.0.0.1:#{port}/sso/sp/consume/idp1", role: "member")
    second = SAMLFixture.response("http://127.0.0.1:#{port}/sso/sp/consume/idp1", role: "admin")
    assert {:ok, {{_, 302, _}, headers, _}} = post_response(port, first, "/")
    cookie = headers |> List.keyfind(~c"set-cookie", 0) |> elem(1) |> to_string() |> String.split(";") |> hd()
    assert {:ok, {{_, 200, _}, _, ~c"member"}} = cookie_request(port, cookie)
    assert {:ok, {{_, 302, _}, _, _}} = post_response(port, second, "/")
    assert {:ok, {{_, 200, _}, _, ~c"member"}} = cookie_request(port, cookie)
  end

  @tag store: ETS
  test "an old cookie stays revoked after IdP logout and a fresh login", %{port: port} do
    xml = SAMLFixture.response("http://127.0.0.1:#{port}/sso/sp/consume/idp1", session_index: "revoked-index")
    assert {:ok, {{_, 302, _}, headers, _}} = post_response(port, xml, "/")
    cookie = response_cookie(headers)
    assert {:ok, {{_, 200, _}, _, _}} = cookie_request(port, cookie)

    assert {:ok, {{_, 200, _}, _, _}} = post_logout(port, "revoked-index")
    assert {:ok, {{_, 401, _}, _, _}} = cookie_request(port, cookie)
    assert {:ok, {{_, 302, _}, _, _}} = post_response(port, signed_response(port), "/")
    assert {:ok, {{_, 401, _}, _, _}} = cookie_request(port, cookie)
  end

  @tag store: ETS
  test "cookie-less IdP logout only revokes sessions matching its index", %{port: port} do
    cookies =
      for index <- ["first-index", "second-index"] do
        xml = SAMLFixture.response("http://127.0.0.1:#{port}/sso/sp/consume/idp1", session_index: index)
        assert {:ok, {{_, 302, _}, headers, _}} = post_response(port, xml, "/")
        response_cookie(headers)
      end

    assert {:ok, {{_, 200, _}, _, _}} = post_logout(port, "first-index")
    assert {:ok, {{_, 401, _}, _, _}} = cookie_request(port, Enum.at(cookies, 0))
    assert {:ok, {{_, 200, _}, _, _}} = cookie_request(port, Enum.at(cookies, 1))
  end

  test "SP initiated login traverses HTTP CSRF, request correlation and session renewal", %{port: port} do
    assert {:ok, {{_, 200, _}, headers, body}} = request(port, "/sso/auth/signin/idp1")
    cookie = response_cookie(headers)
    [_, csrf] = Regex.run(~r/name="_csrf_token" value="([^"]+)"/, to_string(body))
    assert {:ok, {{_, 200, _}, headers, body}} = post_form(port, "/sso/auth/signin/idp1", %{"_csrf_token" => csrf}, cookie)
    cookie = response_cookie(headers)
    [_, encoded] = Regex.run(~r/name="SAMLRequest" value="([^"]+)"/, to_string(body))
    [_, relay] = Regex.run(~r/name="RelayState" value="([^"]+)"/, to_string(body))
    {:ok, request_id} = encoded |> Base.decode64!() |> Samly.SAML.Protocol.message_id()
    response = signed_response(port, request_id)
    assert {:ok, {{_, 302, _}, headers, _}} = post_form(port, "/sso/sp/consume/idp1", %{"SAMLResponse" => Base.encode64(response), "RelayState" => relay}, cookie)
    assert {:ok, {{_, 200, _}, _, _}} = cookie_request(port, response_cookie(headers))
    assert {:ok, {{_, 401, _}, _, _}} = cookie_request(port, cookie)
  end

  @tag store: ETS
  test "local logout revokes before the IdP roundtrip and validates its response", %{port: port} do
    alias Samly.Esaml

    require Esaml

    assert {:ok, {{_, 302, _}, headers, _}} = post_response(port, signed_response(port), "/")
    original_cookie = response_cookie(headers)
    assert {:ok, {{_, 200, _}, headers, body}} = get_with_cookie(port, "/sso/auth/signout/idp1", original_cookie)
    cookie = response_cookie(headers)
    [_, csrf] = Regex.run(~r/name="_csrf_token" value="([^"]+)"/, to_string(body))
    assert {:ok, {{_, 200, _}, headers, body}} = post_form(port, "/sso/auth/signout/idp1", %{"_csrf_token" => csrf}, cookie)
    cookie = response_cookie(headers)
    [_, request] = Regex.run(~r/name="SAMLRequest" value="([^"]+)"/, to_string(body))
    [_, relay] = Regex.run(~r/name="RelayState" value="([^"]+)"/, to_string(body))
    {:ok, request_id} = request |> Base.decode64!() |> Samly.SAML.Protocol.message_id()
    assert {:ok, {{_, 401, _}, _, _}} = cookie_request(port, original_cookie)
    {:ok, key} = Key.load_private_key("test/data/test.pem")
    {:ok, cert} = Key.load_certificate("test/data/test.crt")
    sp = Esaml.esaml_sp(entity_id: ~c"urn:test:idp", key: key, certificate: cert, sp_sign_requests: true)
    response = Samly.SAML.Protocol.logout_response("http://127.0.0.1:#{port}/sso/sp/logout/idp1", sp, :success, request_id)
    assert {:ok, {{_, 302, _}, _, _}} = post_form(port, "/sso/sp/logout/idp1", %{"SAMLResponse" => Base.encode64(response), "RelayState" => relay}, cookie)
  end

  @tag store: ETS
  test "Redirect logout uses verified raw parameters and default DEFLATE binding", %{port: port} do
    alias Samly.Esaml

    require Esaml

    {:ok, key} = Key.load_private_key("test/data/test.pem")
    sp = Esaml.esaml_sp(entity_id: ~c"urn:test:idp")
    subject = Samly.Subject.to_rec(%Samly.Subject{name: "person@example.test"})
    xml = SAMLFixture.response("http://127.0.0.1:#{port}/sso/sp/consume/idp1", session_index: "redirect-index")
    assert {:ok, {{_, 302, _}, headers, _}} = post_response(port, xml, "/")
    cookie = response_cookie(headers)
    destination = "http://127.0.0.1:#{port}/sso/sp/logout/idp1"
    logout = Samly.SAML.Protocol.logout_request(destination, sp, subject, "redirect-index")
    query = destination |> Samly.SAML.Binding.redirect_url(logout, "state+value", signing_key: key) |> URI.parse() |> Map.fetch!(:query)
    query = query |> String.split("&") |> Enum.reject(&String.starts_with?(&1, "SAMLEncoding=")) |> Enum.join("&")
    assert {:ok, {{_, 200, _}, _, _}} = request(port, "/sso/sp/logout/idp1?" <> query)
    assert {:ok, {{_, 401, _}, _, _}} = cookie_request(port, cookie)
    assert {:ok, {{_, 403, _}, _, _}} = request(port, "/sso/sp/logout/idp1?" <> query)
  end

  test "malformed parameter shapes fail closed without diagnostic crashes", %{port: port} do
    for params <- [
          %{"SAMLResponse" => ["nested"]},
          %{"SAMLResponse" => "bad", "RelayState" => %{"x" => "nested"}},
          %{"SAMLResponse" => "bad", "SAMLRequest" => "other"},
          %{"SAMLResponse" => "bad", "SAMLEncoding" => "unsupported"}
        ] do
      assert {:ok, {{_, 403, _}, _, _}} = post_form(port, "/sso/sp/consume/idp1", params)
    end
  end

  defp get_with_cookie(port, path, cookie) do
    :httpc.request(:get, {~c"http://127.0.0.1:#{port}#{path}", [{~c"cookie", to_charlist(cookie)}]}, [autoredirect: false], body_format: :string)
  end

  @tag store: ETS, failing_logout_callback: true
  test "logout callback failures do not undo authoritative revocation or leak exception text", %{port: port} do
    xml = SAMLFixture.response("http://127.0.0.1:#{port}/sso/sp/consume/idp1", session_index: "callback-index")
    assert {:ok, {{_, 302, _}, headers, _}} = post_response(port, xml, "/")
    cookie = response_cookie(headers)

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:ok, {{_, 200, _}, _, _}} = post_logout(port, "callback-index")
      end)

    assert log =~ "on_logout callback failed"
    refute log =~ "callback-secret"
    assert {:ok, {{_, 401, _}, _, _}} = cookie_request(port, cookie)
  end

  defp logout_callback(%{failing_logout_callback: true}), do: fn _, _ -> raise "callback-secret" end
  defp logout_callback(_context), do: nil

  defp post_logout(port, index) do
    alias Samly.Esaml

    require Esaml

    {:ok, key} = Key.load_private_key("test/data/test.pem")
    {:ok, cert} = Key.load_certificate("test/data/test.crt")
    sp = Esaml.esaml_sp(entity_id: ~c"urn:test:idp", key: key, certificate: cert, sp_sign_requests: true)
    subject = Samly.Subject.to_rec(%Samly.Subject{name: "person@example.test"})
    xml = Samly.SAML.Protocol.logout_request("http://127.0.0.1:#{port}/sso/sp/logout/idp1", sp, subject, index)
    post_form(port, "/sso/sp/logout/idp1", %{"SAMLRequest" => Base.encode64(xml)})
  end

  defp response_cookie(headers) do
    headers |> List.keyfind(~c"set-cookie", 0) |> elem(1) |> to_string() |> String.split(";") |> hd()
  end

  defp post_form(port, path, params, cookie \\ nil) do
    headers = if cookie, do: [{~c"cookie", to_charlist(cookie)}], else: []
    :httpc.request(:post, {~c"http://127.0.0.1:#{port}#{path}", headers, ~c"application/x-www-form-urlencoded", Plug.Conn.Query.encode(params)}, [autoredirect: false], body_format: :string)
  end

  test "signed assertions without authentication statements are rejected", %{port: port} do
    xml =
      SAMLFixture.response("http://127.0.0.1:#{port}/sso/sp/consume/idp1",
        transform: &Regex.replace(~r/<saml:AuthnStatement.*?<\/saml:AuthnStatement>/s, &1, "")
      )

    assert {:ok, {{_, 403, _}, _, _}} = post_response(port, xml, "/")
  end

  test "unknown mandatory assertion conditions are rejected", %{port: port} do
    xml =
      SAMLFixture.response("http://127.0.0.1:#{port}/sso/sp/consume/idp1",
        transform: &String.replace(&1, "</saml:Conditions>", ~s(<saml:Condition xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="unrecognized"/></saml:Conditions>))
      )

    assert {:ok, {{_, 403, _}, _, _}} = post_response(port, xml, "/")
  end

  @tag signed_envelopes: false
  test "rejected assertion replays do not consume new unsigned response identifiers", %{port: port} do
    xml = SAMLFixture.response("http://127.0.0.1:#{port}/sso/sp/consume/idp1", sign_envelope: false)
    assert {:ok, {{_, 302, _}, _, _}} = post_response(port, xml, "/")
    {table, _limit} = :sys.get_state(Samly.ReplayCache.ETS)
    before_size = :ets.info(table, :size)

    for index <- 1..3 do
      replay = Regex.replace(~r/ID="_r[0-9]+"/, xml, ~s(ID="_mutated_#{index}"))
      assert {:ok, {{_, 403, _}, _, _}} = post_response(port, replay, "/")
    end

    assert :ets.info(table, :size) == before_size
  end

  defp cookie_request(port, cookie) do
    :httpc.request(:get, {~c"http://127.0.0.1:#{port}/protected", [{~c"cookie", to_charlist(cookie)}]}, [autoredirect: false], body_format: :string)
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
    SAMLFixture.response("http://127.0.0.1:#{port}/sso/sp/consume/idp1", response_to: response_to)
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
