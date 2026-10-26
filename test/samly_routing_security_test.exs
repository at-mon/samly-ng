defmodule Samly.RoutingSecurityEndpoint do
  use Plug.Builder

  plug :session_secret
  plug Plug.Parsers, parsers: [:urlencoded], pass: [], length: 32_768
  plug Plug.Session, store: :cookie, key: "_routing_security", signing_salt: "routing-security"
  plug Samly.Plug
  plug :host_application

  defp session_secret(conn, _opts), do: %{conn | secret_key_base: String.duplicate("routing-security-secret-", 4)}
  defp host_application(conn, _opts), do: Plug.Conn.send_resp(conn, 200, "host_application")
end

defmodule Samly.RoutingSecurityTest do
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Samly.Esaml
  alias Samly.IdpData
  alias Samly.RouterUtil

  require Esaml

  @moduletag capture_log: true

  setup do
    keys = [:identity_providers, :idp_id_from, :config_provider, :external_base_url, :trusted_hosts]
    previous = Map.new(keys, &{&1, Application.fetch_env(:samly, &1)})
    Enum.each(keys, &Application.delete_env(:samly, &1))
    Application.put_env(:samly, :idp_id_from, :path_segment)

    on_exit(fn ->
      for {key, value} <- previous do
        case value do
          {:ok, value} -> Application.put_env(:samly, key, value)
          :error -> Application.delete_env(:samly, key)
        end
      end
    end)

    %{idp: idp()}
  end

  describe "SP URI trust boundary" do
    test "an absolute SP configuration is unchanged by untrusted Host and forwarded headers", %{idp: idp} do
      sp = idp.esaml_sp_rec

      conn =
        :get
        |> conn("http://attacker.example/sso/sp/metadata/idp1")
        |> put_req_header("x-forwarded-host", "attacker.example")
        |> put_req_header("x-forwarded-proto", "http")
        |> put_private(:samly_idp, idp)

      Application.put_env(:samly, :external_base_url, "https://other.example/sso")
      assert RouterUtil.ensure_sp_uris_set(sp, conn) == sp
    end

    test "a configured HTTPS external base overrides the request origin", %{idp: idp} do
      Application.put_env(:samly, :external_base_url, "https://public.example:8443/login/")
      result = RouterUtil.ensure_sp_uris_set(relative_sp(), routing_conn(idp, "http://attacker.example/sso"))
      assert Esaml.esaml_sp(result, :metadata_uri) == ~c"https://public.example:8443/login/sp/metadata/idp1"
      assert Esaml.esaml_sp(result, :consume_uri) == ~c"https://public.example:8443/login/sp/consume/idp1"
      assert Esaml.esaml_sp(result, :logout_uri) == ~c"https://public.example:8443/login/sp/logout/idp1"
    end

    test "trusted-host fallback is exact and does not read forwarded hosts", %{idp: idp} do
      Application.put_env(:samly, :trusted_hosts, ["public.example"])
      conn = idp |> routing_conn("https://public.example:8443/tenant") |> put_req_header("x-forwarded-host", "attacker.example")
      result = RouterUtil.ensure_sp_uris_set(relative_sp(), conn)
      assert Esaml.esaml_sp(result, :metadata_uri) == ~c"https://public.example:8443/sso/sp/metadata/idp1"

      for host <- ["public.example.attacker.test", "other.public.example", "attacker.example"] do
        assert_raise ArgumentError, fn ->
          RouterUtil.ensure_sp_uris_set(relative_sp(), routing_conn(idp, "https://#{host}/sso"))
        end
      end
    end

    test "relative metadata without a trusted base or host fails closed", %{idp: idp} do
      assert_raise ArgumentError, fn ->
        RouterUtil.ensure_sp_uris_set(relative_sp(), routing_conn(idp, "https://public.example/sso"))
      end
    end

    for {name, base} <- [
          {"userinfo", "https://user:password@public.example/sso"},
          {"query", "https://public.example/sso?origin=attacker"},
          {"fragment", "https://public.example/sso#fragment"},
          {"zero port", "https://public.example:0/sso"},
          {"out-of-range port", "https://public.example:65536/sso"},
          {"nonnumeric port", "https://public.example:invalid/sso"},
          {"non-HTTP scheme", "ftp://public.example/sso"},
          {"relative URL", "/sso"},
          {"malformed escape", "https://public.example/%zz"},
          {"encoded control", "https://public.example/sso%0d%0a"}
        ] do
      test "external base rejects #{name}", %{idp: idp} do
        Application.put_env(:samly, :external_base_url, unquote(base))

        assert_raise ArgumentError, fn ->
          RouterUtil.ensure_sp_uris_set(relative_sp(), routing_conn(idp, "https://public.example/sso"))
        end
      end
    end

    test "relative-base custom callback values are retained", %{idp: idp} do
      Application.put_env(:samly, :external_base_url, "https://public.example/sso")
      idp = %{idp | custom_consume_uri: ~c"https://public.example/custom/acs", custom_logout_uri: ~c"/custom/logout"}
      result = RouterUtil.ensure_sp_uris_set(relative_sp(), routing_conn(idp, "https://public.example/sso"))
      assert Esaml.esaml_sp(result, :consume_uri) == idp.custom_consume_uri
      assert Esaml.esaml_sp(result, :logout_uri) == idp.custom_logout_uri
    end

    test "absolute SP URIs retain their documented precedence over custom callbacks", %{idp: idp} do
      idp = %{idp | custom_consume_uri: ~c"https://public.example/custom/acs", custom_logout_uri: ~c"/custom/logout"}
      assert RouterUtil.ensure_sp_uris_set(idp.esaml_sp_rec, routing_conn(idp, "https://public.example/sso")) == idp.esaml_sp_rec
    end

    test "subdomain mode omits the path-segment IdP suffix", %{idp: idp} do
      Application.put_env(:samly, :idp_id_from, :subdomain)
      Application.put_env(:samly, :external_base_url, "https://idp1.public.example/sso")
      result = RouterUtil.ensure_sp_uris_set(relative_sp(), routing_conn(idp, "https://idp1.public.example/sso"))
      assert Esaml.esaml_sp(result, :consume_uri) == ~c"https://idp1.public.example/sso/sp/consume"
    end
  end

  describe "endpoint pass-through" do
    test "no configured providers leaves the connection untouched" do
      conn = conn(:get, "/application")
      assert Samly.Plug.call(conn, Samly.Plug.init([])) == conn
    end

    test "unmatched paths and prefix lookalikes stay in the host application", %{idp: idp} do
      Application.put_env(:samly, :identity_providers, %{idp.id => idp})

      for path <- ["/application", "/sso-other/auth/signin/idp1", "/ssomething", "/other/sso/auth/signin/idp1"] do
        conn = conn(:get, path)
        assert Samly.Plug.call(conn, []) == conn
      end
    end

    test "missing and pathless bases do not claim every request", %{idp: idp} do
      for base <- [nil, "https://public.example"] do
        Application.put_env(:samly, :identity_providers, %{idp.id => %{idp | base_url: base}})
        conn = conn(:get, "/application")
        assert Samly.Plug.call(conn, []) == conn
      end
    end
  end

  describe "routing over HTTP" do
    setup %{idp: idp} do
      Application.put_env(:samly, :identity_providers, %{idp.id => idp})
      server = start_supervised!({Bandit, plug: Samly.RoutingSecurityEndpoint, port: 0, ip: {127, 0, 0, 1}, startup_log: false})
      {:ok, {_address, port}} = ThousandIsland.listener_info(server)
      :inets.start()
      %{port: port}
    end

    test "served metadata uses the trusted HTTPS origin despite forged Host and forwarded headers", %{port: port, idp: idp} do
      Application.put_env(:samly, :external_base_url, "https://public.example/sso")
      Application.put_env(:samly, :identity_providers, %{idp.id => %{idp | base_url: "/sso", esaml_sp_rec: relative_sp()}})

      assert {:ok, {{_, 200, _}, _, body}} =
               request(port, "/sso/sp/metadata/idp1", [{~c"host", ~c"attacker.example"}, {~c"x-forwarded-host", ~c"second-attacker.example"}])

      xml = to_string(body)
      assert xml =~ ~s(Location="https://public.example/sso/sp/consume/idp1")
      refute xml =~ "attacker.example"
    end

    test "metadata HTTP requests fail closed when Host does not match the fallback allowlist", %{port: port, idp: idp} do
      Application.put_env(:samly, :trusted_hosts, ["public.example"])
      Application.put_env(:samly, :identity_providers, %{idp.id => %{idp | base_url: "/sso", esaml_sp_rec: relative_sp()}})
      assert {:ok, {{_, 500, _}, _, body}} = request(port, "/sso/sp/metadata/idp1", [{~c"host", ~c"attacker.example"}])
      refute to_string(body) =~ "attacker.example"
      refute to_string(body) =~ "EntityDescriptor"
    end

    test "mount paths route only at a segment boundary and unknown mounted paths are 404", %{port: port} do
      assert {:ok, {{_, 200, _}, _, ~c"host_application"}} = request(port, "/sso-other")
      assert {:ok, {{_, 404, _}, headers, ~c"not_found"}} = request(port, "/sso/unmatched")
      assert {_, ~c"no-cache, no-store, must-revalidate"} = List.keyfind(headers, ~c"cache-control", 0)
      assert {:ok, {{_, 404, _}, _, ~c"not_found"}} = request(port, "/sso")
    end

    test "a root mount routes authentication instead of dropping its first path character", %{port: port, idp: idp} do
      Application.put_env(:samly, :identity_providers, %{idp.id => %{idp | base_url: "https://public.example/"}})
      assert {:ok, {{_, 200, _}, _, body}} = request(port, "/auth/signin/idp1")
      assert to_string(body) =~ ~s(name="_csrf_token")
    end

    test "a nondefault mount serves a CSRF-bearing local initiation form", %{port: port, idp: idp} do
      Application.put_env(:samly, :identity_providers, %{idp.id => %{idp | base_url: "https://public.example/tenant/saml"}})
      assert {:ok, {{_, 200, _}, _, body}} = request(port, "/tenant/saml/auth/signin/idp1")
      assert to_string(body) =~ ~s(action="/tenant/saml/auth/signin/idp1")
      assert to_string(body) =~ ~s(name="_csrf_token")
      assert {:ok, {{_, 200, _}, _, ~c"host_application"}} = request(port, "/sso/auth/signin/idp1")
    end

    test "custom ACS and logout paths use SAML verification rather than host handlers or local CSRF", %{port: port, idp: idp} do
      idp = %{idp | custom_consume_uri: ~c"https://public.example/custom/acs", custom_logout_uri: ~c"/custom/logout"}
      Application.put_env(:samly, :identity_providers, %{idp.id => idp})
      assert {:ok, {{_, 403, _}, _, ~c"access_denied"}} = post(port, "/custom/acs", %{"SAMLResponse" => "not-base64"})
      assert {:ok, {{_, 403, _}, _, ~c"invalid_request"}} = post(port, "/custom/logout", %{})
      assert {:ok, {{_, 200, _}, _, ~c"host_application"}} = request(port, "/custom/acs-extra")
    end

    test "local sign-in and sign-out reject missing CSRF tokens before redirecting", %{port: port} do
      for action <- ["signin", "signout"] do
        assert {:ok, {{_, 403, _}, headers, _body}} = post(port, "/sso/auth/#{action}/idp1", %{})
        refute List.keyfind(headers, ~c"location", 0)
        refute List.keyfind(headers, ~c"set-cookie", 0)
      end
    end

    test "unknown and ambiguous IdP path segments reject local initiation", %{port: port} do
      for path <- ["/sso/auth/signin/unknown", "/sso/auth/signin", "/sso/auth/signin/idp1/extra"] do
        assert {:ok, {{_, 403, _}, _, ~c"invalid_request unknown IdP"}} = request(port, path)
      end
    end

    test "subdomain IdP resolution uses the request host, not forwarded headers", %{port: port} do
      Application.put_env(:samly, :idp_id_from, :subdomain)
      assert {:ok, {{_, 200, _}, _, body}} = request(port, "/sso/auth/signin", [{~c"host", ~c"idp1.public.example"}])
      assert to_string(body) =~ ~s(name="_csrf_token")

      assert {:ok, {{_, 403, _}, _, ~c"invalid_request unknown IdP"}} =
               request(port, "/sso/auth/signin", [{~c"host", ~c"unknown.public.example"}, {~c"x-forwarded-host", ~c"idp1.public.example"}])
    end

    for target <- ["/safe%0d%0aInjected", "/safe%00tail", "/%5cevil.example", "/%2fevil.example", "/safe%zz"] do
      test "local initiation rejects unsafe percent-encoded target #{target}", %{port: port} do
        path = "/sso/auth/signin/idp1?" <> URI.encode_query(%{"target_url" => unquote(target)})
        assert {:ok, {{_, 400, _}, _, ~c"invalid target_url"}} = request(port, path)
      end
    end

    test "a valid local CSRF token does not permit an unsafe POST return target", %{port: port} do
      assert {:ok, {{_, 200, _}, headers, body}} = request(port, "/sso/auth/signin/idp1")
      {_, set_cookie} = List.keyfind(headers, ~c"set-cookie", 0)
      cookie = set_cookie |> to_string() |> String.split(";", parts: 2) |> hd() |> String.to_charlist()
      [_, csrf] = Regex.run(~r/name="_csrf_token" value="([^"]+)"/, to_string(body))
      params = URI.encode_query(%{"_csrf_token" => csrf, "target_url" => "/safe%0d%0aInjected"})

      assert {:ok, {{_, 400, _}, _, ~c"invalid target_url"}} =
               :httpc.request(
                 :post,
                 {~c"http://127.0.0.1:#{port}/sso/auth/signin/idp1", [{~c"cookie", cookie}], ~c"application/x-www-form-urlencoded", params},
                 http_options(),
                 []
               )
    end

    test "safe encoded spaces and exact approved external targets remain usable", %{port: port, idp: idp} do
      allowed = "https://return.example/done?first=1&second=2"
      Application.put_env(:samly, :identity_providers, %{idp.id => %{idp | allowed_target_urls: [allowed]}})

      for target <- ["/search?q=hello%20world", "/a%20path", allowed] do
        path = "/sso/auth/signin/idp1?" <> URI.encode_query(%{"target_url" => target})
        assert {:ok, {{_, 200, _}, _, body}} = request(port, path)
        assert to_string(body) =~ Samly.HTML.escape_attribute(target)
      end

      path = "/sso/auth/signin/idp1?" <> URI.encode_query(%{"target_url" => allowed <> "&extra=1"})
      assert {:ok, {{_, 400, _}, _, ~c"invalid target_url"}} = request(port, path)
    end
  end

  defp idp do
    %IdpData{
      id: "idp1",
      base_url: "https://public.example/sso",
      valid?: true,
      esaml_sp_rec:
        Esaml.esaml_sp(
          metadata_uri: ~c"https://public.example/sso/sp/metadata/idp1",
          consume_uri: ~c"https://public.example/sso/sp/consume/idp1",
          logout_uri: ~c"https://public.example/sso/sp/logout/idp1"
        )
    }
  end

  defp relative_sp, do: Esaml.esaml_sp(metadata_uri: ~c"/sso/sp/metadata/idp1")
  defp routing_conn(idp, url), do: :get |> conn(url) |> put_private(:samly_idp, idp)

  defp request(port, path, headers \\ []) do
    :httpc.request(:get, {~c"http://127.0.0.1:#{port}#{path}", headers}, http_options(), [])
  end

  defp post(port, path, params) do
    :httpc.request(:post, {~c"http://127.0.0.1:#{port}#{path}", [], ~c"application/x-www-form-urlencoded", URI.encode_query(params)}, http_options(), [])
  end

  defp http_options, do: [autoredirect: false, timeout: 5000, connect_timeout: 2000]
end
