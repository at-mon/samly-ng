Code.require_file("support/metadata_fixture.exs", __DIR__)

defmodule Samly.MetadataEndpoint do
  use Plug.Builder

  plug :put_secret_key_base
  plug Plug.Parsers, parsers: [:urlencoded], pass: [], length: 1_500_000
  plug Plug.Session, store: :cookie, key: "_metadata_test", signing_salt: "metadata-test-salt"
  plug Samly.Plug
  plug :protected

  defp put_secret_key_base(conn, _opts), do: %{conn | secret_key_base: String.duplicate("metadata-test-secret-", 4)}

  defp protected(conn, _opts) do
    conn = Plug.Conn.fetch_session(conn)

    case Samly.get_active_assertion(conn) do
      nil -> Plug.Conn.send_resp(conn, 401, "unauthenticated")
      _ -> Plug.Conn.send_resp(conn, 200, "authenticated")
    end
  end
end

defmodule Samly.MetadataHTTPTest do
  use ExUnit.Case, async: false

  alias Samly.Test.MetadataFixture, as: Fixture
  alias Samly.Test.SAMLFixture

  setup do
    keys = [Samly.Provider, :identity_providers, :service_providers, :state_store]
    previous = Map.new(keys, &{&1, Application.fetch_env(:samly, &1)})
    Samly.State.init(Samly.State.Session)
    server = start_supervised!({Bandit, plug: Samly.MetadataEndpoint, port: 0, ip: {127, 0, 0, 1}})
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    :inets.start()

    on_exit(fn ->
      for {key, value} <- previous do
        case value do
          {:ok, value} -> Application.put_env(:samly, key, value)
          :error -> Application.delete_env(:samly, key)
        end
      end
    end)

    %{port: port}
  end

  describe "metadata trust through HTTP" do
    test "an unrelated SP key cannot authenticate as the selected IdP", %{port: port} do
      idp = Fixture.entity(Fixture.role(Fixture.key(Fixture.other_certificate())))
      sp = Fixture.entity(Fixture.role(Fixture.key(Fixture.certificate()), name: "SPSSODescriptor"), "urn:unrelated:sp")
      load_metadata(Fixture.aggregate(idp <> sp), port)

      assert {:ok, {{_, 403, _}, headers, ~c"access_denied"}} = post_response(port)
      refute List.keyfind(headers, ~c"set-cookie", 0)
    end

    test "a rollover key belonging to the selected IdP authenticates", %{port: port} do
      keys = Fixture.key(Fixture.other_certificate()) <> Fixture.key(Fixture.certificate(), nil)
      load_metadata(Fixture.entity(Fixture.role(keys)), port)

      assert {:ok, {{_, 302, _}, headers, _body}} = post_response(port)
      assert {_, cookie} = List.keyfind(headers, ~c"set-cookie", 0)
      session_cookie = cookie |> to_string() |> String.split(";", parts: 2) |> hd() |> String.to_charlist()

      assert {:ok, {{_, 200, _}, _, ~c"authenticated"}} =
               :httpc.request(:get, {~c"http://127.0.0.1:#{port}/protected", [{~c"cookie", session_cookie}]}, [autoredirect: false], [])
    end
  end

  defp load_metadata(metadata, port) do
    Application.put_env(:samly, Samly.Provider,
      service_providers: [Fixture.sp_config()],
      identity_providers: [Fixture.config(metadata, %{base_url: "http://127.0.0.1:#{port}/sso", allow_idp_initiated_flow: true})]
    )

    assert {:ok, _} = Samly.Provider.refresh_providers()
    assert Samly.Helper.get_idp("idp1").valid?
  end

  defp post_response(port) do
    recipient = "http://127.0.0.1:#{port}/sso/sp/consume/idp1"
    body = URI.encode_query(%{"SAMLResponse" => Base.encode64(SAMLFixture.response(recipient)), "RelayState" => "/protected"})
    :httpc.request(:post, {String.to_charlist(recipient), [], ~c"application/x-www-form-urlencoded", body}, [autoredirect: false], [])
  end
end
