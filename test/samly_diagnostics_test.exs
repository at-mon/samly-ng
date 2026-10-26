defmodule Samly.DiagnosticsTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Samly.Diagnostics
  alias Samly.IdpData

  setup do
    keys = [:debug_csp_reports, :identity_providers, :debug_mode]
    previous = Map.new(keys, &{&1, Application.fetch_env(:samly, &1)})
    previous_level = Logger.level()
    Logger.configure(level: :debug)
    Enum.each(keys, &Application.delete_env(:samly, &1))

    on_exit(fn ->
      Logger.configure(level: previous_level)

      for {key, value} <- previous do
        case value do
          {:ok, value} -> Application.put_env(:samly, key, value)
          :error -> Application.delete_env(:samly, key)
        end
      end
    end)
  end

  test "ordinary Inspect never reveals credential-bearing provider fields" do
    sp = %Samly.SpData{id: "sp", key: {:private_key, "PRIVATE-KEY-SENTINEL"}}
    idp = %IdpData{id: "idp", metadata: "RAW-METADATA-SENTINEL", esaml_sp_rec: {:sp, "PRIVATE-KEY-SENTINEL"}}
    refute inspect(sp) =~ "PRIVATE-KEY-SENTINEL"
    refute inspect(idp) =~ "PRIVATE-KEY-SENTINEL"
    refute inspect(idp) =~ "RAW-METADATA-SENTINEL"
  end

  describe "raw/3" do
    test "raw diagnostics are absent by default even at debug log level" do
      assert capture_log(fn ->
               assert :ok = Diagnostics.raw(%IdpData{}, :saml_response, "private-assertion")
               assert :ok = Diagnostics.raw(nil, :request_url, "https://idp.example/?private=query")
             end) == ""
    end

    test "only an explicit true IdP flag enables raw payloads and URLs" do
      for flag <- [false, nil, "true", 1] do
        assert capture_log(fn ->
                 Diagnostics.raw(%IdpData{debug_mode: flag}, :saml_response, "private-assertion")
               end) == ""
      end

      log =
        capture_log([format: "$level $message\n"], fn ->
          assert :ok = Diagnostics.raw(%IdpData{debug_mode: true}, :saml_response, "<Assertion>alice@example.test</Assertion>")
          assert :ok = Diagnostics.raw(%IdpData{debug_mode: true}, :request_url, "https://idp.example/?raw=query")
        end)

      assert log =~ "debug"
      assert log =~ "saml_response"
      assert log =~ "<Assertion>alice@example.test</Assertion>"
      assert log =~ "https://idp.example/?raw=query"
    end

    test "missing and disabled IdPs never inherit another provider's flag" do
      Application.put_env(:samly, :identity_providers, %{"other" => %IdpData{id: "other", debug_mode: true}})
      Application.put_env(:samly, :debug_mode, true)

      assert capture_log(fn ->
               Diagnostics.raw(nil, :saml_response, "unresolved-provider-payload")
               Diagnostics.raw(%IdpData{id: "disabled"}, :saml_response, "disabled-provider-payload")
             end) == ""
    end

    test "nil payloads produce no diagnostic" do
      assert capture_log(fn -> assert :ok = Diagnostics.raw(%IdpData{debug_mode: true}, :saml_response, nil) end) == ""
    end

    test "logs only the supplied raw content, never the IdP configuration" do
      idp = %IdpData{debug_mode: true, metadata: "SECRET-CONFIG", esaml_sp_rec: {:private_key, "SECRET-KEY"}}
      log = capture_log(fn -> Diagnostics.raw(idp, :saml_response, "raw-payload") end)
      assert log =~ "raw-payload"
      refute log =~ "SECRET-CONFIG"
      refute log =~ "SECRET-KEY"
    end

    test "connection and configuration maps are not accepted as raw payloads" do
      assert capture_log(fn ->
               assert :ok = apply(Diagnostics, :raw, [%IdpData{debug_mode: true}, :saml_response, %{private_key: "SECRET-KEY"}])
             end) == ""

      assert_raise FunctionClauseError, fn ->
        apply(Diagnostics, :csp, [%{cookie_secret: "SECRET-COOKIE"}])
      end
    end

    test "an enabled IdP flag does not override the Logger level" do
      Logger.configure(level: :info)
      assert capture_log(fn -> Diagnostics.raw(%IdpData{debug_mode: true}, :saml_response, "raw-payload") end) == ""
    end

    test "bounds oversized output and marks truncation explicitly" do
      payload = "raw-start:" <> String.duplicate("x", 20_000) <> "HIDDEN-TAIL"
      log = capture_log([format: "$message"], fn -> Diagnostics.raw(%IdpData{debug_mode: true}, :saml_response, payload) end)
      assert byte_size(log) <= 8192
      assert log =~ "raw-start:"
      assert log =~ "[truncated]"
      refute log =~ "HIDDEN-TAIL"
    end

    test "invalid bytes are escaped without dropping surrounding raw content" do
      payload = <<"before:", 0xFF, 0xC0, ":雪:after">>
      log = capture_log([format: "$message"], fn -> Diagnostics.raw(%IdpData{debug_mode: true}, :saml_response, payload) end)
      assert String.valid?(log)
      assert log =~ "before:\\xFF\\xC0:雪:after"
    end

    test "truncating multibyte and invalid-byte payloads keeps valid bounded output" do
      for payload <- [String.duplicate("雪", 10_000), :binary.copy(<<0xFF>>, 10_000)] do
        log = capture_log([format: "$message"], fn -> Diagnostics.raw(%IdpData{debug_mode: true}, :saml_response, payload) end)
        assert String.valid?(log)
        assert byte_size(log) <= 8192
        assert log =~ "[truncated]"
      end
    end
  end

  describe "csp/1" do
    test "is disabled by default and requires its own exact true flag" do
      assert capture_log(fn -> assert :ok = Diagnostics.csp("private-csp-report") end) == ""

      for flag <- [false, nil, "true", 1] do
        Application.put_env(:samly, :debug_csp_reports, flag)
        assert capture_log(fn -> Diagnostics.csp("private-csp-report") end) == ""
      end

      Application.put_env(:samly, :debug_csp_reports, true)
      assert capture_log(fn -> assert :ok = Diagnostics.csp("private-csp-report") end) =~ "private-csp-report"
      assert capture_log(fn -> Diagnostics.raw(nil, :saml_response, "private-assertion") end) == ""
    end

    test "enabled CSP reports use the same bounded invalid-byte-safe formatting" do
      Application.put_env(:samly, :debug_csp_reports, true)
      payload = <<"csp-start:", 0xFF>> <> String.duplicate("x", 20_000) <> "HIDDEN-TAIL"
      log = capture_log([format: "$message"], fn -> Diagnostics.csp(payload) end)
      assert String.valid?(log)
      assert byte_size(log) <= 8192
      assert log =~ "csp-start:\\xFF"
      assert log =~ "[truncated]"
      refute log =~ "HIDDEN-TAIL"
    end
  end

  describe "configuration errors" do
    test "never include configuration data in exception messages" do
      error = Samly.ConfigError.exception(%{private_key: "SECRET-KEY", cookie_secret: "SECRET-COOKIE", metadata: "SECRET-METADATA"})
      assert Exception.message(error) == "invalid_config"
    end
  end
end

defmodule Samly.CsprRouterTestAdapter do
  @moduledoc false
  alias Plug.Adapters.Test.Conn

  def read_req_body(%{read_result: result, owner: owner}, opts) do
    send(owner, {:read_options, opts})
    result
  end

  defdelegate send_resp(state, status, headers, body), to: Conn
  defdelegate get_http_protocol(state), to: Conn
end

defmodule Samly.CsprRouterHTTPTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  setup do
    previous = Application.fetch_env(:samly, :debug_csp_reports)
    previous_level = Logger.level()
    Application.delete_env(:samly, :debug_csp_reports)
    Logger.configure(level: :debug)
    server = start_supervised!({Bandit, plug: Samly.CsprRouter, port: 0, ip: {127, 0, 0, 1}, startup_log: false})
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    :inets.start()

    on_exit(fn ->
      Logger.configure(level: previous_level)

      case previous do
        {:ok, value} -> Application.put_env(:samly, :debug_csp_reports, value)
        :error -> Application.delete_env(:samly, :debug_csp_reports)
      end
    end)

    %{port: port}
  end

  describe "CSP reports over HTTP" do
    test "POST accepts a report without logging or reflecting its content by default", %{port: port} do
      log =
        capture_log(fn ->
          assert {:ok, {{_, 200, _}, _, ~c"OK"}} = post(port, ~s({"document-uri":"https://app.example/?private-csp-value"}))
        end)

      refute log =~ "private-csp-value"
    end

    test "raw content is available only when the separate CSP flag is true", %{port: port} do
      Application.put_env(:samly, :debug_csp_reports, true)

      log =
        capture_log(fn ->
          assert {:ok, {{_, 200, _}, _, ~c"OK"}} = post(port, "explicit-debug-csp-value")
        end)

      assert log =~ "explicit-debug-csp-value"
    end

    test "non-POST methods are rejected with Allow and never log request content", %{port: port} do
      Application.put_env(:samly, :debug_csp_reports, true)

      log =
        capture_log(fn ->
          assert {:ok, {{_, 405, _}, headers, _}} =
                   :httpc.request(:get, {~c"http://127.0.0.1:#{port}/?private-query", []}, http_options(), [])

          assert {_, ~c"POST"} = List.keyfind(headers, ~c"allow", 0)
        end)

      refute log =~ "private-query"
    end

    test "oversized reports are rejected without logging the report by default", %{port: port} do
      log =
        capture_log(fn ->
          assert {:ok, {{_, 413, _}, _, ~c"report_too_large"}} = post(port, String.duplicate("private-csp-value", 10_000))
        end)

      refute log =~ "private-csp-value"
      refute log =~ "MatchError"
    end

    test "oversized debug reports log only a bounded partial body", %{port: port} do
      Application.put_env(:samly, :debug_csp_reports, true)

      log =
        capture_log([format: "$message"], fn ->
          assert {:ok, {{_, 413, _}, _, ~c"report_too_large"}} =
                   post(port, "partial-start:" <> String.duplicate("x", 100_000) <> "HIDDEN-TAIL")
        end)

      assert byte_size(log) <= 8192
      assert log =~ "partial-start:"
      assert log =~ "[truncated]"
      refute log =~ "HIDDEN-TAIL"
    end

    test "a streaming report is rejected before the client sends the entire body", %{port: port} do
      {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 2_000)
      on_exit(fn -> :gen_tcp.close(socket) end)

      assert :ok =
               :gen_tcp.send(socket, [
                 "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100000000\r\n\r\n",
                 String.duplicate("x", 20_000)
               ])

      assert {:ok, response} = :gen_tcp.recv(socket, 0, 2_000)
      assert response =~ "413"
      assert String.downcase(response) =~ "connection: close"
    end

    test "accepts a complete report at the byte limit", %{port: port} do
      assert {:ok, {{_, 200, _}, _, ~c"OK"}} = post(port, String.duplicate("x", 16_384))
    end

    test "a chunked streaming report is bounded without waiting for a terminating chunk", %{port: port} do
      {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 2_000)
      on_exit(fn -> :gen_tcp.close(socket) end)

      assert :ok =
               :gen_tcp.send(socket, [
                 "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
                 "5000\r\n",
                 String.duplicate("x", 20_480),
                 "\r\n"
               ])

      assert {:ok, response} = :gen_tcp.recv(socket, 0, 2_000)
      assert response =~ "413"
      assert String.downcase(response) =~ "connection: close"
    end
  end

  describe "adapter read failures" do
    test "returned errors are safely rejected without logging their reason" do
      Application.put_env(:samly, :debug_csp_reports, true)
      conn = Plug.Test.conn(:post, "/")
      {_, state} = conn.adapter
      conn = %{conn | adapter: {Samly.CsprRouterTestAdapter, Map.put(state, :read_result, {:error, "PRIVATE-READ-ERROR"})}}

      log =
        capture_log(fn ->
          response = Samly.CsprRouter.call(conn, Samly.CsprRouter.init([]))
          assert response.status == 400
          assert response.resp_body == "invalid_report"
        end)

      refute log =~ "PRIVATE-READ-ERROR"
      assert_receive {:read_options, opts}, 1_000
      assert opts[:length] <= 16_384
      assert opts[:read_length] <= 2048
      assert opts[:read_timeout] <= 1000
    end

    test "HTTP/2 rejections never include a hop-by-hop connection header" do
      conn = Plug.Test.conn(:post, "/")
      {_, state} = conn.adapter
      state = %{state | http_protocol: :"HTTP/2"}
      conn = %{conn | adapter: {Samly.CsprRouterTestAdapter, Map.put(state, :read_result, {:error, :timeout})}}
      response = Samly.CsprRouter.call(conn, Samly.CsprRouter.init([]))
      assert response.status == 400
      assert Plug.Conn.get_resp_header(response, "connection") == []
    end

    test "adapters returning an oversized complete body cannot bypass the limit" do
      conn = Plug.Test.conn(:post, "/")
      {_, state} = conn.adapter
      result = {:ok, String.duplicate("x", 16_385), state}
      conn = %{conn | adapter: {Samly.CsprRouterTestAdapter, Map.put(state, :read_result, result)}}
      response = Samly.CsprRouter.call(conn, Samly.CsprRouter.init([]))
      assert response.status == 413
    end
  end

  defp post(port, body) do
    :httpc.request(:post, {~c"http://127.0.0.1:#{port}/", [], ~c"application/csp-report", body}, http_options(), [])
  end

  defp http_options, do: [autoredirect: false, timeout: 5_000, connect_timeout: 2_000]
end
