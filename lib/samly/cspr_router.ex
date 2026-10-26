defmodule Samly.CsprRouter do
  @moduledoc false

  use Plug.Router

  import Plug.Conn

  alias Samly.Diagnostics

  @max_body_bytes 16_384
  @read_options [length: @max_body_bytes, read_length: 2048, read_timeout: 1000]

  plug :match
  plug :dispatch

  post _ do
    case read_body(conn, @read_options) do
      {:ok, body, conn} when byte_size(body) <= @max_body_bytes ->
        Diagnostics.csp(body)
        send_resp(conn, 200, "OK")

      {status, body, conn} when status in [:ok, :more] ->
        Diagnostics.csp(body)

        conn
        |> close_unread_request()
        |> send_resp(413, "report_too_large")

      {:error, _reason} ->
        conn
        |> close_unread_request()
        |> send_resp(400, "invalid_report")
    end
  end

  match _ do
    conn
    |> put_resp_header("allow", "POST")
    |> close_unread_request()
    |> send_resp(405, "method_not_allowed")
  end

  # HTTP/1 servers otherwise drain unread bodies to reuse the connection.
  # HTTP/2 does not permit hop-by-hop connection headers.
  defp close_unread_request(conn) do
    case get_http_protocol(conn) do
      protocol when protocol in [:"HTTP/1", :"HTTP/1.0", :"HTTP/1.1"] -> put_resp_header(conn, "connection", "close")
      _ -> conn
    end
  end
end
