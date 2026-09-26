defmodule Samly.Router do
  @moduledoc false

  use Plug.Router

  plug :secure_samly
  plug :match
  plug :dispatch

  forward("/auth", to: Samly.AuthRouter)
  forward("/sp", to: Samly.SPRouter)
  forward("/csp-report", to: Samly.CsprRouter)

  match _ do
    send_resp(conn, 404, "not_found")
  end

  defp secure_samly(conn, _opts) do
    conn
    |> put_private(:samly_nonce, 18 |> :crypto.strong_rand_bytes() |> Base.encode64())
    |> register_before_send(fn connection ->
      nonce = connection.private[:samly_nonce]

      connection
      |> put_resp_header("cache-control", "no-cache, no-store, must-revalidate")
      |> put_resp_header("pragma", "no-cache")
      |> put_resp_header("x-frame-options", "SAMEORIGIN")
      |> put_resp_header("content-security-policy", content_security_policy(connection, nonce))
      |> put_resp_header("x-content-type-options", "nosniff")
      |> put_resp_header("referrer-policy", "no-referrer")
    end)
  end

  defp content_security_policy(conn, nonce) do
    form_origins =
      case conn.private[:samly_idp] do
        %Samly.IdpData{} = idp ->
          [idp.sso_redirect_url, idp.sso_post_url, idp.slo_redirect_url, idp.slo_post_url]
          |> Enum.flat_map(&origin/1)
          |> Enum.uniq()
          |> Enum.join(" ")

        _ ->
          ""
      end

    "default-src 'none'; script-src 'nonce-#{nonce}'; form-action 'self' #{form_origins}; " <>
      "frame-ancestors 'self'; base-uri 'none'; object-src 'none'; report-uri /sso/csp-report;"
  end

  defp origin(nil), do: []

  defp origin(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host, port: port}
      when scheme in ["http", "https"] and is_binary(host) ->
        default_port = if scheme == "https", do: 443, else: 80
        suffix = if port in [nil, default_port], do: "", else: ":#{port}"
        ["#{scheme}://#{host}#{suffix}"]

      _ ->
        []
    end
  end
end
