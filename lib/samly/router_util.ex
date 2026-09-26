defmodule Samly.RouterUtil do
  @moduledoc false

  alias Plug.Conn
  alias Samly.Esaml
  alias Samly.Helper
  alias Samly.IdpData
  alias Samly.SAML.Binding

  require Esaml
  require Logger

  @subdomain_re ~r/^(?<subdomain>([^.]+))?\./

  def check_idp_id(%Conn{private: %{samly_idp: %IdpData{valid?: true}}} = conn, _opts), do: conn

  def check_idp_id(conn, _opts) do
    idp_id_from = Application.get_env(:samly, :idp_id_from)

    idp_id =
      if idp_id_from == :subdomain do
        case Regex.named_captures(@subdomain_re, conn.host) do
          %{"subdomain" => idp_id} -> idp_id
          _ -> nil
        end
      else
        case conn.params["idp_id_seg"] do
          [idp_id] -> idp_id
          _ -> nil
        end
      end

    provider = Application.get_env(:samly, :config_provider, Samly.ConfigProvider.Application)
    idp = idp_id && provider.get_idp(conn, idp_id)

    if match?(%IdpData{valid?: true}, idp) do
      Conn.put_private(conn, :samly_idp, idp)
    else
      conn |> Conn.send_resp(403, "invalid_request unknown IdP") |> Conn.halt()
    end
  end

  def check_target_url(conn, _opts) do
    target_url = target_url_param(conn)

    if valid_target_url?(target_url, conn.private[:samly_idp]) do
      Conn.put_private(conn, :samly_target_url, target_url)
    else
      conn |> Conn.send_resp(400, "invalid target_url") |> Conn.halt()
    end
  rescue
    ArgumentError ->
      Logger.error("[Samly] target_url must be x-www-form-urlencoded: #{inspect(conn.params["target_url"])}")

      conn |> Conn.send_resp(400, "target_url must be x-www-form-urlencoded") |> Conn.halt()
  end

  defp target_url_param(%Conn{method: "GET", query_string: query}) do
    query |> URI.decode_query() |> Map.get("target_url")
  end

  defp target_url_param(%Conn{body_params: params}) when is_map(params), do: params["target_url"]
  defp target_url_param(_conn), do: nil

  @doc false
  def valid_target_url?(nil, _idp), do: true

  def valid_target_url?(target, %IdpData{allowed_target_urls: allowed}) when is_binary(target) do
    not Regex.match?(~r/[\x00-\x20\x7f\\]/, target) and
      (safe_relative_target?(target) or target in (allowed || []))
  end

  def valid_target_url?(_target, _idp), do: false

  defp safe_relative_target?("/" <> rest = target) do
    not String.starts_with?(rest, ["/", "\\"]) and
      not String.contains?(target, ["\r", "\n", "\0"])
  end

  defp safe_relative_target?(_target), do: false

  defp trusted_base_url(conn) do
    case Application.get_env(:samly, :external_base_url) do
      base_url when is_binary(base_url) ->
        validate_external_base_url!(base_url)

      nil ->
        trusted_hosts = Application.get_env(:samly, :trusted_hosts, [])

        if conn.host in trusted_hosts do
          URI.to_string(%URI{
            scheme: Atom.to_string(conn.scheme),
            host: conn.host,
            port: conn.port,
            path: "/sso"
          })
        else
          raise ArgumentError,
                "relative Samly base URLs require :external_base_url or a matching :trusted_hosts entry"
        end
    end
  end

  defp validate_external_base_url!(base_url) do
    case URI.parse(base_url) do
      %URI{scheme: scheme, host: host} when scheme in ["http", "https"] and is_binary(host) ->
        String.trim_trailing(base_url, "/")

      _ ->
        raise ArgumentError, ":external_base_url must be an absolute HTTP or HTTPS URL"
    end
  end

  # generate URIs using the idp_id
  @spec ensure_sp_uris_set(tuple, Conn.t()) :: tuple
  def ensure_sp_uris_set(sp, conn) do
    case Esaml.esaml_sp(sp, :metadata_uri) do
      [?/ | _] ->
        base_url = trusted_base_url(conn)
        idp_id_from = Application.get_env(:samly, :idp_id_from)
        %IdpData{id: idp_id} = idp_data = conn.private[:samly_idp]

        path_segment_idp_id =
          if idp_id_from == :subdomain do
            nil
          else
            idp_id
          end

        Esaml.esaml_sp(
          sp,
          metadata_uri: Helper.get_metadata_uri(base_url, path_segment_idp_id),
          consume_uri: idp_data.custom_consume_uri || Helper.get_consume_uri(base_url, path_segment_idp_id),
          logout_uri: idp_data.custom_logout_uri || Helper.get_logout_uri(base_url, path_segment_idp_id)
        )

      _ ->
        sp
    end
  end

  def send_saml_request(conn, idp_url, use_redirect?, signed_xml_payload, relay_state) do
    send_saml_request(conn, idp_url, use_redirect?, signed_xml_payload, relay_state, nil)
  end

  # Binding.post_form HTML-escapes attributes and base64-encodes the XML payload.
  # sobelow_skip ["XSS.SendResp"]
  def send_saml_request(conn, idp_url, use_redirect?, signed_xml_payload, relay_state, sp) do
    if use_redirect? do
      key = redirect_signing_key(sp)
      url = Binding.redirect_url(idp_url, signed_xml_payload, relay_state, signing_key: key)

      redirect(conn, 302, url)
    else
      nonce = conn.private[:samly_nonce]
      resp_body = Binding.post_form(idp_url, signed_xml_payload, relay_state, nonce)

      conn
      |> Conn.put_resp_header("content-type", "text/html")
      |> Conn.send_resp(200, resp_body)
    end
  end

  defp redirect_signing_key(nil), do: nil

  defp redirect_signing_key(sp) do
    if Esaml.esaml_sp(sp, :sp_sign_requests), do: Esaml.esaml_sp(sp, :key)
  end

  def redirect(conn, status_code, dest) do
    conn
    |> Conn.put_resp_header("location", dest)
    |> Conn.send_resp(status_code, "")
    |> Conn.halt()
  end
end
