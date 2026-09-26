defmodule Samly.SPHandler do
  @moduledoc false

  import Plug.Conn
  import Samly.RouterUtil, only: [ensure_sp_uris_set: 2, send_saml_request: 6, redirect: 3]

  alias Plug.Conn
  alias Samly.Assertion
  alias Samly.Esaml
  alias Samly.Helper
  alias Samly.IdpData
  alias Samly.SAML.RedirectSignature
  alias Samly.State
  alias Samly.Subject

  require Esaml
  require Logger

  # XMLBuilder escapes metadata; the response is XML, not HTML.
  # sobelow_skip ["XSS.SendResp"]
  def send_metadata(conn) do
    %IdpData{} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: _idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)
    metadata = Helper.sp_metadata(sp)

    conn
    |> put_resp_header("content-type", "text/xml")
    |> send_resp(200, metadata)

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  def consume_signin_response(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:samly_idp]
    %IdpData{pre_session_create_pipeline: pipeline, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_response = conn.body_params["SAMLResponse"]
    relay_state = safe_decode_www_form(conn.body_params["RelayState"])

    with {:ok, %Assertion{} = assertion} <-
           Helper.decode_idp_auth_resp(sp, saml_encoding, saml_response),
         :ok <- validate_authresp(conn, assertion, relay_state),
         assertion = %{assertion | idp_id: idp_id},
         conn = put_private(conn, :samly_assertion, assertion),
         {:halted, %Conn{halted: false} = conn} <- {:halted, pipethrough(conn, pipeline)} do
      updated_assertion = conn.private[:samly_assertion]
      computed = updated_assertion.computed
      assertion = %{assertion | computed: computed, idp_id: idp_id}

      nameid = assertion.subject.name
      assertion_key = {idp_id, nameid}
      conn = State.put_assertion(conn, assertion_key, assertion)
      target_url = auth_target_url(conn, assertion, relay_state)

      conn
      |> configure_session(renew: true)
      |> put_session("samly_assertion_key", assertion_key)
      |> delete_session("relay_state")
      |> delete_session("idp_id")
      |> delete_session("target_url")
      |> delete_session("req_id")
      |> redirect(302, target_url)
    else
      {:halted, conn} ->
        conn

      {:error, reason} ->
        Logger.warning("[Samly] SAML response rejected for #{idp.id}: #{inspect(reason)}")
        send_resp(conn, 403, "access_denied")

      _ ->
        send_resp(conn, 403, "access_denied")
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  # IDP-initiated flow auth response
  @spec validate_authresp(Conn.t(), Assertion.t(), binary) :: :ok | {:error, atom}
  defp validate_authresp(conn, %{subject: %{in_response_to: ""}}, relay_state) do
    idp_data = conn.private[:samly_idp]

    cond do
      not idp_data.allow_idp_initiated_flow -> {:error, :idp_first_flow_not_allowed}
      get_session(conn, "req_id") != nil -> {:error, :unexpected_idp_initiated_response}
      relay_state == "" -> :ok
      Samly.RouterUtil.valid_target_url?(relay_state, idp_data) -> :ok
      true -> {:error, :invalid_target_url}
    end
  end

  # SP-initiated flow auth response
  defp validate_authresp(conn, %{subject: %{in_response_to: in_response_to}}, relay_state) do
    %IdpData{id: idp_id} = conn.private[:samly_idp]
    rs_in_session = get_session(conn, "relay_state")
    idp_id_in_session = get_session(conn, "idp_id")
    url_in_session = get_session(conn, "target_url")
    request_id_in_session = get_session(conn, "req_id")

    cond do
      not secure_equal?(rs_in_session, relay_state) ->
        {:error, :invalid_relay_state}

      idp_id_in_session == nil || idp_id_in_session != idp_id ->
        {:error, :invalid_idp_id}

      url_in_session == nil ->
        {:error, :invalid_target_url}

      request_id_in_session == nil || request_id_in_session != in_response_to ->
        {:error, :invalid_in_response_to}

      true ->
        :ok
    end
  end

  defp pipethrough(conn, nil), do: conn

  defp pipethrough(conn, pipeline) do
    pipeline.call(conn, [])
  end

  defp auth_target_url(_conn, %{subject: %{in_response_to: ""}}, ""), do: "/"
  defp auth_target_url(_conn, %{subject: %{in_response_to: ""}}, url), do: url

  defp auth_target_url(conn, _assertion, _relay_state) do
    get_session(conn, "target_url") || "/"
  end

  def handle_logout_response(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: _idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    params = request_params(conn)
    saml_encoding = params["SAMLEncoding"]
    saml_response = params["SAMLResponse"]
    relay_state = safe_decode_www_form(params["RelayState"])

    with :ok <- verify_redirect_signature(conn, idp, "SAMLResponse"),
         {:ok, payload} <-
           Helper.decode_idp_signout_resp(logout_decode_sp(conn, sp), saml_encoding, saml_response),
         true <- secure_equal?(Esaml.esaml_logoutresp(payload, :in_response_to), get_session(conn, "logout_req_id")),
         ^relay_state when relay_state != nil <- get_session(conn, "relay_state"),
         ^idp_id <- get_session(conn, "idp_id"),
         target_url when target_url != nil <- get_session(conn, "target_url") do
      case pipethrough(configure_session(conn, drop: true), idp.post_session_cleanup_pipeline) do
        %Conn{halted: true} = halted_conn ->
          halted_conn

        pipeline_conn ->
          pipeline_conn
          |> configure_session(drop: true)
          |> redirect(302, target_url)
      end
    else
      _error ->
        Logger.warning("[Samly] Logout response rejected")
        send_resp(conn, 403, "invalid_request")
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  # non-ui logout request from IDP
  def handle_logout_request(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    params = request_params(conn)
    saml_encoding = params["SAMLEncoding"]
    saml_request = params["SAMLRequest"]
    relay_state = safe_decode_www_form(params["RelayState"])

    with :ok <- verify_redirect_signature(conn, idp, "SAMLRequest"),
         {:ok, payload} <-
           Helper.decode_idp_signout_req(logout_decode_sp(conn, sp), saml_encoding, saml_request) do
      Esaml.esaml_logoutreq(name: nameid, issuer: _issuer, id: request_id) = payload
      nameid = to_string(nameid)
      assertion_key = {idp_id, nameid}

      {conn, return_status} =
        case State.get_assertion(conn, assertion_key) do
          %Assertion{idp_id: ^idp_id, subject: %Subject{name: ^nameid}} = assertion ->
            if matching_logout_session?(payload, assertion) do
              run_logout_callback(idp.on_logout, idp_id, assertion)
              conn = State.delete_assertion(conn, assertion_key)
              {conn, :success}
            else
              {conn, :denied}
            end

          _ ->
            {conn, :denied}
        end

      {idp_signout_url, resp_xml_frag} = Helper.gen_idp_signout_resp(sp, idp_rec, return_status, request_id)
      conn = cleanup_logout_conn(conn, assertion_key, idp.post_session_cleanup_pipeline, return_status)

      if conn.halted do
        conn
      else
        send_saml_request(conn, idp_signout_url, idp.use_redirect_for_req, resp_xml_frag, relay_state, sp)
      end
    else
      _error ->
        Logger.warning("[Samly] Logout request rejected")
        send_resp(conn, 403, "invalid_request")
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  defp matching_logout_session?(payload, assertion) do
    requested = payload |> Esaml.esaml_logoutreq(:session_index) |> to_string()
    requested == "" or requested == Map.get(assertion.authn, "session_index")
  end

  defp cleanup_logout_conn(conn, assertion_key, pipeline, :success) do
    if get_session(conn, "samly_assertion_key") == assertion_key, do: conn |> configure_session(drop: true) |> pipethrough(pipeline), else: conn
  end

  defp cleanup_logout_conn(conn, _key, _pipeline, _status), do: conn

  defp safe_decode_www_form(nil), do: ""
  # Plug has already form-decoded values; decoding again changes signed RelayState.
  defp safe_decode_www_form(data) when is_binary(data), do: data
  defp safe_decode_www_form(_data), do: nil

  defp secure_equal?(left, right) when is_binary(left) and is_binary(right), do: Plug.Crypto.secure_compare(left, right)

  defp secure_equal?(_left, _right), do: false

  defp request_params(%Conn{method: "GET", params: params}), do: params
  defp request_params(%Conn{body_params: params}), do: params

  defp verify_redirect_signature(%Conn{method: "GET", query_string: query}, idp, type) do
    RedirectSignature.verify(query, type, idp.certs, allow_legacy_sha1: idp.allow_legacy_sha1)
  end

  defp verify_redirect_signature(_conn, _idp, _type), do: :ok

  defp logout_decode_sp(%Conn{method: "GET"}, sp) do
    Esaml.esaml_sp(sp, idp_signs_logout_requests: false)
  end

  defp logout_decode_sp(_conn, sp), do: Esaml.esaml_sp(sp, idp_signs_logout_requests: true)

  defp run_logout_callback(nil, _idp_id, _assertion), do: :ok

  defp run_logout_callback(callback, idp_id, assertion) do
    callback.(idp_id, assertion)
    :ok
  rescue
    _error ->
      Logger.error("[Samly] on_logout callback failed")
      :ok
  end
end
