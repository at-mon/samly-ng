defmodule Samly.AuthHandler do
  @moduledoc false

  import Plug.Conn
  import Samly.RouterUtil, only: [ensure_sp_uris_set: 2, send_saml_request: 6, redirect: 3]

  alias Samly.Assertion
  alias Samly.Helper
  alias Samly.IdpData
  alias Samly.SAML.Protocol
  alias Samly.State
  alias Samly.Subject

  require Logger

  @sso_init_resp_template """
  <!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\"
    \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">
  <html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">
    <head>
      <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"/>
    </head>
    <body>
      <script nonce=\"<%= nonce %>\">
        document.addEventListener(\"DOMContentLoaded\", function () {
          document.getElementById(\"sso-req-form\").submit();
        });
      </script>
      <noscript>
        <p><strong>Note:</strong>
          Since your browser does not support JavaScript, you must press
          the button below to proceed.
        </p>
      </noscript>
      <form id=\"sso-req-form\" method=\"post\" action=\"<%= action %>\">
        <%= if target_url do %>
        <input type=\"hidden\" name=\"target_url\" value=\"<%= target_url %>\" />
        <% end %>
        <input type=\"hidden\" name=\"_csrf_token\" value=\"<%= csrf_token %>\" />
        <noscript><input type=\"submit\" value=\"Submit\" /></noscript>
      </form>
    </body>
  </html>
  """

  # All interpolated values are escaped for double-quoted HTML attributes.
  # sobelow_skip ["XSS.SendResp"]
  def initiate_sso_req(conn) do
    import Plug.CSRFProtection, only: [get_csrf_token: 0]

    target_url = conn.private[:samly_target_url] || "/"

    opts = [
      nonce: html_escape(conn.private[:samly_nonce]),
      action: html_escape(conn.request_path),
      target_url: html_escape(target_url),
      csrf_token: html_escape(get_csrf_token())
    ]

    conn
    |> put_resp_header("content-type", "text/html")
    |> send_resp(200, EEx.eval_string(@sso_init_resp_template, opts))
  end

  defp html_escape(value) do
    value
    |> to_string()
    |> String.replace("&", "&amp;")
    |> String.replace("\"", "&quot;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
  end

  def send_signin_req(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    target_url = conn.private[:samly_target_url] || "/"
    assertion_key = get_session(conn, "samly_assertion_key")

    case State.get_assertion(conn, assertion_key) do
      %Assertion{idp_id: ^idp_id} ->
        redirect(conn, 302, target_url)

      _ ->
        relay_state = State.gen_id()

        {idp_signin_url, req_xml_frag} =
          Helper.gen_idp_signin_req(sp, idp_rec, Map.get(idp, :nameid_format), force_authn: idp.force_authn)

        {:ok, request_id} = Protocol.message_id(req_xml_frag)

        conn
        |> State.delete_assertion(assertion_key)
        |> configure_session(renew: true)
        |> put_session("relay_state", relay_state)
        |> put_session("idp_id", idp_id)
        |> put_session("req_id", request_id)
        |> put_session("target_url", target_url)
        |> send_saml_request(
          idp_signin_url,
          idp.use_redirect_for_req,
          req_xml_frag,
          relay_state,
          sp
        )
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  def send_signout_req(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    target_url = conn.private[:samly_target_url] || "/"
    assertion_key = get_session(conn, "samly_assertion_key")

    case State.get_assertion(conn, assertion_key) do
      %Assertion{idp_id: ^idp_id, authn: authn, subject: subject} = assertion ->
        run_logout_callback(idp.on_logout, idp_id, assertion)
        session_index = Map.get(authn, "session_index", "")
        subject_rec = Subject.to_rec(subject)

        {idp_signout_url, req_xml_frag} =
          Helper.gen_idp_signout_req(sp, idp_rec, subject_rec, session_index)

        {:ok, logout_request_id} = Protocol.message_id(req_xml_frag)

        conn = State.delete_assertion(conn, assertion_key)
        relay_state = State.gen_id()

        conn
        |> put_session("target_url", target_url)
        |> put_session("logout_req_id", logout_request_id)
        |> put_session("relay_state", relay_state)
        |> put_session("idp_id", idp_id)
        |> delete_session("samly_assertion_key")
        |> send_saml_request(
          idp_signout_url,
          idp.use_redirect_for_req,
          req_xml_frag,
          relay_state,
          sp
        )

      _ ->
        send_resp(conn, 403, "access_denied")
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

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
