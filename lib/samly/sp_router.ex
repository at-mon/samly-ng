defmodule Samly.SPRouter do
  @moduledoc false

  use Plug.Router

  import Plug.Conn
  import Samly.RouterUtil, only: [check_idp_id: 2]

  plug :fetch_session
  plug :match
  plug :check_idp_id
  plug :dispatch

  get "/metadata/*idp_id_seg" do
    Samly.SPHandler.send_metadata(conn)
  end

  post "/consume/*idp_id_seg" do
    Samly.SPHandler.consume_signin_response(conn)
  end

  post "/logout/*idp_id_seg" do
    cond do
      conn.params["SAMLResponse"] != nil -> Samly.SPHandler.handle_logout_response(conn)
      conn.params["SAMLRequest"] != nil -> Samly.SPHandler.handle_logout_request(conn)
      true -> send_resp(conn, 403, "invalid_request")
    end
  end

  get "/logout/*idp_id_seg" do
    cond do
      conn.params["SAMLResponse"] != nil -> Samly.SPHandler.handle_logout_response(conn)
      conn.params["SAMLRequest"] != nil -> Samly.SPHandler.handle_logout_request(conn)
      true -> send_resp(conn, 403, "invalid_request")
    end
  end

  match _ do
    send_resp(conn, 404, "not_found")
  end
end
