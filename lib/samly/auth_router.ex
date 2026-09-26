defmodule Samly.AuthRouter do
  @moduledoc false

  use Plug.Router

  import Plug.Conn
  import Samly.RouterUtil, only: [check_idp_id: 2, check_target_url: 2]

  plug :fetch_session
  plug Plug.CSRFProtection
  plug :match
  plug :check_idp_id
  plug :check_target_url
  plug :dispatch

  get "/signin/*idp_id_seg" do
    Samly.AuthHandler.initiate_sso_req(conn)
  end

  post "/signin/*idp_id_seg" do
    Samly.AuthHandler.send_signin_req(conn)
  end

  get "/signout/*idp_id_seg" do
    Samly.AuthHandler.initiate_sso_req(conn)
  end

  post "/signout/*idp_id_seg" do
    Samly.AuthHandler.send_signout_req(conn)
  end

  match _ do
    send_resp(conn, 404, "not_found")
  end
end
