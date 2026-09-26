defmodule Samly.IngressSecurityTest do
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  test "sign-in HTML escapes request paths and preserves relative target values" do
    conn =
      :get
      |> conn("/sso/auth/signin/idp")
      |> init_test_session(%{})
      |> put_private(:samly_target_url, "/account?a=1&b=2")
      |> put_private(:samly_nonce, "nonce")

    conn = %{conn | request_path: ~s|/sso/" onmouseover="alert(1)|}
    response = Samly.AuthHandler.initiate_sso_req(conn)
    assert response.resp_body =~ ~s(value="/account?a=1&amp;b=2")
    refute response.resp_body =~ ~s(action="/sso/" onmouseover=)
    assert response.resp_body =~ "&quot;"
  end

  test "malformed metadata never activates a configured provider" do
    providers = Samly.SpData.load_providers([%{id: "sp", entity_id: "urn:sp"}])

    assert %{} ==
             Samly.IdpData.load_providers(
               [%{id: "idp", sp_id: "sp", metadata: "<broken", sign_metadata: false, sign_requests: false}],
               providers
             )
  end

  test "browser-normalized cross-origin targets are rejected at the Plug boundary" do
    for target <- ["/\t/evil.example", "/\\evil.example", "/\n/evil.example", "//evil.example"] do
      result =
        :post
        |> conn("/", %{"target_url" => target})
        |> put_private(:samly_idp, %Samly.IdpData{})
        |> Samly.RouterUtil.check_target_url([])

      assert result.status == 400
    end
  end
end
