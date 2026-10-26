defmodule Samly.LogoutCorrelationTest do
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Samly.Esaml
  alias Samly.SAML.Key
  alias Samly.SAML.Protocol
  alias Samly.SAML.XMLDSig
  alias Samly.SPHandler

  require Esaml

  setup do
    {:ok, key} = Key.load_private_key("test/data/test.pem")
    {:ok, cert} = Key.load_certificate("test/data/test.crt")

    sp =
      Esaml.esaml_sp(
        entity_id: ~c"urn:test:sp1",
        idp_entity_id: ~c"urn:test:idp",
        logout_uri: ~c"https://sp.test/logout",
        trusted_fingerprints: [{:sha256, :crypto.hash(:sha256, cert)}]
      )

    idp = %Samly.IdpData{id: "idp1", esaml_sp_rec: sp}
    issued = DateTime.to_iso8601(DateTime.utc_now())

    xml = """
    <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logout_#{Samly.State.gen_id()}" Version="2.0" IssueInstant="#{issued}" Destination="https://sp.test/logout" InResponseTo="_expected_request"><saml:Issuer>urn:test:idp</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>
    """

    {:ok, signed} = XMLDSig.sign(xml, key, cert)

    conn =
      :post
      |> conn("/logout", %{"SAMLResponse" => Base.encode64(signed), "RelayState" => "expected-relay"})
      |> put_private(:samly_idp, idp)
      |> fetch_query_params()

    session = %{"logout_req_id" => "_expected_request", "relay_state" => "expected-relay", "idp_id" => "idp1", "target_url" => "/account"}
    %{conn: conn, session: session, xml: signed, sp: sp}
  end

  describe "logout response correlation" do
    test "wrong browser does not consume replay protection before the intended browser", %{conn: conn, session: session, xml: xml, sp: sp} do
      rejected = conn |> init_test_session(%{}) |> SPHandler.handle_logout_response()
      assert rejected.status == 403

      accepted = conn |> init_test_session(session) |> SPHandler.handle_logout_response()
      assert accepted.status == 302
      assert get_resp_header(accepted, "location") == ["/account"]
      assert accepted.private.plug_session_info == :drop
      assert {:error, :replayed} = Protocol.decode_logout_response(xml, sp)
    end

    test "each invalid correlation field leaves the signed response usable", %{conn: conn, session: session} do
      for invalid <- [
            Map.put(session, "logout_req_id", "wrong-request"),
            Map.put(session, "relay_state", "wrong-relay"),
            Map.put(session, "idp_id", "wrong-idp"),
            Map.delete(session, "target_url")
          ] do
        rejected = conn |> init_test_session(invalid) |> SPHandler.handle_logout_response()
        assert rejected.status == 403
      end

      accepted = conn |> init_test_session(session) |> SPHandler.handle_logout_response()
      assert accepted.status == 302
      replayed = conn |> init_test_session(session) |> SPHandler.handle_logout_response()
      assert replayed.status == 403
    end

    test "legacy decoder still commits successful responses exactly once", %{xml: xml, sp: sp} do
      assert {:ok, _record} = Protocol.decode_logout_response(xml, sp)
      assert {:error, :replayed} = Protocol.decode_logout_response(xml, sp)
    end
  end
end
