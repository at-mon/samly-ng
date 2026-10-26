defmodule Samly.ProtocolValidationTest do
  use ExUnit.Case, async: true

  alias Samly.Esaml
  alias Samly.SAML.Key
  alias Samly.SAML.Protocol
  alias Samly.Test.SAMLFixture

  require Esaml

  setup do
    {:ok, cert} = Key.load_certificate("test/data/test.crt")
    sp = Esaml.esaml_sp(consume_uri: ~c"https://sp.example/consume", entity_id: ~c"urn:test:sp1", idp_entity_id: ~c"urn:test:idp", trusted_fingerprints: [{:sha256, :crypto.hash(:sha256, cert)}])
    %{sp: sp}
  end

  describe "signed assertion claim validation" do
    test "preserves exact NameID whitespace rather than aliasing identities", %{sp: sp} do
      xml = SAMLFixture.response("https://sp.example/consume", name: " person@example.test ")
      assert {:ok, assertion} = Protocol.decode_authn_response(xml, sp)
      assert assertion.subject.name == " person@example.test "
    end

    test "rejects empty or mixed-content identity fields", %{sp: sp} do
      for name <- ["", "  ", "person<other/>@example.test"] do
        xml = SAMLFixture.response("https://sp.example/consume", name: name)
        assert {:error, _} = Protocol.decode_authn_response(xml, sp)
      end
    end

    test "rejects duplicate attributes and duplicate structural elements", %{sp: sp} do
      for transform <- [
            &String.replace(&1, "</saml:AttributeStatement>", "<saml:Attribute Name=\"role\"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>"),
            &String.replace(&1, "</saml:Subject>", "<saml:NameID>other</saml:NameID></saml:Subject>"),
            &String.replace(&1, "</saml:Issuer>", "</saml:Issuer><saml:Issuer>urn:test:idp</saml:Issuer>"),
            &String.replace(&1, "</saml:Conditions>", "</saml:Conditions><saml:Conditions/>")
          ] do
        xml = SAMLFixture.response("https://sp.example/consume", transform: transform)
        assert {:error, _} = Protocol.decode_authn_response(xml, sp)
      end
    end

    test "rejects nested audience values and conflicting confirmation identities", %{sp: sp} do
      for transform <- [
            &String.replace(&1, "<saml:Audience>urn:test:sp1</saml:Audience>", "<saml:Audience>urn:test:<saml:Audience>sp1</saml:Audience></saml:Audience>"),
            &String.replace(&1, "<saml:SubjectConfirmationData ", "<saml:NameID>another@example.test</saml:NameID><saml:SubjectConfirmationData ")
          ] do
        xml = SAMLFixture.response("https://sp.example/consume", transform: transform)
        assert {:error, _} = Protocol.decode_authn_response(xml, sp)
      end
    end

    test "rejects wrong audience, recipient and assertion issuer", %{sp: sp} do
      for {from, to} <- [{"urn:test:sp1", "urn:other:sp"}, {"https://sp.example/consume", "https://other.example/consume"}, {"urn:test:idp", "urn:other:idp"}] do
        xml = SAMLFixture.response("https://sp.example/consume", transform: &String.replace(&1, from, to))
        assert {:error, _} = Protocol.decode_authn_response(xml, sp)
      end
    end

    test "enforces expiry, not-before, and bearer constraints", %{sp: sp} do
      past = DateTime.utc_now() |> DateTime.shift(minute: -10) |> DateTime.to_iso8601()
      future = DateTime.utc_now() |> DateTime.shift(minute: 10) |> DateTime.to_iso8601()

      for transform <- [
            &Regex.replace(~r/NotOnOrAfter="[^"]+"/, &1, ~s(NotOnOrAfter="#{past}")),
            &String.replace(&1, "<saml:Conditions ", ~s(<saml:Conditions NotBefore="#{future}" )),
            &String.replace(&1, "<saml:Conditions ", ~s(<saml:Conditions NotBefore="invalid" )),
            &String.replace(&1, "<saml:SubjectConfirmationData ", ~s(<saml:SubjectConfirmationData NotBefore="#{past}" )),
            &String.replace(&1, "urn:oasis:names:tc:SAML:2.0:cm:bearer", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key")
          ] do
        xml = SAMLFixture.response("https://sp.example/consume", transform: transform)
        assert {:error, _} = Protocol.decode_authn_response(xml, sp)
      end
    end

    test "records all authenticated session indexes and earliest session expiration", %{sp: sp} do
      expiry = DateTime.utc_now() |> DateTime.shift(minute: 1) |> DateTime.to_iso8601()

      transform = fn assertion ->
        [statement] = Regex.run(~r/<saml:AuthnStatement.*?<\/saml:AuthnStatement>/s, assertion)
        extra = String.replace(statement, ~r/SessionIndex="[^"]*"/, ~s(SessionIndex="other" SessionNotOnOrAfter="#{expiry}"))
        String.replace(assertion, statement, statement <> extra)
      end

      xml = SAMLFixture.response("https://sp.example/consume", session_index: "first", transform: transform)
      assert {:ok, assertion} = Protocol.decode_authn_response(xml, sp)
      assert assertion.authn["session_indexes"] == ["first", "other"]
      assert assertion.authn["session_not_on_or_after"] == expiry
    end

    test "envelope-only signatures authenticate a contained assertion", %{sp: sp} do
      xml = SAMLFixture.response("https://sp.example/consume", sign_envelope: false)
      xml = Regex.replace(~r/<ds:Signature\b.*?<\/ds:Signature>/s, xml, "")
      {:ok, key} = Key.load_private_key("test/data/test.pem")
      {:ok, cert} = Key.load_certificate("test/data/test.crt")
      {:ok, signed} = Samly.SAML.XMLDSig.sign(xml, key, cert)
      assert {:ok, _} = Protocol.decode_authn_response(signed, Esaml.esaml_sp(sp, idp_signs_assertions: false))
      assert {:error, _} = Protocol.decode_authn_response(signed, sp)
    end

    test "replay retention covers later bearer confirmations, not only the selected one", %{sp: sp} do
      later = DateTime.utc_now() |> DateTime.shift(minute: 15) |> DateTime.to_iso8601()

      transform = fn assertion ->
        [confirmation] = Regex.run(~r/<saml:SubjectConfirmation .*?<\/saml:SubjectConfirmation>/s, assertion)
        extra = Regex.replace(~r/NotOnOrAfter="[^"]*"/, confirmation, ~s(NotOnOrAfter="#{later}"))
        assertion |> String.replace(confirmation, confirmation <> extra) |> String.replace(~r/<saml:Conditions NotOnOrAfter="[^"]*"/, ~s(<saml:Conditions NotOnOrAfter="#{later}"))
      end

      xml = SAMLFixture.response("https://sp.example/consume", transform: transform)
      assert {:ok, _, entries} = Protocol.verify_authn_response(xml, sp)
      {:ok, later_at, _} = DateTime.from_iso8601(later)
      for {_key, expiry} <- entries, do: assert(DateTime.compare(expiry, DateTime.shift(later_at, minute: 2)) != :lt)
    end

    test "plaintext cannot satisfy mandatory encryption", %{sp: sp} do
      xml = SAMLFixture.response("https://sp.example/consume")
      assert {:error, :encryption_required} = Protocol.decode_authn_response(xml, Esaml.esaml_sp(sp, encrypt_mandatory: true))
    end
  end
end
