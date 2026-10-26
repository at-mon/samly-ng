Code.require_file("support/metadata_fixture.exs", __DIR__)

defmodule Samly.MetadataSecurityTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Samly.IdpData
  alias Samly.SAML.XML
  alias Samly.Test.MetadataFixture, as: Fixture

  describe "metadata entity and role selection" do
    test "selects the IdP issuer and keys when an unrelated SP comes first" do
      unrelated = Fixture.entity(Fixture.role(Fixture.key(Fixture.other_certificate()), name: "SPSSODescriptor", endpoint: "https://sp.example/sso"), "urn:unrelated:sp")
      selected = Fixture.entity(Fixture.role(Fixture.key(Fixture.certificate())))
      idp = load(Fixture.aggregate(unrelated <> selected))

      assert idp.valid?
      assert idp.entity_id == "urn:test:idp"
      assert idp.certs == [Fixture.certificate()]
      assert idp.sso_post_url == "https://idp.example.test/sso"
    end

    test "rejects multiple SAML2 IdP entities and roles" do
      role = Fixture.role(Fixture.key(Fixture.certificate()))

      for metadata <- [Fixture.aggregate(Fixture.entity(role) <> Fixture.entity(role, "urn:other:idp")), Fixture.entity(role <> role)] do
        refute load(metadata).valid?
      end
    end

    test "does not select non-SAML2 roles or entity descriptors in extensions" do
      role = Fixture.role(Fixture.key(Fixture.certificate()))
      legacy = Fixture.role(Fixture.key(Fixture.other_certificate()), protocol: "urn:oasis:names:tc:SAML:1.1:protocol")
      assert load(Fixture.entity(legacy <> role)).certs == [Fixture.certificate()]
      refute load(Fixture.entity(legacy)).valid?
      refute load(Fixture.aggregate("<md:Extensions>#{Fixture.entity(role)}</md:Extensions>")).valid?
    end

    test "supports inherited, default and rebound namespace declarations" do
      metadata = Fixture.entity(Fixture.role(Fixture.key(Fixture.certificate())))
      default = metadata |> String.replace("md:", "") |> String.replace("xmlns:md=", "xmlns=")
      assert load(default).valid?
      assert load(Fixture.aggregate(metadata)).valid?

      for bad <- [
            String.replace(metadata, "urn:oasis:names:tc:SAML:2.0:metadata", "urn:wrong"),
            String.replace(metadata, "http://www.w3.org/2000/09/xmldsig#", "urn:wrong"),
            String.replace(metadata, "<md:IDPSSODescriptor ", "<md:IDPSSODescriptor xmlns:md=\"urn:wrong\" ")
          ] do
        refute load(bad).valid?
      end
    end

    test "trusts only direct signing and omitted-use keys in the selected role" do
      good = Fixture.key(Fixture.certificate())
      other = Fixture.key(Fixture.other_certificate())
      role = Fixture.role(good <> Fixture.key(Fixture.other_certificate(), "encryption") <> Fixture.key(Fixture.other_certificate(), "unknown") <> "<md:Extensions>#{other}</md:Extensions>")
      metadata = Fixture.entity(role <> Fixture.role(other, name: "SPSSODescriptor"))
      assert load(metadata).certs == [Fixture.certificate()]
      assert load(Fixture.entity(Fixture.role(good <> Fixture.key(Fixture.other_certificate(), nil)))).certs == [Fixture.certificate(), Fixture.other_certificate()]
    end

    test "rejects invalid base64, non-certificate bytes and missing signing certificates" do
      for keys <- [Fixture.key("%%%"), Fixture.key(Base.encode64("not a certificate")), "", Fixture.key(Fixture.certificate(), "encryption"), Fixture.key(Fixture.certificate()) <> Fixture.key("bad")] do
        refute load(Fixture.entity(Fixture.role(keys))).valid?
      end
    end

    test "rejects well-formed certificates with unsupported EC public keys" do
      certificate = Base.encode64(Fixture.ec_certificate())
      refute load(Fixture.entity(Fixture.role(Fixture.key(certificate)))).valid?
    end

    test "public metadata getters cannot union ambiguous entity keys" do
      role = Fixture.role(Fixture.key(Fixture.certificate()))
      {:ok, xml} = XML.parse(Fixture.aggregate(Fixture.entity(role) <> Fixture.entity(role, "urn:other:idp")))
      assert IdpData.get_signing_certs(xml) == []
      assert IdpData.get_entity_id(xml) == ""
      assert IdpData.get_sso_post_url(xml) == nil
    end

    test "rejects empty issuers instead of normalizing them to another identity" do
      role = Fixture.role(Fixture.key(Fixture.certificate()))

      for issuer <- ["", " ", " urn:test:idp", "urn:test:idp "] do
        refute load(Fixture.entity(role, issuer)).valid?
      end
    end

    test "rejects absent or ambiguous supported endpoints" do
      metadata = Fixture.entity(Fixture.role(Fixture.key(Fixture.certificate())))
      duplicate = ~s(<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://another.example/sso"/>)
      refute load(String.replace(metadata, "</md:IDPSSODescriptor>", duplicate <> "</md:IDPSSODescriptor>")).valid?
      refute load(String.replace(metadata, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "urn:unsupported")).valid?
    end
  end

  describe "privileged configuration validation" do
    test "rejects disabling both incoming signature requirements" do
      assert valid_config?(%{signed_assertion_in_resp: false, signed_envelopes_in_resp: true})
      assert valid_config?(%{signed_assertion_in_resp: true, signed_envelopes_in_resp: false})
      refute valid_config?(%{signed_assertion_in_resp: false, signed_envelopes_in_resp: false})
    end

    test "rejects unsafe base URLs without rejecting local HTTP or legacy nil" do
      for url <- [nil, "http://localhost:4000/sso", "https://example.test/sso", "/sso"] do
        assert valid_config?(%{base_url: url})
      end

      for url <- [
            "javascript:alert(1)",
            "//evil.test/sso",
            "https://user:secret@example.test/sso",
            "https://example.test/sso?x=y",
            "https://example.test/sso#fragment",
            "https:///sso",
            "https://example.test/\n",
            "https://example.test/%0d%0a",
            "https://example.test\\@evil.test",
            "https://example.test:99999",
            "https://example.test:invalid/",
            "https://[invalid]/",
            12
          ] do
        refute valid_config?(%{base_url: url})
      end
    end

    test "validates custom callbacks and redirect allowlists" do
      assert valid_config?(%{
               custom_consume_uri: "https://example.test/callback",
               custom_logout_uri: "/logout",
               allowed_target_urls: ["/home?q=1", "https://app.example/home?q=1", "/search?q=hello%20world", "https://app.example/a%20path"]
             })

      for url <- ["javascript:alert(1)", "//evil.test/", "https://user:secret@example.test/", "https://example.test/#fragment", "/\\evil.test", "/%2fevil.test", "/%0d%0a", 12] do
        refute valid_config?(%{custom_consume_uri: url})
        refute valid_config?(%{custom_logout_uri: url})
        refute valid_config?(%{allowed_target_urls: [url]})
      end
    end

    test "validates metadata endpoint URLs without taking unrelated endpoints" do
      for url <- ["javascript:alert(1)", "//evil.test/sso", "https://user:secret@example.test/sso", "https://example.test/sso#fragment", "/sso"] do
        refute load(Fixture.entity(Fixture.role(Fixture.key(Fixture.certificate()), endpoint: url))).valid?
      end
    end

    test "never logs configuration values or parser exception contents" do
      secret = "PRIVATE-CONFIG-SECRET"

      logs =
        capture_log(fn ->
          assert IdpData.from_config(Fixture.sp_config(), Fixture.config("<malformed", %{id: secret, base_url: %{password: secret}})) == nil
          assert IdpData.from_config(Fixture.sp_config(), Fixture.config(nil, %{metadata_file: "/#{secret}"})) == nil
        end)

      refute logs =~ secret
    end
  end

  defp load(metadata), do: IdpData.load_provider(Fixture.config(metadata), Samly.SpData.load_providers([Fixture.sp_config()]))

  defp valid_config?(overrides) do
    metadata = Fixture.entity(Fixture.role(Fixture.key(Fixture.certificate())))
    match?(%IdpData{valid?: true}, IdpData.from_config(Fixture.sp_config(), Fixture.config(metadata, overrides)))
  end
end
