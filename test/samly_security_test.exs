defmodule Samly.SecurityTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Samly.Esaml
  alias Samly.SAML.Binding
  alias Samly.SAML.Encryption
  alias Samly.SAML.Key
  alias Samly.SAML.Protocol
  alias Samly.SAML.RedirectSignature
  alias Samly.SAML.XML
  alias Samly.SAML.XMLDSig

  require Esaml

  describe "untrusted XML" do
    test "qualified attributes cannot impersonate unqualified security attributes" do
      assert {:ok, root} = XML.parse(~s(<Response xmlns:evil="urn:evil" evil:ID="spoof"/>))
      assert XML.attribute(root, "ID") == nil
    end

    test "rejects excessive nesting before building an XML tree" do
      xml = String.duplicate("<a>", 129) <> String.duplicate("</a>", 129)
      assert {:error, :xml_too_deep} = XML.parse(xml)
    end

    test "bounds the number of XML elements" do
      assert {:error, :xml_too_many_elements} = XML.parse("<root>" <> String.duplicate("<a/>", 10_000) <> "</root>")
    end

    test "protocol elements must use SAML namespaces and version 2.0" do
      for xml <- [~s(<Response xmlns="urn:attacker" Version="2.0"/>), ~s(<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Version="1.0"/>)] do
        assert {:error, :invalid_request} = Protocol.decode_authn_response(xml, Esaml.esaml_sp())
      end
    end

    test "rejects external entities before parsing" do
      xml = """
      <?xml version="1.0"?>
      <!DOCTYPE Response [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
      <Response>&xxe;</Response>
      """

      assert {:error, :xml_entities_not_allowed} = XML.parse(xml)
    end

    test "rejects internal entities and doctypes" do
      xml = "<!DOCTYPE Response [<!ENTITY value \"expanded\">]><Response>&value;</Response>"

      assert {:error, :xml_entities_not_allowed} = XML.parse(xml)
    end

    test "rejects documents over the configured limit" do
      xml = "<Response>#{String.duplicate("x", 64)}</Response>"

      assert {:error, :xml_too_large} = XML.parse(xml, max_bytes: 32)
    end

    test "rejects invalid UTF-8 without raising" do
      assert {:error, :invalid_xml} = XML.parse(<<255, 254, 253>>)
    end
  end

  describe "SAML bindings" do
    test "round-trips a POST payload" do
      xml = "<Response ID=\"safe\"/>"

      assert {:ok, ^xml} = xml |> Binding.encode_post() |> Binding.decode(nil)
    end

    property "round-trips arbitrary bounded POST payloads" do
      check all(payload <- binary(max_length: 2_048)) do
        assert {:ok, ^payload} = Binding.decode(nil, Binding.encode_post(payload))
      end
    end

    test "rejects malformed base64" do
      assert {:error, :invalid_base64} = Binding.decode(nil, "%%%")
    end

    test "rejects an inflated payload over the limit" do
      payload =
        "<Response>#{String.duplicate("x", 4_096)}</Response>"
        |> :zlib.zip()
        |> Base.encode64()

      assert {:error, :payload_too_large} =
               Binding.decode(Binding.deflate_encoding(), payload, max_inflated_bytes: 128)
    end
  end

  describe "XML signatures" do
    test "exclusive canonicalization matches an independent libxml2 vector" do
      # Reference output verified with xmllint --exc-c14n on this comment-free fixture.
      {:ok, root} = "test/data/c14n_namespace_context.xml" |> File.read!() |> XML.parse()

      expected =
        ~s|<a:Root xmlns:a="urn:root" ID="root"><a:Child xmlns:z="urn:last" alpha="1" beta="2" z:key="tab&#x9;line&#xA;return&#xD;&quot;">A&amp;B&lt;C&gt;D&#xD;</a:Child><Default xmlns="urn:default"><Reset xmlns=""><z:Leaf xmlns:z="urn:last"></z:Leaf></Reset></Default></a:Root>|

      assert XMLDSig.canonicalize(root) == expected
    end

    setup do
      {:ok, key} = Key.load_private_key("test/data/test.pem")
      {:ok, cert} = Key.load_certificate("test/data/test.crt")
      %{key: key, cert: cert, fingerprints: [{:sha256, :crypto.hash(:sha256, cert)}]}
    end

    test "signs and verifies a SHA-256 enveloped signature", context do
      xml = ~s(<samlp:Response xmlns:samlp="urn:test" ID="_safe"><samlp:Status/></samlp:Response>)
      assert {:ok, signed} = XMLDSig.sign(xml, context.key, context.cert)
      assert {:ok, root} = XML.parse(signed)
      assert :ok = XMLDSig.verify(root, root, context.fingerprints)
    end

    test "rejects unsupported canonicalization before cryptographic verification", context do
      {:ok, signed} = XMLDSig.sign(~s(<Response ID="_c14n"/>), context.key, context.cert)

      {:ok, root} =
        signed
        |> String.replace(
          ~s(CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"),
          ~s(CanonicalizationMethod Algorithm="urn:unsupported")
        )
        |> XML.parse()

      assert {:error, :unsupported_signature_structure} =
               XMLDSig.verify(root, root, context.fingerprints)
    end

    test "rejects tampering after signing", context do
      xml =
        ~s(<samlp:Response xmlns:samlp="urn:test" ID="_safe"><samlp:Status>ok</samlp:Status></samlp:Response>)

      assert {:ok, signed} = XMLDSig.sign(xml, context.key, context.cert)
      assert {:ok, root} = signed |> String.replace(">ok<", ">denied<") |> XML.parse()
      assert {:error, :bad_digest} = XMLDSig.verify(root, root, context.fingerprints)
    end

    test "rejects duplicate referenced IDs", context do
      xml = ~s(<samlp:Response xmlns:samlp="urn:test" ID="_safe"><samlp:Status/></samlp:Response>)
      assert {:ok, signed} = XMLDSig.sign(xml, context.key, context.cert)
      wrapped = "<Envelope ID=\"_safe\">#{signed}</Envelope>"
      assert {:ok, document} = XML.parse(wrapped)
      [response] = XML.descendants(document, "Response")

      assert {:error, :ambiguous_reference} =
               XMLDSig.verify(document, response, context.fingerprints)
    end

    test "rejects a signature in an attacker-controlled namespace", context do
      {:ok, signed} = XMLDSig.sign(~s(<Response ID="_namespace"/>), context.key, context.cert)
      {:ok, root} = signed |> String.replace("http://www.w3.org/2000/09/xmldsig#", "urn:attacker") |> XML.parse()
      assert {:error, :bad_signature} = XMLDSig.verify(root, root, context.fingerprints)
    end
  end

  test "unsigned POST logout responses are rejected" do
    xml = """
    <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_logout" Version="2.0"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>
    """

    assert {:error, :no_signature} = Protocol.decode_logout_response(xml, Esaml.esaml_sp())
  end

  test "signed logout requests are bound to issuer, destination, time and one-time use" do
    {:ok, key} = Key.load_private_key("test/data/test.pem")
    {:ok, cert} = Key.load_certificate("test/data/test.crt")
    sp = Esaml.esaml_sp(idp_entity_id: ~c"urn:test:idp", logout_uri: ~c"https://sp.example/logout", trusted_fingerprints: [{:sha256, :crypto.hash(:sha256, cert)}])
    now = DateTime.to_iso8601(DateTime.utc_now())
    stale = DateTime.to_iso8601(DateTime.shift(DateTime.utc_now(), minute: -15))

    for {issuer, destination, instant, expected} <- [
          {"urn:other", "https://sp.example/logout", now, :invalid_issuer},
          {"urn:test:idp", "https://other.example/logout", now, :invalid_logout_destination},
          {"urn:test:idp", "https://sp.example/logout", stale, :invalid_logout_time},
          {"urn:test:idp", "https://sp.example/logout", now, :ok}
        ] do
      xml = """
      <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logout_#{System.unique_integer([:positive])}" Version="2.0" IssueInstant="#{instant}" Destination="#{destination}"><saml:Issuer>#{issuer}</saml:Issuer><saml:NameID>person@example.test</saml:NameID></samlp:LogoutRequest>
      """

      {:ok, signed} = XMLDSig.sign(xml, key, cert)

      if expected == :ok do
        assert {:ok, _} = Protocol.decode_logout_request(signed, sp)
        assert {:error, :replayed} = Protocol.decode_logout_request(signed, sp)
      else
        assert {:error, ^expected} = Protocol.decode_logout_request(signed, sp)
      end
    end
  end

  describe "signed SAML responses" do
    test "validates signatures, claims, and replay", context do
      {:ok, key} = Key.load_private_key("test/data/test.pem")
      {:ok, cert} = Key.load_certificate("test/data/test.crt")
      now = DateTime.truncate(DateTime.utc_now(), :second)
      expires = now |> DateTime.shift(minute: 5) |> DateTime.to_iso8601()
      issued = DateTime.to_iso8601(now)

      assertion = """
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion_#{context.test}" Version="2.0" IssueInstant="#{issued}"><saml:Issuer>urn:test:idp</saml:Issuer><saml:Subject><saml:NameID>person@example.test</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://sp.example.test/consume" InResponseTo="_request" NotOnOrAfter="#{expires}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotOnOrAfter="#{expires}"><saml:AudienceRestriction><saml:Audience>urn:test:sp</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>person@example.test</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>
      """

      {:ok, signed_assertion} = XMLDSig.sign(assertion, key, cert)

      response = """
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response_#{context.test}" InResponseTo="_request" Version="2.0" IssueInstant="#{issued}" Destination="https://sp.example.test/consume"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:test:idp</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>#{signed_assertion}</samlp:Response>
      """

      {:ok, signed_response} = XMLDSig.sign(response, key, cert)

      sp =
        Esaml.esaml_sp(
          consume_uri: ~c"https://sp.example.test/consume",
          entity_id: ~c"urn:test:sp",
          idp_entity_id: ~c"urn:test:idp",
          trusted_fingerprints: [{:sha256, :crypto.hash(:sha256, cert)}]
        )

      assert {:ok, assertion} = Protocol.decode_authn_response(signed_response, sp)
      assert assertion.subject.name == "person@example.test"
      assert assertion.attributes["email"] == "person@example.test"
      assert {:error, :replayed} = Protocol.decode_authn_response(signed_response, sp)
    end
  end

  describe "Redirect signatures" do
    test "verifies SHA-256 and rejects duplicate query parameters" do
      {:ok, key} = Key.load_private_key("test/data/test.pem")
      cert = "test/data/test.crt" |> File.read!() |> :public_key.pem_decode() |> hd() |> elem(1)
      message = URI.encode_www_form("payload")
      relay = URI.encode_www_form("state")
      algorithm = URI.encode_www_form("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
      signed = "SAMLRequest=#{message}&RelayState=#{relay}&SigAlg=#{algorithm}"

      signature =
        signed |> :public_key.sign(:sha256, key) |> Base.encode64() |> URI.encode_www_form()

      query = signed <> "&Signature=" <> signature

      assert :ok = RedirectSignature.verify(query, "SAMLRequest", [Base.encode64(cert)])

      assert {:error, :duplicate_query_parameter} =
               RedirectSignature.verify(query <> "&RelayState=other", "SAMLRequest", [
                 Base.encode64(cert)
               ])
    end

    test "signs generated Redirect binding URLs" do
      {:ok, key} = Key.load_private_key("test/data/test.pem")
      {:ok, cert} = Key.load_certificate("test/data/test.crt")

      url =
        Binding.redirect_url("https://idp.example.test/sso", "<LogoutRequest/>", "state", signing_key: key)

      query = URI.parse(url).query
      assert :ok = RedirectSignature.verify(query, "SAMLRequest", [Base.encode64(cert)])
    end
  end

  describe "encrypted assertions" do
    test "decrypts authenticated RSA-OAEP and AES-GCM assertions" do
      {:ok, private_key} = Key.load_private_key("test/data/test.pem")
      {:ok, certificate} = Key.load_certificate("test/data/test.crt")

      public_key =
        certificate |> :public_key.pkix_decode_cert(:otp) |> elem(1) |> elem(7) |> elem(2)

      symmetric_key = :crypto.strong_rand_bytes(16)
      iv = :crypto.strong_rand_bytes(12)

      assertion =
        ~s(<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_encrypted"/>)

      {ciphertext, tag} =
        :crypto.crypto_one_time_aead(:aes_128_gcm, symmetric_key, iv, assertion, "", true)

      wrapped_key =
        :public_key.encrypt_public(symmetric_key, public_key,
          rsa_padding: :rsa_pkcs1_oaep_padding,
          rsa_oaep_md: :sha,
          rsa_mgf1_md: :sha
        )

      xml = """
      <saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedData><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><xenc:CipherData><xenc:CipherValue>#{Base.encode64(wrapped_key)}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>#{Base.encode64(iv <> ciphertext <> tag)}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>
      """

      assert {:ok, encrypted_assertion} = XML.parse(xml)
      assert {:ok, assertion_node} = Encryption.decrypt(encrypted_assertion, private_key)
      assert XML.attribute(assertion_node, "ID") == "_encrypted"
    end
  end
end
