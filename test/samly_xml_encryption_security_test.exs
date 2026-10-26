Code.require_file("support/xml_security_fixture.exs", __DIR__)

defmodule Samly.XMLEncryptionSecurityTest do
  use ExUnit.Case, async: true

  alias Samly.SAML.Encryption
  alias Samly.SAML.XML
  alias Samly.XMLSecurityFixture

  describe "encryption structure" do
    setup do
      XMLSecurityFixture.encryption()
    end

    for namespace <- ["http://www.w3.org/2001/04/xmlenc#", "http://www.w3.org/2000/09/xmldsig#", "urn:oasis:names:tc:SAML:2.0:assertion"] do
      test "rejects wrong namespace #{namespace}", %{xml: xml, key: key} do
        node = xml |> String.replace(unquote(namespace), "urn:attacker") |> XMLSecurityFixture.parse!()
        assert {:error, _} = Encryption.decrypt(node, key)
      end
    end

    test "rejects nested encrypted data", %{xml: xml, key: key} do
      node = xml |> String.replace("<xenc:EncryptedData>", "<wrapper><xenc:EncryptedData>") |> String.replace("</xenc:EncryptedData>", "</xenc:EncryptedData></wrapper>") |> XMLSecurityFixture.parse!()
      assert {:error, _} = Encryption.decrypt(node, key)
    end

    test "rejects duplicate cipher values", %{xml: xml, key: key} do
      node = xml |> String.replace("</xenc:CipherValue>", "</xenc:CipherValue><xenc:CipherValue>AAAA</xenc:CipherValue>") |> XMLSecurityFixture.parse!()
      assert {:error, _} = Encryption.decrypt(node, key)
    end

    test "rejects nested cipher text", %{xml: xml, key: key} do
      node = xml |> String.replace("<xenc:CipherValue>", "<xenc:CipherValue><wrapper>") |> String.replace("</xenc:CipherValue>", "</wrapper></xenc:CipherValue>") |> XMLSecurityFixture.parse!()
      assert {:error, _} = Encryption.decrypt(node, key)
    end

    test "rejects duplicate methods", %{xml: xml, key: key} do
      node = xml |> String.replace("<ds:KeyInfo>", ~s(<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo>)) |> XMLSecurityFixture.parse!()
      assert {:error, _} = Encryption.decrypt(node, key)
    end

    test "rejects unimplemented OAEP parameters instead of ignoring them", %{xml: xml, key: key} do
      for parameter <- [~s(<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>), "<xenc:OAEPparams>bm9uZW1wdHk=</xenc:OAEPparams>", "<xenc:KeySize>1024</xenc:KeySize>"] do
        node = xml |> String.replace("</xenc:EncryptionMethod>", parameter <> "</xenc:EncryptionMethod>") |> XMLSecurityFixture.parse!()
        assert {:error, _} = Encryption.decrypt(node, key)
      end
    end

    test "rejects unexpected GCM method parameters", %{xml: xml, key: key} do
      node = xml |> String.replace(~s(aes128-gcm"/>), ~s(aes128-gcm"><xenc:KeySize>128</xenc:KeySize></xenc:EncryptionMethod>)) |> XMLSecurityFixture.parse!()
      assert {:error, _} = Encryption.decrypt(node, key)
    end

    test "rejects non-whitespace method content", %{xml: xml, key: key} do
      node = xml |> String.replace("</xenc:EncryptionMethod>", "unsupported</xenc:EncryptionMethod>") |> XMLSecurityFixture.parse!()
      assert {:error, :unsupported_key_encryption} = Encryption.decrypt(node, key)
    end

    test "accepts inherited namespaces from the enclosing document", %{xml: xml, key: key} do
      [opening] = Regex.run(~r/<saml:EncryptedAssertion[^>]*>/, xml)
      declarations = String.replace(opening, "<saml:EncryptedAssertion", "<Response")
      document = declarations <> String.replace(xml, opening, "<saml:EncryptedAssertion>") <> "</Response>"
      root = XMLSecurityFixture.parse!(document)
      {:ok, encrypted} = XML.exactly_one_child(root, "EncryptedAssertion")
      {:ok, context} = XML.namespace_context(root, encrypted)
      assert {:ok, assertion} = Encryption.decrypt(encrypted, key, context)
      assert XML.attribute(assertion, "ID") == "encrypted"
      assert {:error, _} = Encryption.decrypt(encrypted, key)
    end

    test "rejects RSA v1.5 and CBC", %{xml: xml, key: key} do
      for {from, to} <- [{"rsa-oaep-mgf1p", "rsa-1_5"}, {"http://www.w3.org/2009/xmlenc11#aes128-gcm", "http://www.w3.org/2001/04/xmlenc#aes128-cbc"}] do
        node = xml |> String.replace(from, to) |> XMLSecurityFixture.parse!()
        assert {:error, _} = Encryption.decrypt(node, key)
      end
    end

    test "rejects duplicate and incorrectly namespaced SHA256 OAEP parameters" do
      %{xml: xml, key: key} = XMLSecurityFixture.encryption(hash: :sha256)

      for modified <- [
            String.replace(xml, "</xenc:EncryptionMethod>", ~s(<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></xenc:EncryptionMethod>)),
            String.replace(xml, ~s(xmlns:xenc11="http://www.w3.org/2009/xmlenc11#"), ~s(xmlns:xenc11="urn:wrong"))
          ] do
        assert {:error, _} = Encryption.decrypt(XMLSecurityFixture.parse!(modified), key)
      end
    end

    test "rejects decrypted assertion with incorrect namespace" do
      %{xml: xml, key: key} = XMLSecurityFixture.encryption(plaintext: ~s(<Assertion xmlns="urn:attacker"/>))
      assert {:error, _} = Encryption.decrypt(XMLSecurityFixture.parse!(xml), key)
    end

    test "decrypts the independent Python cryptography OAEP and GCM fixture", %{key: key} do
      encrypted = "test/data/xml_encryption_external.xml" |> File.read!() |> XMLSecurityFixture.parse!()
      assert {:ok, assertion} = Encryption.decrypt(encrypted, key)
      assert XML.attribute(assertion, "ID") == "external-encryption"
      {:ok, subject} = XML.exactly_one_child(assertion, "Subject")
      {:ok, name_id} = XML.exactly_one_child(subject, "NameID")
      assert {:ok, " independent principal "} = XML.scalar_text(name_id)
    end

    test "preserves supported OAEP and GCM variants" do
      for hash <- [:sha, :sha256], bytes <- [16, 32] do
        %{xml: xml, key: key} = XMLSecurityFixture.encryption(hash: hash, key_bytes: bytes)
        assert {:ok, assertion} = Encryption.decrypt(XMLSecurityFixture.parse!(xml), key)
        assert XML.attribute(assertion, "ID") == "encrypted"
      end
    end

    test "rejects tampered authenticated ciphertext", %{xml: xml, key: key} do
      values = Regex.scan(~r/<xenc:CipherValue>([^<]*)<\/xenc:CipherValue>/, xml)
      [_, [_, encoded]] = values
      <<first, rest::binary>> = Base.decode64!(encoded)
      tampered = Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>)
      node = xml |> String.replace(encoded, tampered) |> XMLSecurityFixture.parse!()
      assert {:error, :authentication_failed} = Encryption.decrypt(node, key)
    end
  end
end
