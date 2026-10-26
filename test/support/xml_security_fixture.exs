defmodule Samly.XMLSecurityFixture do
  @moduledoc false

  alias Samly.SAML.Key
  alias Samly.SAML.XML

  def encryption(opts \\ []) do
    {:ok, key} = Key.load_private_key("test/data/test.pem")
    {:ok, certificate} = Key.load_certificate("test/data/test.crt")
    public_key = certificate |> :public_key.pkix_decode_cert(:otp) |> elem(1) |> elem(7) |> elem(2)
    symmetric_key = :crypto.strong_rand_bytes(Keyword.get(opts, :key_bytes, 16))
    iv = :crypto.strong_rand_bytes(12)
    cipher = if byte_size(symmetric_key) == 16, do: :aes_128_gcm, else: :aes_256_gcm
    plaintext = Keyword.get(opts, :plaintext, ~s(<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="encrypted"/>))
    {ciphertext, tag} = :crypto.crypto_one_time_aead(cipher, symmetric_key, iv, plaintext, "", true)
    hash = Keyword.get(opts, :hash, :sha)
    wrapped = :public_key.encrypt_public(symmetric_key, public_key, rsa_padding: :rsa_pkcs1_oaep_padding, rsa_oaep_md: hash, rsa_mgf1_md: hash)

    {algorithm, parameters} =
      case hash do
        :sha ->
          {"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", ""}

        :sha256 ->
          {"http://www.w3.org/2009/xmlenc11#rsa-oaep", ~s(<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><xenc11:MGF Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/>)}
      end

    bits = byte_size(symmetric_key) * 8

    xml = """
    <saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedData><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes#{bits}-gcm"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="#{algorithm}">#{parameters}</xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>#{Base.encode64(wrapped)}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>#{Base.encode64(iv <> ciphertext <> tag)}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>
    """

    %{xml: xml, key: key}
  end

  def parse!(xml) do
    {:ok, node} = XML.parse(xml)
    node
  end
end
