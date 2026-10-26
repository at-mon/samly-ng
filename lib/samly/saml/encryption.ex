defmodule Samly.SAML.Encryption do
  @moduledoc false

  alias Samly.SAML.XML

  @saml "urn:oasis:names:tc:SAML:2.0:assertion"
  @xenc "http://www.w3.org/2001/04/xmlenc#"
  @ds "http://www.w3.org/2000/09/xmldsig#"
  @xenc11 "http://www.w3.org/2009/xmlenc11#"
  @rsa_oaep_sha1 @xenc <> "rsa-oaep-mgf1p"
  @rsa_oaep @xenc11 <> "rsa-oaep"
  @aes128_gcm @xenc11 <> "aes128-gcm"
  @aes256_gcm @xenc11 <> "aes256-gcm"
  @sha1 @ds <> "sha1"
  @sha256 @xenc <> "sha256"
  @mgf_sha256 @xenc11 <> "mgf1sha256"
  @vocabulary %{
    "EncryptedAssertion" => @saml,
    "EncryptedData" => @xenc,
    "EncryptedKey" => @xenc,
    "EncryptionMethod" => @xenc,
    "CipherData" => @xenc,
    "CipherValue" => @xenc,
    "KeyInfo" => @ds,
    "DigestMethod" => @ds,
    "MGF" => @xenc11,
    "OAEPparams" => @xenc,
    "KeySize" => @xenc
  }

  @doc false
  @spec decrypt(XML.xml_node(), tuple(), map()) :: {:ok, XML.xml_node()} | {:error, atom()}
  def decrypt(encrypted_assertion, private_key, inherited \\ %{})

  def decrypt(encrypted_assertion, private_key, inherited) when is_tuple(private_key) do
    with true <- XML.valid_namespaces?(encrypted_assertion, @vocabulary, inherited),
         {@saml, "EncryptedAssertion"} <- XML.expanded_name(encrypted_assertion, inherited),
         {:ok, data} <- structure(encrypted_assertion),
         {:ok, key_opts} <- key_options(data.key_method),
         {:ok, cipher} <- data_cipher(data.data_method),
         {:ok, wrapped_key} <- cipher_value(data.encrypted_key),
         {:ok, ciphertext} <- cipher_value(data.encrypted_data),
         {:ok, symmetric_key} <- unwrap_key(wrapped_key, private_key, key_opts),
         {:ok, plaintext} <- decrypt_data(cipher, symmetric_key, ciphertext),
         {:ok, assertion} <- XML.parse(plaintext),
         {@saml, "Assertion"} <- XML.expanded_name(assertion) do
      {:ok, assertion}
    else
      {:error, _reason} = error -> error
      _ -> {:error, :invalid_encrypted_assertion}
    end
  rescue
    _ -> {:error, :invalid_encrypted_assertion}
  end

  def decrypt(_encrypted_assertion, _private_key, _inherited), do: {:error, :missing_decryption_key}

  defp structure(encrypted_assertion) do
    with {:ok, encrypted_data} <- XML.exactly_one_child(encrypted_assertion, "EncryptedData"),
         [^encrypted_data] <- XML.element_children(encrypted_assertion),
         type when type in [nil, @xenc <> "Element"] <- XML.attribute(encrypted_data, "Type"),
         {:ok, data_method} <- XML.exactly_one_child(encrypted_data, "EncryptionMethod"),
         {:ok, key_info} <- XML.exactly_one_child(encrypted_data, "KeyInfo"),
         {:ok, _} <- XML.exactly_one_child(encrypted_data, "CipherData"),
         3 <- length(XML.element_children(encrypted_data)),
         {:ok, encrypted_key} <- XML.exactly_one_child(key_info, "EncryptedKey"),
         [^encrypted_key] <- XML.element_children(key_info),
         {:ok, key_method} <- XML.exactly_one_child(encrypted_key, "EncryptionMethod"),
         {:ok, _} <- XML.exactly_one_child(encrypted_key, "CipherData"),
         2 <- length(XML.element_children(encrypted_key)) do
      {:ok, %{encrypted_data: encrypted_data, encrypted_key: encrypted_key, key_method: key_method, data_method: data_method}}
    else
      _ -> {:error, :invalid_encryption_structure}
    end
  end

  defp key_options(method) do
    case {XML.attribute(method, "Algorithm"), XML.element_children(method), whitespace_content?(method)} do
      {@rsa_oaep_sha1, [], true} ->
        {:ok, oaep_options(:sha)}

      {@rsa_oaep_sha1, [digest], true} ->
        case {node_name(digest), XML.attribute(digest, "Algorithm"), XML.element_children(digest), whitespace_content?(digest)} do
          {"DigestMethod", @sha1, [], true} -> {:ok, oaep_options(:sha)}
          _ -> {:error, :unsupported_key_encryption}
        end

      {@rsa_oaep, [digest, mgf], true} ->
        with "DigestMethod" <- node_name(digest),
             "MGF" <- node_name(mgf),
             @sha256 <- XML.attribute(digest, "Algorithm"),
             @mgf_sha256 <- XML.attribute(mgf, "Algorithm"),
             [] <- XML.element_children(digest),
             [] <- XML.element_children(mgf),
             true <- whitespace_content?(digest) and whitespace_content?(mgf) do
          {:ok, oaep_options(:sha256)}
        else
          _ -> {:error, :unsupported_key_encryption}
        end

      _ ->
        {:error, :unsupported_key_encryption}
    end
  end

  defp oaep_options(hash), do: [rsa_padding: :rsa_pkcs1_oaep_padding, rsa_oaep_md: hash, rsa_mgf1_md: hash]

  defp unwrap_key(wrapped_key, private_key, opts) do
    {:ok, :public_key.decrypt_private(wrapped_key, private_key, opts)}
  rescue
    _ -> {:error, :key_decryption_failed}
  end

  defp data_cipher(method) do
    case {XML.attribute(method, "Algorithm"), XML.element_children(method), whitespace_content?(method)} do
      {@aes128_gcm, [], true} -> {:ok, :aes_128_gcm}
      {@aes256_gcm, [], true} -> {:ok, :aes_256_gcm}
      _ -> {:error, :unsupported_data_encryption}
    end
  end

  defp decrypt_data(cipher, key, <<iv::binary-size(12), rest::binary>>) when (cipher == :aes_128_gcm and byte_size(key) == 16) or (cipher == :aes_256_gcm and byte_size(key) == 32) do
    decrypt_gcm(cipher, key, iv, rest)
  end

  defp decrypt_data(_cipher, _key, _ciphertext), do: {:error, :unsupported_data_encryption}

  defp decrypt_gcm(cipher, key, iv, rest) when byte_size(rest) >= 16 do
    encrypted_size = byte_size(rest) - 16
    <<encrypted::binary-size(^encrypted_size), tag::binary-size(16)>> = rest

    case :crypto.crypto_one_time_aead(cipher, key, iv, encrypted, "", tag, false) do
      :error -> {:error, :authentication_failed}
      plaintext -> {:ok, plaintext}
    end
  end

  defp decrypt_gcm(_cipher, _key, _iv, _rest), do: {:error, :invalid_cipher_value}

  defp cipher_value(node) do
    with {:ok, data} <- XML.exactly_one_child(node, "CipherData"),
         {:ok, value} <- XML.exactly_one_child(data, "CipherValue"),
         [^value] <- XML.element_children(data),
         {:ok, text} <- XML.scalar_text(value),
         {:ok, decoded} <- text |> String.replace(~r/[\x20\x09\x0D\x0A]/, "") |> Base.decode64(),
         true <- byte_size(decoded) > 0 do
      {:ok, decoded}
    else
      _ -> {:error, :invalid_cipher_value}
    end
  end

  defp whitespace_content?({_name, _attributes, children}) do
    Enum.all?(children, fn
      text when is_binary(text) -> Regex.match?(~r/\A[\x20\x09\x0D\x0A]*\z/, text)
      _element -> true
    end)
  end

  defp node_name({name, _, _}), do: XML.local_name(name)
end
