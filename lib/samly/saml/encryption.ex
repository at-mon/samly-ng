defmodule Samly.SAML.Encryption do
  @moduledoc false

  alias Samly.SAML.XML

  @rsa_oaep_sha1 "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
  @rsa_oaep "http://www.w3.org/2009/xmlenc11#rsa-oaep"
  @aes128_gcm "http://www.w3.org/2009/xmlenc11#aes128-gcm"
  @aes256_gcm "http://www.w3.org/2009/xmlenc11#aes256-gcm"
  @sha256 "http://www.w3.org/2001/04/xmlenc#sha256"
  @mgf_sha256 "http://www.w3.org/2009/xmlenc11#mgf1sha256"

  @spec decrypt(XML.xml_node(), tuple()) :: {:ok, XML.xml_node()} | {:error, atom()}
  def decrypt(encrypted_assertion, private_key) when is_tuple(private_key) do
    with {:ok, encrypted_data} <- exactly_one(encrypted_assertion, "EncryptedData"),
         {:ok, encrypted_key} <- exactly_one(encrypted_data, "EncryptedKey"),
         {:ok, wrapped_key} <- cipher_value(encrypted_key),
         {:ok, symmetric_key} <- unwrap_key(encrypted_key, wrapped_key, private_key),
         {:ok, ciphertext} <- cipher_value(encrypted_data),
         {:ok, plaintext} <- decrypt_data(encrypted_data, symmetric_key, ciphertext),
         {:ok, assertion} <- XML.parse(plaintext),
         "Assertion" <- node_name(assertion) do
      {:ok, assertion}
    else
      {:error, _reason} = error -> error
      _ -> {:error, :invalid_encrypted_assertion}
    end
  rescue
    _ -> {:error, :invalid_encrypted_assertion}
  end

  def decrypt(_encrypted_assertion, _private_key), do: {:error, :missing_decryption_key}

  defp unwrap_key(encrypted_key, wrapped_key, private_key) do
    method = direct_child(encrypted_key, "EncryptionMethod")
    algorithm = attribute(method, "Algorithm")

    opts =
      case algorithm do
        @rsa_oaep_sha1 ->
          [rsa_padding: :rsa_pkcs1_oaep_padding, rsa_oaep_md: :sha, rsa_mgf1_md: :sha]

        @rsa_oaep ->
          if digest_algorithm(method) == @sha256 and mgf_algorithm(method) == @mgf_sha256 do
            [rsa_padding: :rsa_pkcs1_oaep_padding, rsa_oaep_md: :sha256, rsa_mgf1_md: :sha256]
          end

        _ ->
          nil
      end

    if opts do
      {:ok, :public_key.decrypt_private(wrapped_key, private_key, opts)}
    else
      {:error, :unsupported_key_encryption}
    end
  rescue
    _ -> {:error, :key_decryption_failed}
  end

  defp decrypt_data(encrypted_data, symmetric_key, ciphertext) do
    algorithm = encrypted_data |> direct_child("EncryptionMethod") |> attribute("Algorithm")

    case {algorithm, symmetric_key, ciphertext} do
      {@aes128_gcm, <<_::128>> = key, <<iv::binary-size(12), rest::binary>>} ->
        decrypt_gcm(key, iv, rest)

      {@aes256_gcm, <<_::256>> = key, <<iv::binary-size(12), rest::binary>>} ->
        decrypt_gcm(key, iv, rest)

      _ ->
        {:error, :unsupported_data_encryption}
    end
  end

  defp decrypt_gcm(key, iv, rest) when byte_size(rest) >= 16 do
    encrypted_size = byte_size(rest) - 16
    <<encrypted::binary-size(^encrypted_size), tag::binary-size(16)>> = rest

    case :crypto.crypto_one_time_aead(gcm_cipher(key), key, iv, encrypted, "", tag, false) do
      :error -> {:error, :authentication_failed}
      plaintext -> {:ok, plaintext}
    end
  end

  defp gcm_cipher(key) when byte_size(key) == 16, do: :aes_128_gcm
  defp gcm_cipher(key) when byte_size(key) == 32, do: :aes_256_gcm

  defp cipher_value(node) do
    case node |> direct_child("CipherData") |> direct_child("CipherValue") |> XML.text() do
      "" -> {:error, :missing_cipher_value}
      value -> decode64(value)
    end
  end

  defp decode64(value) do
    case value |> String.replace(~r/\s+/, "") |> Base.decode64() do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_cipher_value}
    end
  end

  defp exactly_one(node, name) do
    case XML.descendants(node, name) do
      [match] -> {:ok, match}
      [] -> {:error, :missing_encryption_element}
      _ -> {:error, :ambiguous_encryption_element}
    end
  end

  defp digest_algorithm(method), do: method |> direct_child("DigestMethod") |> attribute("Algorithm")

  defp mgf_algorithm(method), do: method |> direct_child("MGF") |> attribute("Algorithm")

  defp direct_child(nil, _name), do: nil
  defp direct_child(node, name), do: node |> XML.children(name) |> List.first()
  defp attribute(nil, _name), do: nil
  defp attribute(node, name), do: XML.attribute(node, name)
  defp node_name({name, _, _}), do: XML.local_name(name)
end
