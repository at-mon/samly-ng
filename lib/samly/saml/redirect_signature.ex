defmodule Samly.SAML.RedirectSignature do
  @moduledoc false

  @algorithms %{
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => :sha256,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => :sha384,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => :sha512
  }
  @sha1 "http://www.w3.org/2000/09/xmldsig#rsa-sha1"

  @spec verify(binary(), binary(), [binary()], keyword()) :: :ok | {:error, atom()}
  def verify(query, message_type, certificates, opts \\ []) do
    with {:ok, _params} <- verify_and_decode(query, message_type, certificates, opts), do: :ok
  end

  @doc false
  def verify_and_decode(query, message_type, certificates, opts \\ []) do
    with {:ok, params} <- parse_raw_query(query),
         :ok <- validate_message_type(params, message_type),
         {:ok, message} <- fetch(params, message_type),
         {:ok, algorithm_raw} <- fetch(params, "SigAlg"),
         {:ok, signature_raw} <- fetch(params, "Signature"),
         {:ok, hash} <- hash_algorithm(decode(algorithm_raw), opts),
         {:ok, signature} <- signature_raw |> decode() |> Base.decode64(),
         signed = signed_octets(message_type, message, params["RelayState"], algorithm_raw),
         true <- Enum.any?(certificates, &verifies?(&1, signed, hash, signature)) do
      {:ok, Map.new(params, fn {key, value} -> {key, decode(value)} end)}
    else
      false -> {:error, :bad_redirect_signature}
      :error -> {:error, :bad_redirect_signature}
      {:error, _reason} = error -> error
    end
  rescue
    _ -> {:error, :bad_redirect_signature}
  end

  defp parse_raw_query(query) do
    query
    |> String.split("&", trim: true)
    |> Enum.reduce_while({:ok, %{}}, fn pair, {:ok, params} ->
      [key | value] = String.split(pair, "=", parts: 2)
      decoded_key = decode(key)

      cond do
        String.contains?(decoded_key, ["[", "]"]) -> {:halt, {:error, :invalid_query_parameter}}
        Map.has_key?(params, decoded_key) -> {:halt, {:error, :duplicate_query_parameter}}
        true -> {:cont, {:ok, Map.put(params, decoded_key, List.first(value) || "")}}
      end
    end)
  end

  defp validate_message_type(params, type) when type in ["SAMLRequest", "SAMLResponse"] do
    case Enum.filter(["SAMLRequest", "SAMLResponse"], &Map.has_key?(params, &1)) do
      [^type] -> :ok
      _ -> {:error, :ambiguous_saml_message}
    end
  end

  defp signed_octets(type, message, nil, algorithm), do: "#{type}=#{message}&SigAlg=#{algorithm}"

  defp signed_octets(type, message, relay_state, algorithm) do
    "#{type}=#{message}&RelayState=#{relay_state}&SigAlg=#{algorithm}"
  end

  defp hash_algorithm(@sha1, opts) do
    if Keyword.get(opts, :allow_legacy_sha1, false),
      do: {:ok, :sha},
      else: {:error, :legacy_sha1_disabled}
  end

  defp hash_algorithm(uri, _opts) do
    case Map.fetch(@algorithms, uri) do
      {:ok, hash} -> {:ok, hash}
      :error -> {:error, :unsupported_signature_algorithm}
    end
  end

  defp verifies?(certificate64, signed, hash, signature) do
    case Base.decode64(String.replace(certificate64, ~r/\s+/, "")) do
      {:ok, certificate} -> :public_key.verify(signed, hash, signature, public_key(certificate))
      :error -> false
    end
  rescue
    _ -> false
  end

  defp public_key(certificate) do
    certificate |> :public_key.pkix_decode_cert(:otp) |> elem(1) |> elem(7) |> elem(2)
  end

  defp fetch(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} when value != "" -> {:ok, value}
      _ -> {:error, :missing_signature_parameter}
    end
  end

  defp decode(value), do: URI.decode_www_form(value)
end
