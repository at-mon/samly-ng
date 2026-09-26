defmodule Samly.SAML.Binding do
  @moduledoc false

  @deflate "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE"
  @default_max_encoded_bytes 1_398_104
  @default_max_inflated_bytes 1_048_576

  @spec deflate_encoding() :: binary()
  def deflate_encoding, do: @deflate

  @spec encode_post(binary()) :: binary()
  def encode_post(xml) when is_binary(xml), do: Base.encode64(xml)

  @rsa_sha256 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

  @spec redirect_url(binary() | charlist(), binary(), binary(), keyword()) :: binary()
  def redirect_url(destination, xml, relay_state, opts \\ []) do
    payload_type = payload_type(xml)
    compressed = deflate_raw(xml)
    message = encode_form(Base.encode64(compressed))
    relay = encode_form(relay_state)
    base_query = "#{payload_type}=#{message}&RelayState=#{relay}"
    query = sign_redirect_query(base_query, Keyword.get(opts, :signing_key))

    separator = if String.contains?(to_string(destination), "?"), do: "&", else: "?"
    to_string(destination) <> separator <> "SAMLEncoding=#{encode_form(@deflate)}&" <> query
  end

  @spec post_form(binary() | charlist(), binary(), binary(), binary()) :: binary()
  def post_form(destination, xml, relay_state, nonce \\ "") do
    nonce_attr = if nonce == "", do: "", else: ~s( nonce="#{html_escape(nonce)}")

    """
    <!doctype html>
    <html lang="en"><head><meta charset="utf-8"><title>POST data</title></head>
    <body>
    <script#{nonce_attr}>document.addEventListener("DOMContentLoaded",function(){document.getElementById("saml-req-form").submit()});</script>
    <noscript><p><strong>Note:</strong> Press the button below to proceed.</p></noscript>
    <form id="saml-req-form" method="post" action="#{html_escape(to_string(destination))}">
    <input type="hidden" name="#{payload_type(xml)}" value="#{encode_post(xml)}">
    <input type="hidden" name="RelayState" value="#{html_escape(relay_state)}">
    <noscript><input type="submit" value="Submit"></noscript>
    </form></body></html>
    """
  end

  @spec decode(binary() | nil, binary(), keyword()) :: {:ok, binary()} | {:error, atom()}
  def decode(encoding, payload, opts \\ [])

  def decode(payload, nil, opts) when is_binary(payload), do: decode(nil, payload, opts)

  def decode(_encoding, payload, _opts) when not is_binary(payload), do: {:error, :missing_saml_payload}

  def decode(encoding, payload, opts) do
    max_encoded = Keyword.get(opts, :max_encoded_bytes, @default_max_encoded_bytes)
    max_inflated = Keyword.get(opts, :max_inflated_bytes, @default_max_inflated_bytes)

    with :ok <- validate_size(payload, max_encoded),
         {:ok, decoded} <- decode64(payload),
         {:ok, xml} <- maybe_inflate(encoding, decoded, max_inflated),
         :ok <- validate_size(xml, max_inflated) do
      {:ok, xml}
    end
  end

  defp decode64(payload) do
    case Base.decode64(payload, ignore: :whitespace) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_base64}
    end
  end

  defp maybe_inflate(@deflate, compressed, limit), do: inflate(compressed, limit)
  defp maybe_inflate(_, decoded, _limit), do: {:ok, decoded}

  defp inflate(compressed, limit) do
    z = :zlib.open()

    try do
      :ok = :zlib.inflateInit(z, -15)
      inflate_bounded(z, compressed, limit, [], 0)
    catch
      _, _ -> {:error, :invalid_deflate}
    after
      :zlib.close(z)
    end
  end

  defp inflate_bounded(z, input, limit, chunks, size) do
    case :zlib.safeInflate(z, input) do
      {:continue, output} when input == <<>> and output == [] ->
        {:error, :invalid_deflate}

      {:continue, output} ->
        continue_inflate(z, output, limit, chunks, size)

      {:finished, output} ->
        with {:ok, chunks, _size} <- append_bounded(output, limit, chunks, size) do
          :ok = :zlib.inflateEnd(z)
          {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}
        end
    end
  end

  defp continue_inflate(z, output, limit, chunks, size) do
    with {:ok, chunks, size} <- append_bounded(output, limit, chunks, size) do
      inflate_bounded(z, <<>>, limit, chunks, size)
    end
  end

  defp append_bounded(output, limit, chunks, size) do
    output_size = :erlang.iolist_size(output)

    if size + output_size <= limit do
      {:ok, [output | chunks], size + output_size}
    else
      {:error, :payload_too_large}
    end
  end

  defp validate_size(data, limit) when byte_size(data) <= limit, do: :ok
  defp validate_size(_data, _limit), do: {:error, :payload_too_large}

  defp deflate_raw(xml) do
    z = :zlib.open()

    try do
      :ok = :zlib.deflateInit(z, :default, :deflated, -15, 8, :default)
      IO.iodata_to_binary(:zlib.deflate(z, xml, :finish))
    after
      :zlib.close(z)
    end
  end

  defp payload_type(xml) do
    if Regex.match?(~r/<(?:\w+:)?\w*Response\b/, xml), do: "SAMLResponse", else: "SAMLRequest"
  end

  defp sign_redirect_query(query, key) when is_tuple(key) do
    sig_alg = encode_form(@rsa_sha256)
    signed = query <> "&SigAlg=" <> sig_alg
    signature = signed |> :public_key.sign(:sha256, key) |> Base.encode64() |> encode_form()
    signed <> "&Signature=" <> signature
  end

  defp sign_redirect_query(query, _key), do: query

  defp encode_form(value), do: URI.encode_www_form(to_string(value))

  defp html_escape(value) do
    value
    |> to_string()
    |> String.replace("&", "&amp;")
    |> String.replace("\"", "&quot;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
  end
end
