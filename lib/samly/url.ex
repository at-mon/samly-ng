defmodule Samly.URL do
  @moduledoc false

  @doc false
  @spec valid?(term(), :base | :callback | :target | :endpoint) :: boolean()
  def valid?(url, kind) when is_binary(url) and url != "" do
    with true <- safe_text?(url) and not Regex.match?(~r/%(?![0-9a-fA-F]{2})/, url),
         {:ok, uri} <- URI.new(url),
         decoded = URI.decode(url),
         true <- String.valid?(decoded) and not Regex.match?(~r/[\x00-\x1f\x7f\\]/, decoded) do
      valid_uri?(uri, kind) and not String.starts_with?(decoded, "//")
    else
      _ -> false
    end
  end

  def valid?(_url, _kind), do: false

  defp safe_text?(url), do: String.valid?(url) and not Regex.match?(~r/[\x00-\x20\x7f\\]/, url)

  defp valid_uri?(%URI{userinfo: nil, fragment: nil, query: query} = uri, kind) do
    (kind not in [:base, :callback] or is_nil(query)) and valid_location?(uri, kind)
  end

  defp valid_uri?(_uri, _kind), do: false

  defp valid_location?(%URI{scheme: scheme, host: host, port: port}, _kind) when scheme in ["http", "https"] and is_binary(host) and host != "" and port in 1..65_535, do: true

  defp valid_location?(%URI{scheme: nil, host: nil, authority: nil, path: "/" <> rest}, kind) when kind in [:base, :callback, :target], do: not String.starts_with?(rest, "/")

  defp valid_location?(_uri, _kind), do: false
end
