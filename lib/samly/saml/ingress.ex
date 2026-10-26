defmodule Samly.SAML.Ingress do
  @moduledoc false

  alias Samly.SAML.Binding
  alias Samly.SAML.RedirectSignature

  @parameters ~w(SAMLRequest SAMLResponse RelayState SAMLEncoding SigAlg Signature)

  def post_params(conn, type) do
    params = conn.body_params
    query = conn.query_params

    with false <- Enum.any?(@parameters, &Map.has_key?(query, &1)),
         :ok <- validate(params, type),
         true <- params["SAMLEncoding"] in [nil, ""] do
      {:ok, params, []}
    else
      _ -> {:error, :invalid_saml_parameters}
    end
  end

  def logout_params(%Plug.Conn{method: "GET", query_string: query}, idp, type) do
    with {:ok, params} <- RedirectSignature.verify_and_decode(query, type, idp.certs, allow_legacy_sha1: idp.allow_legacy_sha1),
         :ok <- validate(params, type),
         true <- params["SAMLEncoding"] in [nil, Binding.deflate_encoding()] do
      {:ok, Map.put(params, "SAMLEncoding", Binding.deflate_encoding()), [redirect_verified: true]}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_saml_parameters}
    end
  end

  def logout_params(conn, _idp, type), do: post_params(conn, type)

  defp validate(params, type) do
    present = Enum.filter(~w(SAMLRequest SAMLResponse), &Map.has_key?(params, &1))
    scalars? = Enum.all?(@parameters, fn key -> not Map.has_key?(params, key) or is_binary(params[key]) end)

    case {present, scalars?} do
      {[^type], true} -> :ok
      _ -> {:error, :invalid_saml_parameters}
    end
  end
end
