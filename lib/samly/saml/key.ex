defmodule Samly.SAML.Key do
  @moduledoc false

  @spec load_certificate(Path.t()) :: {:ok, binary()} | {:error, atom() | term()}
  # Path is trusted SP configuration, never a request parameter.
  # sobelow_skip ["Traversal.FileModule"]
  def load_certificate(path) do
    with {:ok, pem} <- File.read(path),
         [{:Certificate, der, :not_encrypted}] <- :public_key.pem_decode(pem) do
      {:ok, der}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_certificate}
    end
  end

  @spec load_private_key(Path.t()) :: {:ok, tuple()} | {:error, atom() | term()}
  # Path is trusted SP configuration, never a request parameter.
  # sobelow_skip ["Traversal.FileModule"]
  def load_private_key(path) do
    with {:ok, pem} <- File.read(path),
         [entry] <- :public_key.pem_decode(pem),
         type when type in [:RSAPrivateKey, :PrivateKeyInfo] <- elem(entry, 0),
         key when is_tuple(key) <- :public_key.pem_entry_decode(entry) do
      {:ok, key}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_private_key}
    end
  rescue
    _ -> {:error, :invalid_private_key}
  end
end
