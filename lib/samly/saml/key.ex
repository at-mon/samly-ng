defmodule Samly.SAML.Key do
  @moduledoc false

  require Record

  Record.defrecordp(:otp_certificate, :OTPCertificate, Record.extract(:OTPCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl"))
  Record.defrecordp(:otp_tbs_certificate, :OTPTBSCertificate, Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl"))
  Record.defrecordp(:otp_public_key_info, :OTPSubjectPublicKeyInfo, Record.extract(:OTPSubjectPublicKeyInfo, from_lib: "public_key/include/OTP-PUB-KEY.hrl"))
  Record.defrecordp(:rsa_private_key, :RSAPrivateKey, Record.extract(:RSAPrivateKey, from_lib: "public_key/include/OTP-PUB-KEY.hrl"))

  @doc false
  @spec load_certificate(Path.t()) :: {:ok, binary()} | {:error, atom() | term()}
  # Path is trusted SP configuration, never a request parameter.
  # sobelow_skip ["Traversal.FileModule"]
  def load_certificate(path) do
    with {:ok, pem} <- File.read(path),
         [{:Certificate, der, :not_encrypted}] <- :public_key.pem_decode(pem),
         {:ok, _key} <- certificate_public_key(der) do
      {:ok, der}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_certificate}
    end
  rescue
    _ -> {:error, :invalid_certificate}
  end

  @doc false
  @spec load_private_key(Path.t()) :: {:ok, tuple()} | {:error, atom() | term()}
  # Path is trusted SP configuration, never a request parameter.
  # sobelow_skip ["Traversal.FileModule"]
  def load_private_key(path) do
    with {:ok, pem} <- File.read(path),
         [{type, _der, :not_encrypted} = entry] when type in [:RSAPrivateKey, :PrivateKeyInfo] <- :public_key.pem_decode(pem),
         rsa_private_key(modulus: modulus, publicExponent: exponent, privateExponent: private_exponent) = key <- :public_key.pem_entry_decode(entry),
         true <- valid_rsa_public_key?(modulus, exponent) and is_integer(private_exponent) and private_exponent > 0,
         true <- usable_private_key?(key, {:RSAPublicKey, modulus, exponent}) do
      {:ok, key}
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_private_key}
    end
  rescue
    _ -> {:error, :invalid_private_key}
  end

  @doc false
  @spec certificate_public_key(binary()) :: {:ok, tuple()} | {:error, :invalid_certificate}
  def certificate_public_key(der) when is_binary(der) do
    with otp_certificate(tbsCertificate: tbs) <- :public_key.pkix_decode_cert(der, :otp),
         otp_tbs_certificate(subjectPublicKeyInfo: info) <- tbs,
         otp_public_key_info(subjectPublicKey: {:RSAPublicKey, modulus, exponent} = key) <- info,
         true <- valid_rsa_public_key?(modulus, exponent) do
      {:ok, key}
    else
      _ -> {:error, :invalid_certificate}
    end
  rescue
    _ -> {:error, :invalid_certificate}
  end

  @doc false
  @spec matching_pair?(binary(), tuple()) :: boolean()
  def matching_pair?(certificate, rsa_private_key(modulus: modulus, publicExponent: exponent)) do
    certificate_public_key(certificate) == {:ok, {:RSAPublicKey, modulus, exponent}}
  end

  def matching_pair?(_certificate, _key), do: false

  defp valid_rsa_public_key?(modulus, exponent) do
    is_integer(modulus) and modulus > 0 and rem(modulus, 2) == 1 and
      is_integer(exponent) and exponent >= 3 and rem(exponent, 2) == 1 and exponent < modulus
  end

  defp usable_private_key?(key, public_key) do
    challenge = "Samly RSA key validation"
    signature = :public_key.sign(challenge, :sha256, key)
    :public_key.verify(challenge, :sha256, signature, public_key)
  end
end
