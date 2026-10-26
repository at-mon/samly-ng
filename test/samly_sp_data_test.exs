defmodule SamlySpDataTest do
  use ExUnit.Case

  alias Samly.SAML.Key
  alias Samly.SpData

  @sp_config1 %{
    id: "sp1",
    entity_id: "urn:test:sp1",
    certfile: "test/data/test.crt",
    keyfile: "test/data/test.pem"
  }

  describe "RSA credentials" do
    @tag :tmp_dir
    test "rejects a valid RSA key that does not match the certificate", %{tmp_dir: dir} do
      key = :public_key.generate_key({:rsa, 2048, 65_537})
      path = Path.join(dir, "other.pem")
      File.write!(path, :public_key.pem_encode([:public_key.pem_entry_encode(:RSAPrivateKey, key)]))
      refute SpData.load_provider(%{@sp_config1 | keyfile: path}).valid?
    end

    @tag :tmp_dir
    test "rejects EC PKCS8 private keys", %{tmp_dir: dir} do
      key = :public_key.generate_key({:namedCurve, :secp256r1})
      path = Path.join(dir, "ec.pem")
      File.write!(path, :public_key.pem_encode([:public_key.pem_entry_encode(:PrivateKeyInfo, key)]))
      assert {:error, :invalid_private_key} = Key.load_private_key(path)
      refute SpData.load_provider(%{@sp_config1 | keyfile: path}).valid?
    end

    @tag :tmp_dir
    test "rejects PEM certificate wrappers containing invalid DER", %{tmp_dir: dir} do
      path = Path.join(dir, "invalid.crt")
      File.write!(path, :public_key.pem_encode([{:Certificate, "not a certificate", :not_encrypted}]))
      assert {:error, :invalid_certificate} = Key.load_certificate(path)
      refute SpData.load_provider(%{@sp_config1 | certfile: path}).valid?
    end

    @tag :tmp_dir
    test "retains PKCS8 RSA private key support", %{tmp_dir: dir} do
      {:ok, key} = Key.load_private_key(@sp_config1.keyfile)
      path = Path.join(dir, "rsa-pkcs8.pem")
      File.write!(path, :public_key.pem_encode([:public_key.pem_entry_encode(:PrivateKeyInfo, key)]))
      assert SpData.load_provider(%{@sp_config1 | keyfile: path}).valid?
    end
  end

  test "valid-sp-config-1" do
    %SpData{} = sp_data = SpData.load_provider(@sp_config1)
    assert sp_data.valid?
  end

  test "cert-unspecified-sp-config" do
    sp_config = %{@sp_config1 | certfile: ""}
    %SpData{cert: :undefined} = sp_data = SpData.load_provider(sp_config)
    assert sp_data.valid?
  end

  test "key-unspecified-sp-config" do
    sp_config = %{@sp_config1 | keyfile: ""}
    %SpData{key: :undefined} = sp_data = SpData.load_provider(sp_config)
    assert sp_data.valid?
  end

  test "invalid-sp-config-1" do
    sp_config = %{@sp_config1 | id: ""}
    %SpData{} = sp_data = SpData.load_provider(sp_config)
    refute sp_data.valid?
  end

  test "invalid-sp-config-2" do
    sp_config = %{@sp_config1 | certfile: "non-existent.crt"}
    %SpData{} = sp_data = SpData.load_provider(sp_config)
    refute sp_data.valid?
  end

  test "invalid-sp-config-3" do
    sp_config = %{@sp_config1 | keyfile: "non-existent.pem"}
    %SpData{} = sp_data = SpData.load_provider(sp_config)
    refute sp_data.valid?
  end

  test "invalid-sp-config-4" do
    sp_config = %{@sp_config1 | certfile: "test/data/test.pem"}
    %SpData{} = sp_data = SpData.load_provider(sp_config)
    refute sp_data.valid?
  end

  test "invalid-sp-config-5" do
    sp_config = %{@sp_config1 | keyfile: "test/data/test.crt"}
    %SpData{} = sp_data = SpData.load_provider(sp_config)
    refute sp_data.valid?
  end
end
