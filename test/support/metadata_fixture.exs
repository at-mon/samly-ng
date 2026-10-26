defmodule Samly.Test.MetadataFixture do
  @moduledoc false

  alias Samly.SAML.Key
  alias Samly.SAML.XML

  @metadata_ns "urn:oasis:names:tc:SAML:2.0:metadata"
  @signature_ns "http://www.w3.org/2000/09/xmldsig#"
  @protocol "urn:oasis:names:tc:SAML:2.0:protocol"

  def certificate do
    {:ok, cert} = Key.load_certificate("test/data/test.crt")
    Base.encode64(cert)
  end

  def ec_certificate do
    %{cert: cert} = :public_key.pkix_test_root_cert(~c"Metadata EC test", key: {:namedCurve, :secp256r1}, digest: :sha256)
    cert
  end

  def other_certificate do
    {:ok, tree} = XML.parse(File.read!("test/data/idp_metadata.xml"))

    tree
    |> XML.descendants("X509Certificate")
    |> hd()
    |> XML.text()
    |> String.replace(~r/\s+/, "")
  end

  def key(cert, use \\ "signing") do
    use_attr =
      case use do
        nil -> ""
        value -> ~s( use="#{value}")
      end

    ~s(<md:KeyDescriptor#{use_attr}><ds:KeyInfo><ds:X509Data><ds:X509Certificate>#{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>)
  end

  def role(keys, opts \\ []) do
    name = Keyword.get(opts, :name, "IDPSSODescriptor")
    protocol = Keyword.get(opts, :protocol, @protocol)
    endpoint = Keyword.get(opts, :endpoint, "https://idp.example.test/sso")
    extra = Keyword.get(opts, :extra, "")

    """
    <md:#{name} protocolSupportEnumeration="#{protocol}">#{keys}<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="#{endpoint}"/>#{extra}</md:#{name}>
    """
  end

  def entity(roles, id \\ "urn:test:idp") do
    ~s(<md:EntityDescriptor xmlns:md="#{@metadata_ns}" xmlns:ds="#{@signature_ns}" entityID="#{id}">#{roles}</md:EntityDescriptor>)
  end

  def aggregate(entities) do
    ~s(<md:EntitiesDescriptor xmlns:md="#{@metadata_ns}" xmlns:ds="#{@signature_ns}">#{entities}</md:EntitiesDescriptor>)
  end

  def config(metadata, overrides \\ %{}) do
    Map.merge(%{id: "idp1", sp_id: "sp1", metadata: metadata, base_url: "http://127.0.0.1:4000/sso"}, overrides)
  end

  def sp_config(overrides \\ %{}) do
    Map.merge(%{id: "sp1", entity_id: "urn:test:sp1", certfile: "test/data/test.crt", keyfile: "test/data/test.pem"}, overrides)
  end
end
