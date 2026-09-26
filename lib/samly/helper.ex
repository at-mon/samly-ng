defmodule Samly.Helper do
  @moduledoc false

  alias Samly.Esaml
  alias Samly.IdpData
  alias Samly.SAML.Binding
  alias Samly.SAML.Protocol

  require Esaml

  @spec get_idp(binary) :: nil | IdpData.t()
  def get_idp(idp_id) do
    idps = Application.get_env(:samly, :identity_providers, %{})
    Map.get(idps, idp_id)
  end

  @spec get_metadata_uri(nil | binary, binary) :: nil | charlist
  def get_metadata_uri(nil, _idp_id), do: nil

  def get_metadata_uri(sp_base_url, nil) when is_binary(sp_base_url) do
    String.to_charlist("#{sp_base_url}/sp/metadata")
  end

  def get_metadata_uri(sp_base_url, idp_id) when is_binary(sp_base_url) do
    String.to_charlist("#{sp_base_url}/sp/metadata/#{idp_id}")
  end

  @spec get_consume_uri(nil | binary, binary) :: nil | charlist
  def get_consume_uri(nil, _idp_id), do: nil

  def get_consume_uri(sp_base_url, nil) when is_binary(sp_base_url) do
    String.to_charlist("#{sp_base_url}/sp/consume")
  end

  def get_consume_uri(sp_base_url, idp_id) when is_binary(sp_base_url) do
    String.to_charlist("#{sp_base_url}/sp/consume/#{idp_id}")
  end

  @spec get_logout_uri(nil | binary, binary) :: nil | charlist
  def get_logout_uri(nil, _idp_id), do: nil

  def get_logout_uri(sp_base_url, nil) when is_binary(sp_base_url) do
    String.to_charlist("#{sp_base_url}/sp/logout")
  end

  def get_logout_uri(sp_base_url, idp_id) when is_binary(sp_base_url) do
    String.to_charlist("#{sp_base_url}/sp/logout/#{idp_id}")
  end

  def sp_metadata(sp) do
    Protocol.metadata(sp)
  end

  def gen_idp_signin_req(sp, idp_metadata, nameid_format) do
    gen_idp_signin_req(sp, idp_metadata, nameid_format, [])
  end

  def gen_idp_signin_req(sp, idp_metadata, nameid_format, opts) do
    idp_signin_url = Esaml.esaml_idp_metadata(idp_metadata, :login_location)

    xml_frag = Protocol.authn_request(idp_signin_url, sp, nameid_format, opts)

    {idp_signin_url, xml_frag}
  end

  def gen_idp_signout_req(sp, idp_metadata, subject_rec, session_index) do
    idp_signout_url = Esaml.esaml_idp_metadata(idp_metadata, :logout_location)
    xml_frag = Protocol.logout_request(idp_signout_url, sp, subject_rec, session_index)
    {idp_signout_url, xml_frag}
  end

  def gen_idp_signout_resp(sp, idp_metadata, signout_status, in_response_to \\ nil) do
    idp_signout_url = Esaml.esaml_idp_metadata(idp_metadata, :logout_location)
    xml_frag = Protocol.logout_response(idp_signout_url, sp, signout_status, in_response_to)
    {idp_signout_url, xml_frag}
  end

  def decode_idp_auth_resp(sp, saml_encoding, saml_response) do
    with {:ok, xml_frag} <- decode_saml_payload(saml_encoding, saml_response),
         {:ok, assertion} <- Protocol.decode_authn_response(xml_frag, sp) do
      {:ok, assertion}
    else
      {:error, reason} -> {:error, reason}
      error -> {:error, {:invalid_request, "#{inspect(error)}"}}
    end
  end

  def decode_idp_signout_resp(sp, saml_encoding, saml_response) do
    case decode_saml_payload(saml_encoding, saml_response) do
      {:ok, xml} -> Protocol.decode_logout_response(xml, sp)
      _ -> {:error, :invalid_request}
    end
  end

  def decode_idp_signout_req(sp, saml_encoding, saml_request) do
    case decode_saml_payload(saml_encoding, saml_request) do
      {:ok, xml} -> Protocol.decode_logout_request(xml, sp)
      _ -> {:error, :invalid_request}
    end
  end

  defp decode_saml_payload(saml_encoding, saml_payload) do
    Binding.decode(saml_encoding, saml_payload)
  end
end
