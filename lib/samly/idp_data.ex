defmodule Samly.IdpData do
  @moduledoc """
  A loaded identity-provider definition.

  Custom `Samly.ConfigProvider` implementations can build a definition with
  `from_config/2` instead of manually constructing internal SAML records.
  Treat configuration and returned structs as privileged data; they include
  credential-related material and must not be exposed to clients or logs.

  See the [configuration reference](configuration.html) for supported input keys.
  Struct fields derived from metadata are not additional configuration options.
  """

  alias Samly.Esaml
  alias Samly.Helper
  alias Samly.IdpData
  alias Samly.SAML.XML
  alias Samly.SpData

  require Esaml
  require Logger

  @type nameid_format :: :unknown | charlist()
  @type certs :: [binary()]
  @type url :: nil | binary()

  defstruct id: "",
            sp_id: "",
            base_url: nil,
            custom_consume_uri: nil,
            custom_logout_uri: nil,
            metadata_file: nil,
            metadata: nil,
            pre_session_create_pipeline: nil,
            post_session_cleanup_pipeline: nil,
            on_logout: nil,
            use_redirect_for_req: false,
            sign_requests: true,
            sign_metadata: true,
            signed_assertion_in_resp: true,
            signed_envelopes_in_resp: true,
            allow_idp_initiated_flow: false,
            allowed_target_urls: [],
            force_authn: false,
            allow_legacy_sha1: false,
            debug_mode: false,
            entity_id: "",
            certs: [],
            sso_redirect_url: nil,
            sso_post_url: nil,
            slo_redirect_url: nil,
            slo_post_url: nil,
            nameid_format: :unknown,
            fingerprints: [],
            esaml_idp_rec: Esaml.esaml_idp_metadata(),
            esaml_sp_rec: Esaml.esaml_sp(),
            valid?: false

  @type t :: %__MODULE__{
          id: binary(),
          sp_id: binary(),
          base_url: nil | binary(),
          custom_consume_uri: nil | charlist(),
          custom_logout_uri: nil | charlist(),
          metadata_file: nil | binary(),
          metadata: nil | binary(),
          pre_session_create_pipeline: nil | module(),
          post_session_cleanup_pipeline: nil | module(),
          on_logout: nil | (binary(), Samly.Assertion.t() -> any()),
          use_redirect_for_req: boolean(),
          sign_requests: boolean(),
          sign_metadata: boolean(),
          signed_assertion_in_resp: boolean(),
          signed_envelopes_in_resp: boolean(),
          allow_idp_initiated_flow: boolean(),
          allowed_target_urls: nil | [binary()],
          force_authn: boolean(),
          allow_legacy_sha1: boolean(),
          debug_mode: boolean(),
          entity_id: binary(),
          certs: certs(),
          sso_redirect_url: url(),
          sso_post_url: url(),
          slo_redirect_url: url(),
          slo_post_url: url(),
          nameid_format: nameid_format(),
          fingerprints: [binary()],
          esaml_idp_rec: tuple(),
          esaml_sp_rec: tuple(),
          valid?: boolean()
        }

  @redirect "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
  @post "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  @nameid_formats %{
    email: ~c"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    x509: ~c"urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
    windows: ~c"urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
    krb: ~c"urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
    persistent: ~c"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    transient: ~c"urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
  }

  @type id :: binary()

  @spec from_config(map(), map()) :: nil | t()
  @doc "Builds an IdP from trusted SP and IdP configuration maps, returning nil if it is not usable."
  def from_config(sp_config, idp_config) do
    service_providers = SpData.load_providers([sp_config])
    load_providers([idp_config], service_providers)[idp_config.id]
  end

  @doc false
  @spec load_providers([map], %{required(id()) => SpData.t()}) ::
          %{required(id()) => t()} | no_return()
  def load_providers(prov_config, service_providers) do
    prov_config
    |> Enum.flat_map(fn idp_config ->
      try do
        [load_provider(idp_config, service_providers)]
      rescue
        error ->
          Logger.error("[Samly] Failed to load identity provider #{inspect(idp_config[:id])}: #{Exception.message(error)}")

          []
      end
    end)
    |> Enum.filter(fn idp_data -> idp_data.valid? end)
    |> Map.new(fn idp_data -> {idp_data.id, idp_data} end)
  end

  @doc false
  @spec load_provider(map(), %{required(id()) => SpData.t()}) :: t() | no_return
  def load_provider(idp_config, service_providers) do
    %IdpData{}
    |> save_idp_config(idp_config)
    |> load_metadata()
    |> override_nameid_format(idp_config)
    |> update_esaml_recs(service_providers, idp_config)
    |> verify_slo_url()
  end

  @spec save_idp_config(t(), map()) :: t()
  defp save_idp_config(%IdpData{} = idp_data, %{id: id, sp_id: sp_id} = opts_map) when is_binary(id) and is_binary(sp_id) do
    %{idp_data | id: id, sp_id: sp_id, base_url: Map.get(opts_map, :base_url)}
    |> set_metadata(opts_map)
    |> set_pipeline(opts_map)
    |> set_callback(opts_map)
    |> set_custom_uri(opts_map, :custom_consume_uri)
    |> set_custom_uri(opts_map, :custom_logout_uri)
    |> set_allowed_target_urls(opts_map)
    |> set_boolean_attr(opts_map, :use_redirect_for_req)
    |> set_boolean_attr(opts_map, :sign_requests)
    |> set_boolean_attr(opts_map, :sign_metadata)
    |> set_boolean_attr(opts_map, :signed_assertion_in_resp)
    |> set_boolean_attr(opts_map, :signed_envelopes_in_resp)
    |> set_boolean_attr(opts_map, :allow_idp_initiated_flow)
    |> set_boolean_attr(opts_map, :force_authn)
    |> set_boolean_attr(opts_map, :allow_legacy_sha1)
    |> set_boolean_attr(opts_map, :debug_mode)
  end

  @spec load_metadata(t()) :: t()
  defp load_metadata(%IdpData{metadata: metadata} = idp_data) when not is_nil(metadata), do: from_xml(metadata, idp_data)

  # Path comes exclusively from trusted application/provider configuration.
  # sobelow_skip ["Traversal.FileModule"]
  defp load_metadata(%IdpData{metadata_file: metadata_file} = idp_data) when not is_nil(metadata_file) do
    case File.read(idp_data.metadata_file) do
      {:ok, metadata} ->
        load_metadata(%{idp_data | metadata: metadata})

      {:error, reason} ->
        Logger.error("[Samly] Failed to read metadata_file [#{inspect(idp_data.metadata_file)}]: #{inspect(reason)}")

        idp_data
    end
  end

  defp load_metadata(idp_data) do
    Logger.error("[Samly] Either `metadata` or `metadata_file` must be specified in the IdP configuration")

    idp_data
  end

  @spec update_esaml_recs(t(), %{required(id()) => SpData.t()}, map()) :: t()
  defp update_esaml_recs(%IdpData{} = idp_data, service_providers, opts_map) do
    case Map.get(service_providers, idp_data.sp_id) do
      %SpData{} = sp ->
        idp_data = %{idp_data | esaml_idp_rec: to_esaml_idp_metadata(idp_data, opts_map)}
        idp_data = %{idp_data | esaml_sp_rec: get_esaml_sp(sp, idp_data)}
        %{idp_data | valid?: idp_data.valid? and idp_data.id != "" and cert_config_ok?(idp_data, sp)}

      _ ->
        Logger.error("[Samly] Unknown/invalid sp_id: #{idp_data.sp_id}")
        %{idp_data | valid?: false}
    end
  end

  @spec cert_config_ok?(t(), SpData.t()) :: boolean
  defp cert_config_ok?(%IdpData{} = idp_data, %SpData{} = sp_data) do
    if (idp_data.sign_metadata || idp_data.sign_requests) &&
         (sp_data.cert == :undefined || sp_data.key == :undefined) do
      Logger.error("[Samly] SP cert or key missing - Skipping identity provider: #{idp_data.id}")
      false
    else
      true
    end
  end

  @spec verify_slo_url(t()) :: t()
  defp verify_slo_url(%IdpData{} = idp_data) do
    if idp_data.valid? && idp_data.slo_redirect_url == nil && idp_data.slo_post_url == nil do
      Logger.warning("[Samly] SLO Endpoint missing in [#{inspect(idp_data.metadata_file)}]")
    end

    idp_data
  end

  @default_metadata_file "idp_metadata.xml"

  @spec set_metadata(t(), map()) :: t()
  defp set_metadata(%IdpData{} = idp_data, %{} = opts_map) do
    %{
      idp_data
      | metadata_file: Map.get(opts_map, :metadata_file, @default_metadata_file),
        metadata: opts_map[:metadata]
    }
  end

  @spec set_pipeline(t(), map()) :: t()
  defp set_pipeline(%IdpData{} = idp_data, %{} = opts_map) do
    %{
      idp_data
      | pre_session_create_pipeline: Map.get(opts_map, :pre_session_create_pipeline),
        post_session_cleanup_pipeline: Map.get(opts_map, :post_session_cleanup_pipeline)
    }
  end

  defp set_callback(%IdpData{} = idp_data, opts_map) do
    case Map.get(opts_map, :on_logout) do
      nil -> idp_data
      callback when is_function(callback, 2) -> %{idp_data | on_logout: callback}
      _ -> raise ArgumentError, ":on_logout must be a function with arity 2"
    end
  end

  defp set_custom_uri(%IdpData{} = idp_data, opts_map, field) do
    value =
      case Map.get(opts_map, field) do
        nil -> nil
        uri when is_binary(uri) -> String.to_charlist(uri)
        _ -> raise ArgumentError, "#{inspect(field)} must be a URL string"
      end

    Map.put(idp_data, field, value)
  end

  defp set_allowed_target_urls(%IdpData{} = idp_data, %{} = opts_map) do
    target_urls =
      case Map.get(opts_map, :allowed_target_urls, nil) do
        nil -> nil
        urls when is_list(urls) -> Enum.filter(urls, &is_binary/1)
      end

    %{idp_data | allowed_target_urls: target_urls}
  end

  @spec override_nameid_format(t(), map()) :: t()
  defp override_nameid_format(%IdpData{} = idp_data, idp_config) do
    nameid_format =
      case Map.get(idp_config, :nameid_format, "") do
        "" ->
          idp_data.nameid_format

        format when is_binary(format) ->
          to_charlist(format)

        format when is_atom(format) ->
          Map.get_lazy(@nameid_formats, format, fn ->
            Logger.error("[Samly] invalid nameid_format [#{inspect(idp_data.metadata_file)}]: #{inspect(format)}")

            idp_data.nameid_format
          end)
      end

    %{idp_data | nameid_format: nameid_format}
  end

  @spec set_boolean_attr(t(), map(), atom()) :: t()
  defp set_boolean_attr(%IdpData{} = idp_data, %{} = opts_map, attr_name) when is_atom(attr_name) do
    v = Map.get(opts_map, attr_name)
    if is_boolean(v), do: Map.put(idp_data, attr_name, v), else: idp_data
  end

  @spec from_xml(binary, t()) :: t()
  defp from_xml(metadata_xml, %IdpData{} = idp_data) when is_binary(metadata_xml) do
    case XML.parse(metadata_xml) do
      {:ok, md_xml} ->
        signing_certs = get_signing_certs(md_xml)

        %{
          idp_data
          | valid?: get_entity_id(md_xml) != "" and signing_certs != [],
            entity_id: get_entity_id(md_xml),
            certs: signing_certs,
            fingerprints: idp_cert_fingerprints(signing_certs),
            sso_redirect_url: get_sso_redirect_url(md_xml),
            sso_post_url: get_sso_post_url(md_xml),
            slo_redirect_url: get_slo_redirect_url(md_xml),
            slo_post_url: get_slo_post_url(md_xml),
            nameid_format: get_nameid_format(md_xml)
        }

      {:error, reason} ->
        Logger.error("[Samly] Invalid IdP metadata: #{inspect(reason)}")
        %{idp_data | valid?: false}
    end
  end

  # @spec to_esaml_idp_metadata(IdpData.t(), map()) :: :esaml_idp_metadata
  defp to_esaml_idp_metadata(%IdpData{} = idp_data, %{} = idp_config) do
    {sso_url, slo_url} = get_sso_slo_urls(idp_data, idp_config)
    sso_url = if sso_url, do: String.to_charlist(sso_url), else: []
    slo_url = if slo_url, do: String.to_charlist(slo_url), else: :undefined

    Esaml.esaml_idp_metadata(
      entity_id: String.to_charlist(idp_data.entity_id),
      login_location: sso_url,
      logout_location: slo_url,
      name_format: idp_data.nameid_format
    )
  end

  defp get_sso_slo_urls(%IdpData{} = idp_data, %{use_redirect_for_req: true}) do
    {idp_data.sso_redirect_url, idp_data.slo_redirect_url}
  end

  defp get_sso_slo_urls(%IdpData{} = idp_data, %{use_redirect_for_req: false}) do
    {idp_data.sso_post_url, idp_data.slo_post_url}
  end

  defp get_sso_slo_urls(%IdpData{} = idp_data, _opts_map) do
    {
      idp_data.sso_post_url || idp_data.sso_redirect_url,
      idp_data.slo_post_url || idp_data.slo_redirect_url
    }
  end

  @spec idp_cert_fingerprints(certs()) :: [binary()]
  defp idp_cert_fingerprints(certs) when is_list(certs) do
    Enum.flat_map(certs, fn cert ->
      case Base.decode64(cert) do
        {:ok, der} -> [{:sha256, :crypto.hash(:sha256, der)}]
        :error -> []
      end
    end)
  end

  # @spec get_esaml_sp(%SpData{}, %IdpData{}) :: :esaml_sp
  defp get_esaml_sp(%SpData{} = sp_data, %IdpData{} = idp_data) do
    idp_id_from = Application.get_env(:samly, :idp_id_from)
    path_segment_idp_id = if idp_id_from == :subdomain, do: nil, else: idp_data.id

    sp_entity_id =
      case sp_data.entity_id do
        "" -> :undefined
        id -> String.to_charlist(id)
      end

    Esaml.esaml_sp(
      org:
        Esaml.esaml_org(
          name: String.to_charlist(sp_data.org_name),
          displayname: String.to_charlist(sp_data.org_displayname),
          url: String.to_charlist(sp_data.org_url)
        ),
      tech:
        Esaml.esaml_contact(
          name: String.to_charlist(sp_data.contact_name),
          email: String.to_charlist(sp_data.contact_email)
        ),
      key: sp_data.key,
      certificate: sp_data.cert,
      sp_sign_requests: idp_data.sign_requests,
      sp_sign_metadata: idp_data.sign_metadata,
      idp_signs_envelopes: idp_data.signed_envelopes_in_resp,
      idp_signs_assertions: idp_data.signed_assertion_in_resp,
      trusted_fingerprints: idp_data.fingerprints,
      metadata_uri: Helper.get_metadata_uri(idp_data.base_url, path_segment_idp_id),
      consume_uri: Helper.get_consume_uri(idp_data.base_url, path_segment_idp_id),
      logout_uri: Helper.get_logout_uri(idp_data.base_url, path_segment_idp_id),
      entity_id: sp_entity_id,
      idp_entity_id: String.to_charlist(idp_data.entity_id),
      allow_legacy_sha1: idp_data.allow_legacy_sha1
    )
  end

  @doc false
  @spec get_entity_id(XML.xml_node()) :: binary()
  def get_entity_id(md_elem) do
    md_elem
    |> XML.descendants("EntityDescriptor")
    |> List.first()
    |> then(fn node -> if node, do: XML.attribute(node, "entityID") end)
    |> to_string()
    |> String.trim()
  end

  @doc false
  @spec get_nameid_format(XML.xml_node()) :: nameid_format()
  def get_nameid_format(md_elem) do
    case md_elem |> first_descendant("NameIDFormat") |> XML.text() do
      "" -> :unknown
      nameid_format -> to_charlist(nameid_format)
    end
  end

  @doc false
  @spec get_req_signed(XML.xml_node()) :: binary()
  def get_req_signed(md_elem) do
    md_elem
    |> first_descendant("IDPSSODescriptor")
    |> attribute_or_empty("WantAuthnRequestsSigned")
  end

  @doc false
  @spec get_signing_certs(XML.xml_node()) :: certs()
  def get_signing_certs(md_elem), do: get_certs(md_elem, :signing)

  @doc false
  @spec get_enc_certs(XML.xml_node()) :: certs()
  def get_enc_certs(md_elem), do: get_certs(md_elem, :encryption)

  defp get_certs(md_elem, purpose) do
    md_elem
    |> XML.descendants("KeyDescriptor")
    |> Enum.filter(&key_for_purpose?(&1, purpose))
    |> Enum.map(fn key -> key |> first_descendant("X509Certificate") |> XML.text() end)
    |> Enum.map(&String.replace(&1, ~r/\s+/, ""))
    |> Enum.reject(&(&1 == ""))
  end

  @doc false
  @spec get_sso_redirect_url(XML.xml_node()) :: url()
  def get_sso_redirect_url(md_elem), do: get_url(md_elem, "SingleSignOnService", @redirect)

  @doc false
  @spec get_sso_post_url(XML.xml_node()) :: url()
  def get_sso_post_url(md_elem), do: get_url(md_elem, "SingleSignOnService", @post)

  @doc false
  @spec get_slo_redirect_url(XML.xml_node()) :: url()
  def get_slo_redirect_url(md_elem), do: get_url(md_elem, "SingleLogoutService", @redirect)

  @doc false
  @spec get_slo_post_url(XML.xml_node()) :: url()
  def get_slo_post_url(md_elem), do: get_url(md_elem, "SingleLogoutService", @post)

  defp get_url(md_elem, service, binding) do
    md_elem
    |> XML.descendants(service)
    |> Enum.find(&(XML.attribute(&1, "Binding") == binding))
    |> case do
      nil -> nil
      node -> XML.attribute(node, "Location")
    end
  end

  defp first_descendant(nil, _name), do: nil
  defp first_descendant(node, name), do: node |> XML.descendants(name) |> List.first()

  defp attribute_or_empty(nil, _name), do: ""
  defp attribute_or_empty(node, name), do: XML.attribute(node, name) || ""

  defp key_for_purpose?(node, :encryption), do: XML.attribute(node, "use") == "encryption"
  defp key_for_purpose?(node, :signing), do: XML.attribute(node, "use") != "encryption"
end
