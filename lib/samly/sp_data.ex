defmodule Samly.SpData do
  @moduledoc false

  alias Samly.SAML.Key
  alias Samly.SpData

  require Logger

  defstruct id: "",
            entity_id: "",
            certfile: "",
            keyfile: "",
            contact_name: "",
            contact_email: "",
            org_name: "",
            org_displayname: "",
            org_url: "",
            cert: :undefined,
            key: :undefined,
            valid?: true

  @type t :: %__MODULE__{
          id: binary(),
          entity_id: binary(),
          certfile: binary(),
          keyfile: binary(),
          contact_name: binary(),
          contact_email: binary(),
          org_name: binary(),
          org_displayname: binary(),
          org_url: binary(),
          cert: :undefined | binary(),
          key: :undefined | :RSAPrivateKey,
          valid?: boolean()
        }

  @type id :: binary

  @default_contact_name "Samly SP Admin"
  @default_contact_email "admin@samly"
  @default_org_name "Samly SP"
  @default_org_displayname "SAML SP built with Samly"
  @default_org_url "https://github.com/handnot2/samly"

  @spec load_providers(list(map)) :: %{required(id) => t}
  def load_providers(prov_configs) do
    prov_configs
    |> Enum.map(&load_provider/1)
    |> Enum.filter(fn sp_data -> sp_data.valid? end)
    |> Map.new(fn sp_data -> {sp_data.id, sp_data} end)
  end

  @spec load_provider(map) :: t() | no_return
  def load_provider(%{} = opts_map) do
    %__MODULE__{
      id: Map.get(opts_map, :id, ""),
      entity_id: Map.get(opts_map, :entity_id, ""),
      certfile: Map.get(opts_map, :certfile, ""),
      keyfile: Map.get(opts_map, :keyfile, ""),
      contact_name: Map.get(opts_map, :contact_name, @default_contact_name),
      contact_email: Map.get(opts_map, :contact_email, @default_contact_email),
      org_name: Map.get(opts_map, :org_name, @default_org_name),
      org_displayname: Map.get(opts_map, :org_displayname, @default_org_displayname),
      org_url: Map.get(opts_map, :org_url, @default_org_url)
    }
    |> set_id(opts_map)
    |> load_cert(opts_map)
    |> load_key(opts_map)
  end

  @spec set_id(t(), map()) :: t()
  defp set_id(%SpData{} = sp_data, %{} = opts_map) do
    case Map.get(opts_map, :id, "") do
      "" ->
        Logger.error("[Samly] Invalid SP Config: missing id")
        %{sp_data | valid?: false}

      id ->
        %{sp_data | id: id}
    end
  end

  @spec load_cert(t(), map()) :: t()
  defp load_cert(%SpData{certfile: ""} = sp_data, _) do
    %{sp_data | cert: :undefined}
  end

  defp load_cert(%SpData{certfile: certfile} = sp_data, %{}) do
    case Key.load_certificate(certfile) do
      {:ok, cert} ->
        %{sp_data | cert: cert}

      {:error, _reason} ->
        Logger.error("[Samly] Failed to load SP certificate")

        %{sp_data | valid?: false}
    end
  end

  @spec load_key(t(), map()) :: t()
  defp load_key(%SpData{keyfile: ""} = sp_data, _) do
    %{sp_data | key: :undefined}
  end

  defp load_key(%SpData{keyfile: keyfile} = sp_data, %{}) do
    case Key.load_private_key(keyfile) do
      {:ok, key} ->
        %{sp_data | key: key}

      {:error, _reason} ->
        Logger.error("[Samly] Failed to load SP private key")
        %{sp_data | key: :undefined, valid?: false}
    end
  end
end
