defmodule Samly.ConfigProvider do
  @moduledoc """
  Resolves identity providers at request time.

  Implement this behaviour and configure `config :samly, :config_provider, MyProvider` to support tenant-specific or dynamically loaded identity providers.
  """

  @callback get_idp(Plug.Conn.t(), binary()) :: nil | Samly.IdpData.t()
end

defmodule Samly.ConfigProvider.Application do
  @moduledoc """
  Default resolver for the identity providers loaded by `Samly.Provider`.

  Looks up the supplied string ID in application configuration and returns the
  loaded provider or `nil`.
  It does not dynamically fetch metadata or register new endpoint paths.
  """
  @behaviour Samly.ConfigProvider

  @impl true
  def get_idp(_conn, idp_id), do: Samly.Helper.get_idp(idp_id)
end
