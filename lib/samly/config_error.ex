defmodule Samly.ConfigError do
  @moduledoc false

  defexception [:message]

  @impl true
  @spec exception(map()) :: Exception.t()
  def exception(data) when is_map(data) do
    %__MODULE__{message: "invalid_config"}
  end
end
