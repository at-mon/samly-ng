defmodule Samly.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    Supervisor.start_link([Samly.ReplayCache.ETS], strategy: :one_for_one, name: Samly.Supervisor)
  end
end
