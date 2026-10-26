defmodule Samly.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      Samly.ReplayCache.ETS,
      %{id: Samly.State.Supervisor, start: {Supervisor, :start_link, [[], [strategy: :one_for_one, name: Samly.State.Supervisor]]}, type: :supervisor}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: Samly.Supervisor)
  end
end
