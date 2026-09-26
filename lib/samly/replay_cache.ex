defmodule Samly.ReplayCache do
  @moduledoc """
  Tracks accepted SAML message IDs to prevent replay attacks.

  Configure `:replay_cache` with a module implementing `consume/2` when a
  cluster-wide store is required.
  """

  @callback consume(binary(), DateTime.t()) :: :ok | {:error, atom()}

  @spec consume(binary(), DateTime.t()) :: :ok | {:error, atom()}
  def consume(id, expires_at) do
    provider = Application.get_env(:samly, :replay_cache, Samly.ReplayCache.ETS)
    provider.consume(:crypto.hash(:sha256, id), expires_at)
  end
end

defmodule Samly.ReplayCache.ETS do
  @moduledoc """
  The default supervised, node-local replay cache.

  It retains up to 100,000 entries and rejects new entries when full.
  Expired entries are pruned every 60 seconds.
  History does not survive cache or VM restarts and is not shared between nodes.
  Configure a durable shared `Samly.ReplayCache` implementation when either
  restart-safe or multi-node protection is required.
  The Samly application starts this cache automatically.
  """
  @behaviour Samly.ReplayCache

  use GenServer

  @table :samly_replay_cache

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl GenServer
  def init(opts) do
    table = :ets.new(@table, [:set, :protected])
    Process.send_after(self(), :prune, 60_000)
    {:ok, {table, Keyword.get(opts, :max_entries, 100_000)}}
  end

  @impl Samly.ReplayCache
  def consume(id, expires_at) do
    GenServer.call(__MODULE__, {:consume, id, DateTime.to_unix(expires_at)})
  catch
    :exit, _reason -> {:error, :replay_cache_unavailable}
  end

  @impl GenServer
  def handle_call({:consume, id, expires}, _from, {table, limit} = state) do
    now = System.system_time(:second)

    result =
      cond do
        expires <= now ->
          {:error, :expired_message}

        :ets.member(table, id) ->
          {:error, :replayed}

        :ets.info(table, :size) >= limit ->
          {:error, :replay_cache_full}

        true ->
          true = :ets.insert_new(table, {id, expires})
          :ok
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_info(:prune, {table, _limit} = state) do
    now = System.system_time(:second)
    :ets.select_delete(table, [{{:"$1", :"$2"}, [{:"=<", :"$2", now}], [true]}])
    Process.send_after(self(), :prune, 60_000)
    {:noreply, state}
  end
end
