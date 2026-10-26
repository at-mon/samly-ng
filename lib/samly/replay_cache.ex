defmodule Samly.ReplayCache do
  @moduledoc """
  Tracks accepted SAML message IDs to prevent replay attacks.

  Configure `:replay_cache` with a module implementing `consume/2` when a
  cluster-wide store is required.
  """

  @callback consume(binary(), DateTime.t()) :: :ok | {:error, atom()}
  @callback consume_many([{binary(), DateTime.t()}]) :: :ok | {:error, atom()}
  @optional_callbacks consume_many: 1

  @spec consume(binary(), DateTime.t()) :: :ok | {:error, atom()}
  def consume(id, expires_at), do: consume_many([{id, expires_at}])

  @doc "Atomically consumes all identifiers, or rejects without inserting any."
  @spec consume_many([{binary(), DateTime.t()}]) :: :ok | {:error, atom()}
  def consume_many(entries) when is_list(entries) and entries != [] do
    provider = Application.get_env(:samly, :replay_cache, Samly.ReplayCache.ETS)
    entries = Enum.map(entries, fn {id, expires} -> {:crypto.hash(:sha256, id), expires} end)
    Code.ensure_loaded!(provider)

    case {function_exported?(provider, :consume_many, 1), entries} do
      {true, entries} -> provider.consume_many(entries)
      {false, [{id, expires}]} -> provider.consume(id, expires)
      {false, _entries} -> {:error, :atomic_replay_cache_required}
    end
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
  def consume(id, expires_at), do: consume_many([{id, expires_at}])

  @impl Samly.ReplayCache
  def consume_many(entries) do
    entries = Enum.map(entries, fn {id, expires} -> {id, DateTime.to_unix(expires, :microsecond)} end)
    GenServer.call(__MODULE__, {:consume_many, entries}, 5_000)
  catch
    :exit, _reason -> {:error, :replay_cache_unavailable}
  end

  @impl GenServer
  def handle_call({:consume, id, expires}, from, state) do
    handle_call({:consume_many, [{id, expires * 1_000_000}]}, from, state)
  end

  def handle_call({:consume_many, entries}, _from, {table, limit} = state) do
    now = System.system_time(:microsecond)
    entries = Enum.uniq_by(entries, &elem(&1, 0))

    result =
      cond do
        entries == [] or Enum.any?(entries, fn {_id, expires} -> expires <= now end) ->
          {:error, :expired_message}

        Enum.any?(entries, fn {id, _expires} -> :ets.member(table, id) end) ->
          {:error, :replayed}

        :ets.info(table, :size) + length(entries) > limit ->
          {:error, :replay_cache_full}

        true ->
          true = :ets.insert_new(table, entries)
          :ok
      end

    {:reply, result, state}
  end

  @impl GenServer
  def handle_info(:prune, {table, _limit} = state) do
    now = System.system_time(:microsecond)
    :ets.select_delete(table, [{{:"$1", :"$2"}, [{:"=<", :"$2", now}], [true]}])
    Process.send_after(self(), :prune, 60_000)
    {:noreply, state}
  end
end
