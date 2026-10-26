defmodule Samly.State.ETS.Owner do
  @moduledoc false
  use GenServer

  alias Samly.State.Lifetime
  alias Samly.State.Selector

  @call_timeout 5_000

  @doc false
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc false
  @spec request(atom(), term()) :: term()
  def request(table, message) do
    case :ets.info(table, :owner) do
      :undefined -> {:error, :unavailable}
      owner -> call(owner, message)
    end
  end

  # This transport boundary discards call arguments from exit reasons: requests
  # contain authenticated assertions and must never appear in request crash logs.
  defp call(owner, message) do
    GenServer.call(owner, message, @call_timeout)
  catch
    :exit, _reason -> {:error, :unavailable}
  end

  @impl true
  def init(opts) do
    table = :ets.new(Keyword.fetch!(opts, :table), [:named_table, :protected, :set, read_concurrency: true])
    subjects = :ets.new(:subjects, [:private, :bag])
    expirations = :ets.new(:expirations, [:private, :ordered_set])
    interval = Keyword.fetch!(opts, :cleanup_interval_ms)

    {:ok, %{table: table, subjects: subjects, expirations: expirations, max_entries: Keyword.fetch!(opts, :max_entries), cleanup_interval_ms: interval, timer: schedule_prune(interval)}}
  end

  @impl true
  def handle_call(:configuration, _from, state) do
    {:reply, Map.take(state, [:table, :max_entries, :cleanup_interval_ms]), state}
  end

  def handle_call({:put, key, assertion}, _from, state) do
    now = System.system_time(:microsecond)
    prune(state, now)
    {:reply, put(state, key, assertion, now), state}
  end

  def handle_call({:delete, key}, _from, state) do
    delete(state, key)
    {:reply, :ok, state}
  end

  def handle_call({:revoke, selector}, _from, state) do
    prune(state, System.system_time(:microsecond))
    subject_key = Selector.subject_key(selector.idp_id, selector.subject)

    revoked =
      state.subjects
      |> :ets.lookup(subject_key)
      |> Enum.flat_map(fn {^subject_key, key} -> revoke_entry(state, key, selector) end)

    {:reply, {:ok, revoked}, state}
  end

  @impl true
  def handle_info({:timeout, timer, :prune}, %{timer: timer} = state) do
    prune(state, System.system_time(:microsecond))
    {:noreply, %{state | timer: schedule_prune(state.cleanup_interval_ms)}}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def format_status(status) do
    status
    |> Map.put(:state, :redacted)
    |> Map.put(:message, :redacted)
    |> Map.put(:reason, :redacted)
    |> Map.put(:log, [])
  end

  defp put(state, key, assertion, now) do
    with {:ok, deadline} when deadline > now <- Lifetime.expires_at(assertion),
         :ok <- capacity(state, key) do
      delete(state, key)
      :ets.insert(state.table, {key, assertion, deadline})
      :ets.insert(state.subjects, {Selector.subject_key(elem(key, 0), assertion.subject), key})
      :ets.insert(state.expirations, {{deadline, key}})
      :ok
    else
      {:error, _reason} = error -> error
      _ -> {:error, :expired_assertion}
    end
  end

  defp capacity(state, key) do
    if :ets.member(state.table, key) or :ets.info(state.table, :size) < state.max_entries do
      :ok
    else
      {:error, :capacity}
    end
  end

  defp delete(state, key) do
    case :ets.take(state.table, key) do
      [{^key, assertion, deadline}] ->
        :ets.delete_object(state.subjects, {Selector.subject_key(elem(key, 0), assertion.subject), key})
        :ets.delete(state.expirations, {deadline, key})

      [] ->
        :ok
    end
  end

  defp revoke_entry(state, key, selector) do
    case :ets.lookup(state.table, key) do
      [{^key, assertion, _deadline}] ->
        if Selector.matches?(key, assertion, selector) do
          delete(state, key)
          [{key, assertion}]
        else
          []
        end

      [] ->
        []
    end
  end

  defp prune(state, now) do
    case :ets.first(state.expirations) do
      {deadline, key} when deadline <= now ->
        delete(state, key)
        prune(state, now)

      _ ->
        :ok
    end
  end

  defp schedule_prune(interval), do: :erlang.start_timer(interval, self(), :prune)
end
