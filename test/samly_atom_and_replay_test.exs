defmodule Samly.AtomAndReplayTest do
  use ExUnit.Case, async: false

  alias Samly.ReplayCache
  alias Samly.ReplayCache.ETS
  alias Samly.SAML.XML

  test "replay protection survives the process handling the first request" do
    id = "request-#{System.unique_integer([:positive])}"
    expiry = DateTime.shift(DateTime.utc_now(), minute: 5)
    assert :ok == fn -> ReplayCache.consume(id, expiry) end |> Task.async() |> Task.await()
    assert {:error, :replayed} == ReplayCache.consume(id, expiry)
  end

  test "concurrent requests can consume a message only once" do
    id = "concurrent-#{System.unique_integer([:positive])}"
    expiry = DateTime.shift(DateTime.utc_now(), minute: 5)

    results =
      1..32
      |> Task.async_stream(fn _ -> ReplayCache.consume(id, expiry) end)
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &(&1 == :ok)) == 1
    assert Enum.count(results, &(&1 == {:error, :replayed})) == 31
  end

  test "a full replay cache rejects new messages without evicting existing protection" do
    cache = start_supervised!(%{id: :bounded_cache, start: {GenServer, :start_link, [ETS, [max_entries: 1]]}})
    expires = System.system_time(:second) + 300
    assert :ok = GenServer.call(cache, {:consume, "first", expires})
    assert {:error, :replay_cache_full} = GenServer.call(cache, {:consume, "second", expires})
    assert {:error, :replayed} = GenServer.call(cache, {:consume, "first", expires})
    assert {:error, :expired_message} = GenServer.call(cache, {:consume, "expired", expires - 600})
    send(cache, :prune)
    assert {:error, :replayed} = GenServer.call(cache, {:consume, "first", expires})
  end

  test "batch replay consumption is all or nothing" do
    suffix = Samly.State.gen_id()
    expires = DateTime.shift(DateTime.utc_now(), minute: 5)
    assert :ok = ReplayCache.consume("existing" <> suffix, expires)
    assert {:error, :replayed} = ReplayCache.consume_many([{"new" <> suffix, expires}, {"existing" <> suffix, expires}])
    assert :ok = ReplayCache.consume("new" <> suffix, expires)
  end

  test "overlapping concurrent replay batches have one winner" do
    suffix = Samly.State.gen_id()
    expires = DateTime.shift(DateTime.utc_now(), minute: 5)
    results = 1..16 |> Task.async_stream(fn index -> ReplayCache.consume_many([{"shared" <> suffix, expires}, {"unique#{index}" <> suffix, expires}]) end) |> Enum.map(fn {:ok, result} -> result end)
    assert Enum.count(results, &(&1 == :ok)) == 1
    assert Enum.count(results, &(&1 == {:error, :replayed})) == 15
  end

  test "replay deadlines preserve timestamp precision" do
    expires = %{DateTime.shift(DateTime.utc_now(), minute: 5) | microsecond: {123_456, 6}}
    key = Samly.State.gen_id()
    assert :ok = ReplayCache.consume(key, expires)
    {table, _} = :sys.get_state(ETS)
    assert [{_, deadline}] = :ets.lookup(table, :crypto.hash(:sha256, key))
    assert deadline == DateTime.to_unix(expires, :microsecond)
  end

  test "batch capacity failure does not reserve any of the submitted keys" do
    cache = start_supervised!(%{id: :small_cache, start: {GenServer, :start_link, [ETS, [max_entries: 1]]}})
    expires = System.system_time(:microsecond) + 300_000_000
    assert {:error, :replay_cache_full} = GenServer.call(cache, {:consume_many, [{"one", expires}, {"two", expires}]})
    assert :ok = GenServer.call(cache, {:consume_many, [{"one", expires}]})
  end

  defmodule SingletonCache do
    @moduledoc false
    @behaviour ReplayCache

    @impl true
    def consume(key, _expires) do
      send(self(), {:consumed, key})
      :ok
    end
  end

  test "legacy custom stores support singletons but cannot emulate atomic batches" do
    previous = Application.fetch_env(:samly, :replay_cache)

    on_exit(fn ->
      case previous do
        {:ok, provider} -> Application.put_env(:samly, :replay_cache, provider)
        :error -> Application.delete_env(:samly, :replay_cache)
      end
    end)

    Application.put_env(:samly, :replay_cache, SingletonCache)
    expires = DateTime.shift(DateTime.utc_now(), minute: 5)
    assert :ok = ReplayCache.consume("one", expires)
    assert_receive {:consumed, key}, 100
    assert key == :crypto.hash(:sha256, "one")
    assert {:error, :atomic_replay_cache_required} = ReplayCache.consume_many([{"two", expires}, {"three", expires}])
    refute_receive {:consumed, _}, 20
  end

  test "untrusted XML names and values remain binaries without growing the atom table" do
    parse_unique = fn index ->
      name = "untrusted_#{index}"

      assert {:ok, {^name, [{^name, ^name}], [^name]}} =
               XML.parse("<#{name} #{name}=\"#{name}\">#{name}</#{name}>")
    end

    # Warm lazy-loaded code before measuring, and run outside asynchronous tests.
    Enum.each(1..100, parse_unique)
    before_count = :erlang.system_info(:atom_count)
    Enum.each(101..10_100, parse_unique)
    assert :erlang.system_info(:atom_count) == before_count
  end
end
