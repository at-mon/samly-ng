defmodule Samly.AtomAndReplayTest do
  use ExUnit.Case, async: false

  alias Samly.ReplayCache
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
    cache = start_supervised!(%{id: :bounded_cache, start: {GenServer, :start_link, [Samly.ReplayCache.ETS, [max_entries: 1]]}})
    expires = System.system_time(:second) + 300
    assert :ok = GenServer.call(cache, {:consume, "first", expires})
    assert {:error, :replay_cache_full} = GenServer.call(cache, {:consume, "second", expires})
    assert {:error, :replayed} = GenServer.call(cache, {:consume, "first", expires})
    assert {:error, :expired_message} = GenServer.call(cache, {:consume, "expired", expires - 600})
    send(cache, :prune)
    assert {:error, :replayed} = GenServer.call(cache, {:consume, "first", expires})
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
