Code.require_file("support/state_fixture.exs", __DIR__)

defmodule Samly.StateTest.LegacyStore do
  @moduledoc false
  @behaviour Samly.State.Store

  @impl true
  def init(opts), do: opts
  @impl true
  def get_assertion(_conn, _key, _opts), do: nil
  @impl true
  def put_assertion(conn, _key, _assertion, _opts), do: conn
  @impl true
  def delete_assertion(conn, _key, _opts), do: conn
end

defmodule Samly.StateTest do
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test
  import Samly.Test.StateFixture

  alias Samly.State
  alias Samly.State.ETS
  alias Samly.State.ETS.Owner
  alias Samly.State.Session

  @table :samly_state_unit_test

  setup do
    previous = Application.fetch_env(:samly, :state_store)
    on_exit(fn -> restore_env(:state_store, previous) end)
    %{conn: init_test_session(conn(:get, "/"), %{})}
  end

  describe "browser locator" do
    test "accepts only a nonempty versioned opaque session locator", %{conn: conn} do
      assert State.assertion_key(put_session(conn, "samly_session", {:v1, "idp1", "opaque"})) == {"idp1", "opaque"}
      assert State.assertion_key(put_session(conn, "samly_assertion_key", {"idp1", "name"})) == nil

      for locator <- [nil, {"idp1", "name"}, {:v2, "idp1", "opaque"}, {:v1, "", "opaque"}, {:v1, "idp1", ""}, {:v1, :idp, "opaque"}, ["idp1", "opaque"]] do
        assert State.assertion_key(put_session(conn, "samly_session", locator)) == nil
      end
    end

    test "nil lookups do not invoke or require a store", %{conn: conn} do
      Application.delete_env(:samly, :state_store)
      assert State.get_assertion(conn, nil) == nil
    end

    test "legacy adapters explicitly reject unsupported logout revocation", %{conn: conn} do
      State.init(Samly.StateTest.LegacyStore)

      assert_raise RuntimeError, ~r/revoke_assertions\/3/, fn ->
        State.revoke_assertions(conn, selector(assertion()))
      end
    end
  end

  for store <- [Session, ETS] do
    describe "#{inspect(store)}" do
      setup do
        opts =
          case unquote(store) do
            ETS -> [table: @table]
            Session -> []
          end

        State.init(unquote(store), opts)
        on_exit(fn -> stop_table(@table) end)
        :ok
      end

      test "round trips and removes an opaque session", %{conn: conn} do
        assertion = assertion()
        key = {"idp1", State.gen_id()}
        conn = State.put_assertion(conn, key, assertion)
        assert State.get_assertion(conn, key) == assertion
        assert State.get_assertion(conn, {"idp1", "unknown"}) == nil
        assert State.get_assertion(State.delete_assertion(conn, key), key) == nil
      end

      test "nil keys and malformed lifetimes fail closed", %{conn: conn} do
        key = {"idp1", State.gen_id()}
        assert State.get_assertion(conn, nil) == nil

        for invalid <- [%Samly.Assertion{}, assertion(expires_in: -60), assertion(authn: %{"session_not_on_or_after" => "bad"})] do
          assert_raise RuntimeError, fn -> State.put_assertion(conn, key, invalid) end
          assert State.get_assertion(conn, key) == nil
        end
      end

      test "authn session expiry caps but never extends subject expiry", %{conn: conn} do
        key = {"idp1", State.gen_id()}
        expired_session = assertion(authn: %{"session_not_on_or_after" => timestamp(-60)})
        expired_subject = assertion(expires_in: -60, authn: %{"session_not_on_or_after" => timestamp(7200)})

        for invalid <- [expired_session, expired_subject] do
          assert_raise RuntimeError, fn -> State.put_assertion(conn, key, invalid) end
        end

        valid = assertion(authn: %{"session_not_on_or_after" => timestamp(1800)})
        assert State.get_assertion(State.put_assertion(conn, key, valid), key) == valid
      end

      test "revocation matches exact qualified subject and any requested index", %{conn: conn} do
        assertion = assertion(name_format: "urn:format", name_qualifier: "issuer", sp_name_qualifier: "sp")
        key = {"idp1", State.gen_id()}
        conn = State.put_assertion(conn, key, assertion)

        for field <- [:name, :name_format, :name_qualifier, :sp_name_qualifier] do
          subject = Map.put(assertion.subject, field, "different")
          assert {^conn, []} = State.revoke_assertions(conn, %{selector(assertion) | subject: subject})
          assert State.get_assertion(conn, key) == assertion
        end

        assert {^conn, []} = State.revoke_assertions(conn, selector(assertion, ["other"]))
        assert {^conn, []} = State.revoke_assertions(conn, %{selector(assertion) | idp_id: "other"})
        assert {updated, [{^key, ^assertion}]} = State.revoke_assertions(conn, selector(assertion, ["other", "index1"]))
        assert State.get_assertion(updated, key) == nil
      end

      test "revocation considers every authenticated session index", %{conn: conn} do
        assertion = assertion(authn: %{"session_index" => "first", "session_indexes" => ["first", "second"]})
        key = {"idp1", State.gen_id()}
        conn = State.put_assertion(conn, key, assertion)
        assert {updated, [{^key, ^assertion}]} = State.revoke_assertions(conn, selector(assertion, ["second"]))
        assert State.get_assertion(updated, key) == nil
      end

      test "invalid selectors never broaden revocation", %{conn: conn} do
        key = {"idp1", State.gen_id()}
        assertion = assertion()
        conn = State.put_assertion(conn, key, assertion)

        for invalid <- [%{}, %{selector(assertion) | session_indexes: [""]}, %{selector(assertion) | subject: %Samly.Subject{}}] do
          assert_raise ArgumentError, fn -> State.revoke_assertions(conn, invalid) end
          assert State.get_assertion(conn, key) == assertion
        end
      end

      test "missing qualifiers normalize consistently and empty index selection matches all", %{conn: conn} do
        assertion = assertion(name_format: nil, name_qualifier: "", sp_name_qualifier: :undefined)
        key = {"idp1", State.gen_id()}
        conn = State.put_assertion(conn, key, assertion)
        selector = %{selector(assertion) | subject: %Samly.Subject{name: assertion.subject.name}}
        assert {updated, [{^key, ^assertion}]} = State.revoke_assertions(conn, selector)
        assert State.get_assertion(updated, key) == nil
      end
    end
  end

  describe "stateless session limitations" do
    setup do
      State.init(Session)
      :ok
    end

    test "logout can only affect the supplied browser entry, not a copied cookie", %{conn: conn} do
      key = {"idp1", State.gen_id()}
      assertion = assertion()
      original = State.put_assertion(conn, key, assertion)
      assert {logged_out, [{^key, ^assertion}]} = State.revoke_assertions(original, selector(assertion))
      assert State.get_assertion(logged_out, key) == nil
      assert State.get_assertion(original, key) == assertion
      assert {^conn, []} = State.revoke_assertions(conn, selector(assertion))
    end

    test "deleting a different session key leaves the current entry intact", %{conn: conn} do
      key = {"idp1", State.gen_id()}
      assertion = assertion()
      conn = State.put_assertion(conn, key, assertion)
      updated = State.delete_assertion(conn, {"idp1", "unrelated"})
      assert State.get_assertion(updated, key) == assertion
    end
  end

  describe "authoritative ETS sessions" do
    setup do
      State.init(ETS, table: @table, max_entries: 2)
      on_exit(fn -> stop_table(@table) end)
      :ok
    end

    test "same subject sessions retain independent attributes and revocation reaches absent browsers", %{conn: conn} do
      first = assertion(attributes: %{"role" => "first"})
      second = assertion(attributes: %{"role" => "second"}, authn: %{"session_index" => "index2"})
      key1 = {"idp1", State.gen_id()}
      key2 = {"idp1", State.gen_id()}
      State.put_assertion(conn, key1, first)
      State.put_assertion(conn, key2, second)
      assert State.get_assertion(conn, key1) == first
      assert State.get_assertion(conn, key2) == second
      assert {^conn, [{^key1, ^first}]} = State.revoke_assertions(conn, selector(first, ["index1"]))
      assert State.get_assertion(conn, key1) == nil
      assert State.get_assertion(conn, key2) == second
      assert {^conn, [{^key2, ^second}]} = State.revoke_assertions(conn, selector(first))
    end

    test "capacity rejects writes without evicting live assertions", %{conn: conn} do
      assertion = assertion()
      key1 = {"idp1", State.gen_id()}
      key2 = {"idp1", State.gen_id()}
      key3 = {"idp1", State.gen_id()}
      State.put_assertion(conn, key1, assertion)
      State.put_assertion(conn, key2, assertion)
      assert_raise RuntimeError, ~r/capacity/, fn -> State.put_assertion(conn, key3, assertion) end
      assert State.get_assertion(conn, key1) == assertion
      assert State.get_assertion(conn, key2) == assertion
      assert State.get_assertion(conn, key3) == nil
    end

    test "concurrent writes cannot exceed capacity", %{conn: conn} do
      results =
        1..20
        |> Task.async_stream(
          fn _ ->
            key = {"idp1", State.gen_id()}

            try do
              State.put_assertion(conn, key, assertion())
              :stored
            rescue
              error in RuntimeError ->
                assert error.message =~ "capacity"
                :rejected
            end
          end,
          max_concurrency: 10,
          timeout: 5_000,
          ordered: false
        )
        |> Enum.frequencies()

      assert results == %{{:ok, :stored} => 2, {:ok, :rejected} => 18}
      assert :ets.info(@table, :size) == 2
    end

    test "overlapping revocations return each removed session only once", %{conn: conn} do
      assertion = assertion()
      keys = for _ <- 1..2, do: {"idp1", State.gen_id()}
      Enum.each(keys, &State.put_assertion(conn, &1, assertion))

      revoked =
        1..10
        |> Task.async_stream(fn _ -> State.revoke_assertions(conn, selector(assertion)) end, timeout: 5_000, ordered: false)
        |> Enum.flat_map(fn {:ok, {_conn, rows}} -> rows end)

      assert Enum.sort(Enum.map(revoked, &elem(&1, 0))) == Enum.sort(keys)
      assert :ets.info(@table, :size) == 0
    end

    test "replacing an entry removes its old subject index", %{conn: conn} do
      key = {"idp1", State.gen_id()}
      old = assertion(name: "old")
      replacement = assertion(name: "new")
      State.put_assertion(conn, key, old)
      State.put_assertion(conn, key, replacement)
      assert {^conn, []} = State.revoke_assertions(conn, selector(old))
      assert State.get_assertion(conn, key) == replacement
      assert {^conn, [{^key, ^replacement}]} = State.revoke_assertions(conn, selector(replacement))
    end

    test "owner restart invalidates old sessions without a request-owned replacement", %{conn: conn} do
      key = {"idp1", State.gen_id()}
      State.put_assertion(conn, key, assertion())
      old_owner = :ets.info(@table, :owner)
      assert :ok = Supervisor.terminate_child(Samly.State.Supervisor, @table)
      assert State.get_assertion(conn, key) == nil
      assert {:ok, new_owner} = Supervisor.restart_child(Samly.State.Supervisor, @table)
      refute old_owner == new_owner
      assert State.get_assertion(conn, key) == nil
      replacement_key = {"idp1", State.gen_id()}
      State.put_assertion(conn, replacement_key, assertion())
      assert State.get_assertion(conn, key) == nil
    end

    test "reads proceed while mutation owner is suspended", %{conn: conn} do
      key = {"idp1", State.gen_id()}
      assertion = assertion()
      State.put_assertion(conn, key, assertion)
      owner = :ets.info(@table, :owner)
      :ok = :sys.suspend(owner, 1_000)

      try do
        assert State.get_assertion(conn, key) == assertion
      after
        :sys.resume(owner, 1_000)
      end
    end

    test "the table is protected and is owned by a supervised process", %{conn: conn} do
      owner = :ets.info(@table, :owner)
      assert is_pid(owner)
      refute owner == self()
      assert :ets.info(@table, :protection) == :protected
      assert Enum.any?(Supervisor.which_children(Samly.State.Supervisor), fn {_, pid, _, _} -> pid == owner end)
      assert_raise ArgumentError, fn -> :ets.insert(@table, {{"idp1", "forged"}, assertion()}) end
      assert State.get_assertion(conn, {"idp1", "forged"}) == nil
    end

    test "unavailable tables fail closed for reads and fail writes", %{conn: conn} do
      stop_table(@table)
      key = {"idp1", State.gen_id()}
      assert State.get_assertion(conn, key) == nil
      assert_raise RuntimeError, ~r/unavailable/, fn -> State.put_assertion(conn, key, assertion()) end
      assert_raise RuntimeError, ~r/unavailable/, fn -> State.revoke_assertions(conn, selector(assertion())) end
    end
  end

  describe "ETS expiry cleanup" do
    setup do
      State.init(ETS, table: @table, max_entries: 1, cleanup_interval_ms: 60_000)
      on_exit(fn -> stop_table(@table) end)
      :ok
    end

    test "reads expire immediately and scheduled cleanup removes assertions and indexes", %{conn: conn} do
      key = {"idp1", State.gen_id()}
      assertion = assertion(expires_in: 1)
      State.put_assertion(conn, key, assertion)
      owner = :ets.info(@table, :owner)
      %{timer: timer} = :sys.get_state(owner, 1_000)
      assert is_integer(:erlang.read_timer(timer))
      await_expiry(assertion)
      assert State.get_assertion(conn, key) == nil
      assert :ets.info(@table, :size) == 1
      :erlang.cancel_timer(timer)
      send(owner, {:timeout, timer, :prune})
      assert %{table: @table} = Owner.request(@table, :configuration)
      assert :ets.info(@table, :size) == 0
      assert {^conn, []} = State.revoke_assertions(conn, selector(assertion))
    end

    test "capacity admission prunes expired entries before rejecting a new session", %{conn: conn} do
      key = {"idp1", State.gen_id()}
      assertion = assertion(expires_in: 1)
      State.put_assertion(conn, key, assertion)
      await_expiry(assertion)
      new_key = {"idp1", State.gen_id()}
      live = assertion()
      assert State.put_assertion(conn, new_key, live) == conn
      assert State.get_assertion(conn, new_key) == live
      assert State.get_assertion(conn, key) == nil
      assert :ets.info(@table, :size) == 1
    end
  end

  describe "owner status redaction" do
    test "sensitive state, messages, reasons and log events are hidden" do
      status = %{state: %{secret: "SECRET"}, message: {:put, "TOKEN"}, reason: {"SECRET", "TOKEN"}, log: ["SECRET"], name: :owner}
      sanitized = Owner.format_status(status)
      refute inspect(sanitized) =~ "SECRET"
      refute inspect(sanitized) =~ "TOKEN"
      assert sanitized.name == :owner
      assert Samly.Provider.format_status(status) == sanitized
    end
  end

  defp await_expiry(assertion) do
    {:ok, expiry, _} = DateTime.from_iso8601(assertion.subject.notonorafter)
    wait_ms = max(0, DateTime.diff(expiry, DateTime.utc_now(), :millisecond)) + 10
    ref = make_ref()
    Process.send_after(self(), {:expired, ref}, wait_ms)
    assert_receive {:expired, ^ref}, wait_ms + 1_000
  end

  defp stop_table(table) do
    case :ets.info(table, :owner) do
      :undefined ->
        :ok

      owner when owner == self() ->
        :ets.delete(table)

      _owner ->
        Supervisor.terminate_child(Samly.State.Supervisor, table)
        Supervisor.delete_child(Samly.State.Supervisor, table)
    end
  end
end
