defmodule Samly.StateTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  describe "With Session Cache" do
    setup do
      opts =
        Plug.Session.init(
          store: :cookie,
          key: "_samly_state_test_session",
          encryption_salt: "salty enc",
          signing_salt: "salty signing",
          key_length: 64
        )

      Samly.State.init(Samly.State.Session)

      conn =
        :get
        |> conn("/")
        |> Plug.Session.call(opts)
        |> fetch_session()

      [conn: conn]
    end

    test "put/get assertion", %{conn: conn} do
      not_on_or_after = DateTime.utc_now() |> DateTime.shift(hour: 8) |> DateTime.to_iso8601()
      assertion = %Samly.Assertion{subject: %{notonorafter: not_on_or_after}}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert assertion == Samly.State.get_assertion(conn, assertion_key)
    end

    test "get failure for unknown assertion key", %{conn: conn} do
      assertion = %Samly.Assertion{}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert is_nil(Samly.State.get_assertion(conn, {"idp1", "name2"}))
    end

    test "get failure for expired assertion key", %{conn: conn} do
      assertion = %Samly.Assertion{}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert is_nil(Samly.State.get_assertion(conn, {"idp1", "name1"}))
    end

    test "delete assertion", %{conn: conn} do
      not_on_or_after = DateTime.utc_now() |> DateTime.shift(hour: 8) |> DateTime.to_iso8601()
      assertion = %Samly.Assertion{subject: %{notonorafter: not_on_or_after}}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert assertion == Samly.State.get_assertion(conn, assertion_key)
      conn = Samly.State.delete_assertion(conn, assertion_key)
      assert is_nil(Samly.State.get_assertion(conn, assertion_key))
    end
  end

  describe "With ETS Cache" do
    setup do
      Samly.State.init(Samly.State.ETS)
      [conn: conn(:get, "/")]
    end

    test "put/get assertion", %{conn: conn} do
      not_on_or_after = DateTime.utc_now() |> DateTime.shift(hour: 8) |> DateTime.to_iso8601()
      assertion = %Samly.Assertion{subject: %{notonorafter: not_on_or_after}}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert assertion == Samly.State.get_assertion(conn, assertion_key)
    end

    test "get failure for unknown assertion key", %{conn: conn} do
      assertion = %Samly.Assertion{}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert is_nil(Samly.State.get_assertion(conn, {"idp1", "name2"}))
    end

    test "get failure for expired assertion key", %{conn: conn} do
      assertion = %Samly.Assertion{}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert is_nil(Samly.State.get_assertion(conn, {"idp1", "name1"}))
    end

    test "delete assertion", %{conn: conn} do
      not_on_or_after = DateTime.utc_now() |> DateTime.shift(hour: 8) |> DateTime.to_iso8601()
      assertion = %Samly.Assertion{subject: %{notonorafter: not_on_or_after}}
      assertion_key = {"idp1", "name1"}
      conn = Samly.State.put_assertion(conn, assertion_key, assertion)
      assert assertion == Samly.State.get_assertion(conn, assertion_key)
      conn = Samly.State.delete_assertion(conn, assertion_key)
      assert is_nil(Samly.State.get_assertion(conn, assertion_key))
    end
  end
end
