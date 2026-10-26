defmodule Samly.State.ETS do
  @moduledoc """
  Stores authenticated assertions in bounded, node-local ETS storage.

  A supervised owner creates the protected table and serializes mutations.
  Reads do not call the owner and fail closed while storage is unavailable.
  Owner or node restarts discard sessions and require reauthentication.

  ## Options

  * `:table` - Predefined atom table name, default `:samly_assertions_table`.
  * `:max_entries` - Maximum live sessions, default `10_000`.
    Full storage rejects new sessions without evicting live sessions.
  * `:cleanup_interval_ms` - Expired-entry cleanup interval, default `60_000`.

  Store keys are `{idp_id, opaque_session_id}`, never NameIDs.
  Do not depend on the internal table layout.
  Use a shared authoritative store when sessions must survive node restarts or
  logout must reach sessions on other nodes.
  """

  @behaviour Samly.State.Store

  alias Samly.Assertion
  alias Samly.State.ETS.Owner
  alias Samly.State.Lifetime
  alias Samly.State.Selector
  alias Samly.State.Store

  @assertions_table :samly_assertions_table
  @default_max_entries 10_000
  @default_cleanup_interval_ms 60_000

  @impl Store
  def init(opts) do
    config = %{
      table: Keyword.get(opts, :table, @assertions_table),
      max_entries: Keyword.get(opts, :max_entries, @default_max_entries),
      cleanup_interval_ms: Keyword.get(opts, :cleanup_interval_ms, @default_cleanup_interval_ms)
    }

    validate_config!(config)
    child = Supervisor.child_spec({Owner, Map.to_list(config)}, id: config.table)

    case Supervisor.start_child(Samly.State.Supervisor, child) do
      {:ok, _pid} -> config.table
      {:error, {:already_started, _pid}} -> existing_table!(config)
      _ -> raise "Samly.State.ETS storage initialization failed"
    end
  end

  @impl Store
  def get_assertion(_conn, nil, _table), do: nil

  def get_assertion(_conn, assertion_key, table) do
    case :ets.lookup(table, assertion_key) do
      [{^assertion_key, %Assertion{} = assertion, _deadline}] -> Lifetime.valid_assertion(assertion)
      _ -> nil
    end
  rescue
    ArgumentError -> nil
  end

  @impl Store
  def put_assertion(conn, assertion_key, assertion, table) do
    validate_key!(assertion_key)
    table |> Owner.request({:put, assertion_key, assertion}) |> mutation_result!()
    conn
  end

  @impl Store
  def delete_assertion(conn, nil, _table), do: conn

  def delete_assertion(conn, assertion_key, table) do
    table |> Owner.request({:delete, assertion_key}) |> mutation_result!()
    conn
  end

  @impl Store
  def revoke_assertions(conn, selector, table) do
    if !Selector.valid?(selector), do: raise(ArgumentError, "Invalid assertion revocation selector")

    case Owner.request(table, {:revoke, selector}) do
      {:ok, revoked} -> {conn, revoked}
      error -> mutation_result!(error)
    end
  end

  defp validate_config!(%{table: table, max_entries: maximum, cleanup_interval_ms: interval})
       when is_atom(table) and table not in [nil, true, false] and is_integer(maximum) and maximum > 0 and is_integer(interval) and interval > 0, do: :ok

  defp validate_config!(_), do: raise(ArgumentError, "Samly.State.ETS requires an atom table and positive capacity and cleanup interval")

  defp validate_key!({idp, session}) when is_binary(idp) and byte_size(idp) > 0 and is_binary(session) and byte_size(session) > 0, do: :ok
  defp validate_key!(_), do: raise(ArgumentError, "Invalid assertion storage key")

  defp existing_table!(config) do
    case Owner.request(config.table, :configuration) do
      ^config -> config.table
      _ -> raise "Samly.State.ETS table already initialized with different options"
    end
  end

  defp mutation_result!(:ok), do: :ok
  defp mutation_result!({:error, :capacity}), do: raise("Samly.State.ETS capacity exceeded")
  defp mutation_result!({:error, :expired_assertion}), do: raise("Samly.State.ETS cannot store an expired or invalid assertion")
  defp mutation_result!({:error, :unavailable}), do: raise("Samly.State.ETS storage unavailable")
end
