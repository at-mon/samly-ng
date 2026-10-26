defmodule Samly.State do
  @moduledoc """
  Dispatches authenticated assertion storage to the configured store.

  Configure `:store` and `:opts` under `config :samly, Samly.State`.
  `Samly.Provider` initializes the store; this is separate from browser session
  middleware and from the one-time-use protection in `Samly.ReplayCache`.
  Custom stores implement `Samly.State.Store` with opaque per-login session keys.
  """

  alias Plug.Conn
  alias Samly.Assertion
  alias Samly.State.Selector
  alias Samly.State.Store

  @state_store :state_store

  @doc false
  @spec init(module(), keyword()) :: :ok
  def init(store_provider, opts \\ []) do
    opts = store_provider.init(opts)
    Application.put_env(:samly, @state_store, %{provider: store_provider, opts: opts})
  end

  @doc false
  @spec assertion_key(Conn.t()) :: Store.assertion_key() | nil
  def assertion_key(conn) do
    case Conn.get_session(conn, "samly_session") do
      {:v1, idp_id, session_id} when is_binary(idp_id) and byte_size(idp_id) > 0 and is_binary(session_id) and byte_size(session_id) > 0 -> {idp_id, session_id}
      _ -> nil
    end
  end

  @doc false
  @spec get_assertion(Conn.t(), Store.assertion_key() | nil) :: Assertion.t() | nil
  def get_assertion(_conn, nil), do: nil

  def get_assertion(conn, assertion_key) do
    case Application.get_env(:samly, @state_store) do
      %{provider: store_provider, opts: opts} -> store_provider.get_assertion(conn, assertion_key, opts)
      nil -> nil
    end
  end

  @doc false
  @spec put_assertion(Conn.t(), Store.assertion_key(), Assertion.t()) :: Conn.t() | no_return()
  def put_assertion(conn, assertion_key, assertion) do
    %{provider: store_provider, opts: opts} = Application.fetch_env!(:samly, @state_store)
    store_provider.put_assertion(conn, assertion_key, assertion, opts)
  end

  @doc false
  @spec delete_assertion(Conn.t(), Store.assertion_key() | nil) :: Conn.t() | no_return()
  def delete_assertion(conn, nil), do: conn

  def delete_assertion(conn, assertion_key) do
    %{provider: store_provider, opts: opts} = Application.fetch_env!(:samly, @state_store)
    store_provider.delete_assertion(conn, assertion_key, opts)
  end

  @doc false
  @spec revoke_assertions(Conn.t(), Store.selector()) :: {Conn.t(), [{Store.assertion_key(), Assertion.t()}]} | no_return()
  def revoke_assertions(conn, selector) do
    if !Selector.valid?(selector), do: raise(ArgumentError, "Invalid assertion revocation selector")
    %{provider: store_provider, opts: opts} = Application.fetch_env!(:samly, @state_store)

    if function_exported?(store_provider, :revoke_assertions, 3) do
      store_provider.revoke_assertions(conn, selector, opts)
    else
      raise "State store must implement revoke_assertions/3 for IdP logout; migrate the custom adapter"
    end
  end

  @doc false
  @spec gen_id() :: binary()
  def gen_id do
    24 |> :crypto.strong_rand_bytes() |> Base.url_encode64()
  end
end
