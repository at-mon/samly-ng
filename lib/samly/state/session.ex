defmodule Samly.State.Session do
  @moduledoc """
  Stores an authenticated assertion directly in the Plug session.

  This adapter is stateless and has no server-side revocation authority.
  Logout removes only the assertion in the supplied browser session: a copied
  cookie remains valid until its assertion expires, and cookie-less IdP logout
  cannot revoke sessions in other browsers.
  Use ETS or an authoritative shared custom store when reliable revocation is required.

  ## Options

  * `:key` - Binary or atom session key, default `"samly_assertion"`.
  """

  @behaviour Samly.State.Store

  alias Plug.Conn
  alias Samly.Assertion
  alias Samly.State.Lifetime
  alias Samly.State.Selector
  alias Samly.State.Store

  @session_key "samly_assertion"

  @impl Store
  def init(opts) do
    key = Keyword.get(opts, :key, @session_key)
    if !(is_binary(key) or is_atom(key)), do: raise(ArgumentError, "Samly.State.Session key must be a binary or atom")
    %{key: key}
  end

  @impl Store
  def get_assertion(_conn, nil, _opts), do: nil

  def get_assertion(conn, assertion_key, %{key: key}) do
    case Conn.get_session(conn, key) do
      {^assertion_key, %Assertion{} = assertion} -> Lifetime.valid_assertion(assertion)
      _ -> nil
    end
  end

  @impl Store
  def put_assertion(conn, assertion_key, assertion, %{key: key}) do
    case Lifetime.valid_assertion(assertion) do
      %Assertion{} -> Conn.put_session(conn, key, {assertion_key, assertion})
      nil -> raise "Samly.State.Session cannot store an expired or invalid assertion"
    end
  end

  @impl Store
  def delete_assertion(conn, assertion_key, %{key: key}) do
    case Conn.get_session(conn, key) do
      {^assertion_key, _assertion} -> Conn.delete_session(conn, key)
      _ -> conn
    end
  end

  @impl Store
  def revoke_assertions(conn, selector, %{key: key}) do
    if !Selector.valid?(selector), do: raise(ArgumentError, "Invalid assertion revocation selector")

    case Conn.get_session(conn, key) do
      {assertion_key, %Assertion{} = assertion} ->
        if Selector.matches?(assertion_key, assertion, selector) do
          {Conn.delete_session(conn, key), [{assertion_key, assertion}]}
        else
          {conn, []}
        end

      _ ->
        {conn, []}
    end
  end
end
