defmodule Samly.State.Store do
  @moduledoc """
  Specification for authenticated assertion stores.

  Keys contain a fresh opaque session ID, not the subject's NameID.
  Custom stores must preserve independent sessions for the same subject and
  reject failed writes before an authenticated browser session is established.
  IdP-initiated logout requires `c:revoke_assertions/3`; adapters without this
  capability raise an explicit migration error instead of pretending to revoke.
  """

  alias Plug.Conn
  alias Samly.Assertion
  alias Samly.Subject

  @typedoc "Options passed to initialization."
  @type opts :: Plug.opts()

  @typedoc "Store-specific initialized configuration."
  @type config :: term()

  @type idp_id :: binary()
  @type session_id :: binary()

  @typedoc "An IdP identifier and a fresh opaque per-login session ID."
  @type assertion_key :: {idp_id(), session_id()}

  @typedoc "Qualified subject and optional SessionIndexes; an empty list selects all matching sessions."
  @type selector :: %{idp_id: idp_id(), subject: Subject.t(), session_indexes: [binary()]}

  @doc """
  Initializes the store and returns the configuration passed to its callbacks.
  """
  @callback init(opts :: opts()) :: config() | no_return()

  @doc """
  Returns an unexpired assertion, or `nil` when absent, expired or unavailable.
  """
  @callback get_assertion(conn :: Conn.t(), key :: assertion_key() | nil, config :: config()) :: Assertion.t() | nil

  @doc """
  Stores an assertion or raises on failure, without establishing authentication.
  """
  @callback put_assertion(conn :: Conn.t(), key :: assertion_key(), assertion :: Assertion.t(), config :: config()) :: Conn.t() | no_return()

  @doc """
  Removes the selected session or raises on failure.
  The caller must terminate the corresponding browser session after removal.
  """
  @callback delete_assertion(conn :: Conn.t(), key :: assertion_key() | nil, config :: config()) :: Conn.t() | no_return()

  @doc """
  Atomically revokes matching sessions and returns their keys and assertions.

  Match the IdP and qualified NameID (name, format, NameQualifier and
  SPNameQualifier) exactly, with missing qualifier representations normalized.
  Match any supplied SessionIndex, or all subject sessions for an empty list.
  Authoritative stores must revoke even when no browser cookie is available.
  The stateless Session adapter can only affect its supplied browser entry.
  """
  @callback revoke_assertions(conn :: Conn.t(), selector :: selector(), config :: config()) :: {Conn.t(), [{assertion_key(), Assertion.t()}]} | no_return()

  @optional_callbacks revoke_assertions: 3
end
