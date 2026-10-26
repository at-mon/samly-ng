defmodule Samly.State.Lifetime do
  @moduledoc false

  alias Samly.Assertion

  @doc false
  @spec expires_at(Assertion.t()) :: {:ok, integer()} | :error
  def expires_at(%Assertion{subject: %{notonorafter: subject_expiry}, authn: authn}) when is_map(authn) do
    with {:ok, subject_deadline} <- parse_deadline(subject_expiry) do
      session_deadline(authn, subject_deadline)
    end
  end

  def expires_at(_), do: :error

  @doc false
  @spec valid_assertion(term()) :: Assertion.t() | nil
  def valid_assertion(assertion) do
    case expires_at(assertion) do
      {:ok, deadline} -> if deadline > System.system_time(:microsecond), do: assertion
      :error -> nil
    end
  end

  defp session_deadline(%{"session_not_on_or_after" => expiry}, subject_deadline) do
    with {:ok, session_deadline} <- parse_deadline(expiry) do
      {:ok, min(session_deadline, subject_deadline)}
    end
  end

  defp session_deadline(_authn, subject_deadline), do: {:ok, subject_deadline}

  defp parse_deadline(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} -> {:ok, DateTime.to_unix(datetime, :microsecond)}
      _ -> :error
    end
  end

  defp parse_deadline(_), do: :error
end
