defmodule Samly.State.Selector do
  @moduledoc false

  alias Samly.Assertion
  alias Samly.Subject

  @doc false
  @spec valid?(term()) :: boolean()
  def valid?(%{idp_id: idp_id, subject: %Subject{name: name}, session_indexes: indexes})
      when is_binary(idp_id) and byte_size(idp_id) > 0 and is_binary(name) and byte_size(name) > 0 and is_list(indexes) do
    Enum.all?(indexes, &(is_binary(&1) and byte_size(&1) > 0))
  end

  def valid?(_), do: false

  @doc false
  @spec matches?(term(), Assertion.t(), Samly.State.Store.selector()) :: boolean()
  def matches?({idp_id, _session_id}, %Assertion{subject: subject, authn: authn}, %{idp_id: idp_id, subject: selected, session_indexes: indexes}) do
    qualified_subject(subject) == qualified_subject(selected) and matches_index?(authn, indexes)
  end

  def matches?(_, _, _), do: false

  @doc false
  @spec subject_key(binary(), map()) :: tuple()
  def subject_key(idp_id, subject), do: {idp_id, qualified_subject(subject)}

  defp qualified_subject(subject) do
    {Map.get(subject, :name), normalize(Map.get(subject, :name_format)), normalize(Map.get(subject, :name_qualifier)), normalize(Map.get(subject, :sp_name_qualifier))}
  end

  defp normalize(value) when value in [nil, "", :undefined], do: nil
  defp normalize(value), do: value

  defp matches_index?(_authn, []), do: true

  defp matches_index?(%{"session_indexes" => sessions}, indexes) when is_list(sessions) do
    Enum.any?(sessions, &(&1 in indexes))
  end

  defp matches_index?(authn, indexes), do: Map.get(authn, "session_index") in indexes
end
