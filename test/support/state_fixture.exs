defmodule Samly.Test.StateFixture do
  @moduledoc false

  alias Samly.Assertion
  alias Samly.Subject

  def assertion(opts \\ []) do
    subject = %Subject{
      name: Keyword.get(opts, :name, "same-user"),
      notonorafter: timestamp(Keyword.get(opts, :expires_in, 3600)),
      name_format: Keyword.get(opts, :name_format, :undefined),
      name_qualifier: Keyword.get(opts, :name_qualifier, :undefined),
      sp_name_qualifier: Keyword.get(opts, :sp_name_qualifier, :undefined)
    }

    %Assertion{
      idp_id: Keyword.get(opts, :idp_id, "idp1"),
      subject: subject,
      authn: Keyword.get(opts, :authn, %{"session_index" => "index1"}),
      attributes: Keyword.get(opts, :attributes, %{})
    }
  end

  def timestamp(seconds) do
    DateTime.utc_now() |> DateTime.shift(second: seconds) |> DateTime.to_iso8601()
  end

  def selector(assertion, indexes \\ []) do
    %{idp_id: assertion.idp_id, subject: assertion.subject, session_indexes: indexes}
  end

  def restore_env(key, {:ok, value}), do: Application.put_env(:samly, key, value)
  def restore_env(key, :error), do: Application.delete_env(:samly, key)
end
