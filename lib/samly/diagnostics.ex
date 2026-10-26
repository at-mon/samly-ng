defmodule Samly.Diagnostics do
  @moduledoc false

  alias Samly.IdpData

  require Logger

  # Leave room below Logger's default 8096-byte formatter truncation limit.
  @max_bytes 8000
  @truncation " [truncated]"

  @doc false
  @spec raw(IdpData.t() | nil, atom(), binary() | nil) :: :ok
  def raw(%IdpData{debug_mode: true}, label, payload) when is_atom(label) and is_binary(payload) do
    Logger.debug(fn -> message(label, payload) end)
    :ok
  end

  def raw(_idp, label, _payload) when is_atom(label), do: :ok

  @doc false
  @spec csp(binary()) :: :ok
  def csp(payload) when is_binary(payload) do
    if Application.get_env(:samly, :debug_csp_reports, false) === true do
      Logger.debug(fn -> message(:csp_report, payload) end)
    end

    :ok
  end

  defp message(label, payload) do
    prefix = "Samly raw #{label}: "
    budget = @max_bytes - byte_size(prefix) - byte_size(@truncation)
    [prefix, render(payload, budget, [])]
  end

  # Stop processing at the output bound, not after formatting the entire input.
  # UTF-8 is preserved; invalid bytes remain diagnosable as hexadecimal escapes.
  defp render(<<>>, _budget, acc), do: Enum.reverse(acc)

  defp render(<<codepoint::utf8, rest::binary>>, budget, acc) do
    append(<<codepoint::utf8>>, rest, budget, acc)
  end

  defp render(<<byte, rest::binary>>, budget, acc) do
    append("\\x" <> Base.encode16(<<byte>>), rest, budget, acc)
  end

  defp append(part, rest, budget, acc) when byte_size(part) <= budget do
    render(rest, budget - byte_size(part), [part | acc])
  end

  defp append(_part, _rest, _budget, acc), do: Enum.reverse([@truncation | acc])
end
