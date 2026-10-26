defmodule Samly.HTML do
  @moduledoc false

  @doc false
  @spec escape_attribute(String.Chars.t()) :: binary()
  def escape_attribute(value) do
    value
    |> to_string()
    |> String.replace("&", "&amp;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&#39;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
  end
end
