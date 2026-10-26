defmodule Samly.SAML.XML.Lexical do
  @moduledoc false

  # Saxy does not implement XML 1.0 section 2.11 / 3.3.3 normalization and
  # discards processing instructions. Work on raw lexical input, never on
  # decoded attribute values, so character references retain their meaning.
  @doc false
  @spec prepare(binary()) :: {:ok, binary()} | {:error, atom()}
  def prepare(xml) do
    with :ok <- validate_characters(xml) do
      xml
      |> String.replace("\r\n", "\n")
      |> String.replace("\r", "\n")
      |> declaration()
    end
  end

  @doc false
  @spec validate_characters(binary()) :: :ok | {:error, :invalid_xml}
  def validate_characters(<<>>), do: :ok

  def validate_characters(<<char::utf8, rest::binary>>) when char in [9, 10, 13] or char in 0x20..0xD7FF or char in 0xE000..0xFFFD or char in 0x10000..0x10FFFF, do: validate_characters(rest)

  def validate_characters(_), do: {:error, :invalid_xml}

  defp declaration(<<0xEF, 0xBB, 0xBF, rest::binary>>), do: declaration(rest)

  defp declaration("<?xml" <> <<space, _::binary>> = xml) when space in [9, 10, 32] do
    case :binary.split(xml, "?>") do
      [declaration, rest] -> scan(rest, :text, [declaration <> "?>"])
      _ -> {:error, :invalid_xml}
    end
  end

  defp declaration(xml), do: scan(xml, :text, [])

  defp scan(<<>>, :text, acc), do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}
  defp scan(<<>>, _state, _acc), do: {:error, :invalid_xml}

  defp scan("<!--" <> rest, :text, acc), do: literal(rest, "-->", "<!--", acc)
  defp scan("<![CDATA[" <> rest, :text, acc), do: literal(rest, "]]>", "<![CDATA[", acc)
  defp scan("]]>" <> _, :text, _acc), do: {:error, :invalid_xml}
  defp scan("<?" <> _, :text, _acc), do: {:error, :xml_processing_instructions_not_allowed}
  defp scan("<!" <> _, :text, _acc), do: {:error, :xml_entities_not_allowed}
  defp scan("<" <> rest, :text, acc), do: scan(rest, :tag, ["<" | acc])
  defp scan(">" <> rest, :tag, acc), do: scan(rest, :text, [">" | acc])
  defp scan(<<quote, rest::binary>>, :tag, acc) when quote in [?', ?"], do: scan(rest, {:attribute, quote}, [<<quote>> | acc])

  defp scan(<<quote, rest::binary>>, {:attribute, quote}, acc), do: scan(rest, :tag, [<<quote>> | acc])

  defp scan("<" <> _, {:attribute, _}, _acc), do: {:error, :invalid_xml}

  defp scan("&" <> rest, state, acc) when state != :tag do
    case :binary.split(rest, ";") do
      [reference, tail] ->
        with :ok <- validate_reference(reference) do
          scan(tail, state, [["&", reference, ";"] | acc])
        end

      _ ->
        {:error, :invalid_xml}
    end
  end

  defp scan(xml, :text, acc), do: scan_run(xml, :text, acc, ["<", "&", "]]>"])
  defp scan(xml, :tag, acc), do: scan_run(xml, :tag, acc, [">", "'", "\""])
  defp scan(xml, {:attribute, quote} = state, acc), do: scan_run(xml, state, acc, [<<quote>>, "&", "<"])

  defp scan_run(xml, state, acc, delimiters) do
    size =
      case :binary.match(xml, delimiters) do
        {position, _length} -> position
        :nomatch -> byte_size(xml)
      end

    <<run::binary-size(^size), rest::binary>> = xml
    scan(rest, state, [normalize_run(run, state) | acc])
  end

  defp normalize_run(run, {:attribute, _quote}), do: String.replace(run, ["\t", "\n"], " ")
  defp normalize_run(run, _state), do: run

  defp literal(xml, closing, opening, acc) do
    case :binary.split(xml, closing) do
      [content, rest] ->
        with :ok <- validate_literal(opening, content) do
          scan(rest, :text, [[opening, content, closing] | acc])
        end

      _ ->
        {:error, :invalid_xml}
    end
  end

  defp validate_literal("<!--", content) do
    if String.contains?(content, "--") or String.ends_with?(content, "-"), do: {:error, :invalid_xml}, else: :ok
  end

  defp validate_literal(_opening, _content), do: :ok

  defp validate_reference(name) when name in ["amp", "lt", "gt", "quot", "apos"], do: :ok
  defp validate_reference("#x" <> digits), do: character_reference(digits, 16, 0)
  defp validate_reference("#" <> digits), do: character_reference(digits, 10, 0)
  defp validate_reference(_), do: {:error, :invalid_xml}

  defp character_reference(<<>>, _base, _value), do: {:error, :invalid_xml}

  defp character_reference(digits, base, value) do
    case Integer.parse(binary_part(digits, 0, 1), base) do
      {digit, ""} -> continue_reference(binary_part(digits, 1, byte_size(digits) - 1), base, value * base + digit)
      _ -> {:error, :invalid_xml}
    end
  end

  defp continue_reference(_rest, _base, value) when value > 0x10FFFF, do: {:error, :invalid_xml}
  defp continue_reference(<<>>, _base, value) when value in 0xD800..0xDFFF, do: {:error, :invalid_xml}
  defp continue_reference(<<>>, _base, value), do: validate_characters(<<value::utf8>>)
  defp continue_reference(rest, base, value), do: character_reference(rest, base, value)
end
