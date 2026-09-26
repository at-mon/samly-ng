defmodule Samly.SAML.XML do
  @moduledoc false

  @default_max_bytes 1_048_576
  @forbidden_tokens ["<!DOCTYPE", "<!ENTITY"]

  @type xml_node :: {binary(), [{binary(), binary()}], [xml_node() | binary()]}

  @spec parse(binary(), keyword()) :: {:ok, xml_node()} | {:error, atom()}
  def parse(xml, opts \\ []) when is_binary(xml) do
    max_bytes = Keyword.get(opts, :max_bytes, @default_max_bytes)

    with :ok <- validate_size(xml, max_bytes),
         :ok <- reject_entities(xml),
         {:ok, tree} <- parse_bounded(xml) do
      {:ok, tree}
    else
      {:error, %Saxy.ParseError{}} -> {:error, :invalid_xml}
      {:error, reason} -> {:error, reason}
    end
  rescue
    ArgumentError -> {:error, :invalid_xml}
  end

  @spec encode(xml_node()) :: binary()
  def encode(node), do: node |> to_xml_builder() |> XmlBuilder.generate(format: :none)

  @spec local_name(binary()) :: binary()
  def local_name(name) do
    name
    |> String.split(":", parts: 2)
    |> List.last()
  end

  @spec attribute(xml_node(), binary()) :: binary() | nil
  def attribute({_name, attributes, _children}, wanted) do
    Enum.find_value(attributes, fn {name, value} ->
      if name == wanted, do: value
    end)
  end

  @spec children(xml_node(), binary()) :: [xml_node()]
  def children({_name, _attributes, children}, wanted) do
    Enum.filter(children, fn
      {name, _, _} -> local_name(name) == wanted
      _ -> false
    end)
  end

  @spec child(xml_node(), binary()) :: xml_node() | nil
  def child(node, wanted), do: node |> children(wanted) |> List.first()

  @spec descendants(xml_node(), binary()) :: [xml_node()]
  def descendants({_name, _attributes, children} = node, wanted) do
    own = if node_name(node) == wanted, do: [node], else: []

    own ++
      Enum.flat_map(children, fn
        {_name, _attributes, _children} = child -> descendants(child, wanted)
        _ -> []
      end)
  end

  @spec text(xml_node() | nil) :: binary()
  def text(nil), do: ""

  def text({_name, _attributes, children}) do
    children
    |> Enum.map(fn
      value when is_binary(value) -> value
      {_name, _attributes, _children} = child -> text(child)
    end)
    |> IO.iodata_to_binary()
    |> String.trim()
  end

  defp node_name({name, _, _}), do: local_name(name)

  @doc false
  def valid_namespaces?(node, vocabulary, inherited \\ %{})

  def valid_namespaces?({name, attrs, children}, vocabulary, inherited) do
    namespaces =
      Enum.reduce(attrs, inherited, fn
        {"xmlns", uri}, acc -> Map.put(acc, "", uri)
        {"xmlns:" <> prefix, uri}, acc -> Map.put(acc, prefix, uri)
        _, acc -> acc
      end)

    {prefix, local} =
      case String.split(name, ":", parts: 2) do
        [prefix, local] -> {prefix, local}
        [local] -> {"", local}
      end

    expected = Map.get(vocabulary, local)

    (is_nil(expected) or Map.get(namespaces, prefix) == expected) and
      Enum.all?(children, &valid_namespaces?(&1, vocabulary, namespaces))
  end

  def valid_namespaces?(text, _vocabulary, _inherited) when is_binary(text), do: true

  defp parse_bounded(xml) do
    case Saxy.parse_string(xml, Samly.SAML.XML.Handler, {[], 0, 0}) do
      {:ok, {:error, reason}} -> {:error, reason}
      {:ok, {tree, 0, _count}} -> {:ok, tree}
      {:error, _reason} = error -> error
    end
  end

  defp validate_size(xml, max_bytes) when byte_size(xml) <= max_bytes, do: :ok
  defp validate_size(_xml, _max_bytes), do: {:error, :xml_too_large}

  defp reject_entities(xml) do
    upper = String.upcase(xml)

    if Enum.any?(@forbidden_tokens, &String.contains?(upper, &1)) do
      {:error, :xml_entities_not_allowed}
    else
      :ok
    end
  end

  defp to_xml_builder({name, attributes, children}) do
    {name, attributes, Enum.map(children, &to_xml_builder/1)}
  end

  defp to_xml_builder(text) when is_binary(text), do: text
end
