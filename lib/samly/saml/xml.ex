defmodule Samly.SAML.XML do
  @moduledoc false

  alias Samly.SAML.XML.Lexical
  alias Samly.SAML.XML.Namespaces

  @default_max_bytes 1_048_576

  @type xml_node :: {binary(), [{binary(), binary()}], [xml_node() | binary()]}

  @spec parse(binary(), keyword()) :: {:ok, xml_node()} | {:error, atom()}
  def parse(xml, opts \\ [])

  def parse(xml, opts) when is_binary(xml) do
    max_bytes = Keyword.get(opts, :max_bytes, @default_max_bytes)

    with :ok <- validate_size(xml, max_bytes),
         {:ok, xml} <- Lexical.prepare(xml),
         {:ok, tree} <- parse_bounded(xml) do
      {:ok, tree}
    else
      {:error, %Saxy.ParseError{}} -> {:error, :invalid_xml}
      {:error, reason} -> {:error, reason}
    end
  rescue
    ArgumentError -> {:error, :invalid_xml}
  end

  def parse(_xml, _opts), do: {:error, :invalid_xml}

  @spec encode(xml_node()) :: binary()
  def encode(node), do: node |> encode_node() |> IO.iodata_to_binary()

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

  @doc false
  @spec element_children(xml_node()) :: [xml_node()]
  def element_children({_name, _attributes, children}), do: Enum.filter(children, &is_tuple/1)

  @doc false
  @spec exactly_one_child(xml_node(), binary()) :: {:ok, xml_node()} | {:error, atom()}
  def exactly_one_child(node, wanted) do
    case children(node, wanted) do
      [child] -> {:ok, child}
      [] -> {:error, :missing_element}
      _ -> {:error, :ambiguous_element}
    end
  end

  @doc false
  @spec optional_child(xml_node(), binary()) :: {:ok, xml_node() | nil} | {:error, atom()}
  def optional_child(node, wanted) do
    case children(node, wanted) do
      [child] -> {:ok, child}
      [] -> {:ok, nil}
      _ -> {:error, :ambiguous_element}
    end
  end

  @doc false
  @spec scalar_text(xml_node()) :: {:ok, binary()} | {:error, :non_scalar_text}
  def scalar_text({_name, _attributes, children}) do
    if Enum.all?(children, &is_binary/1) do
      {:ok, IO.iodata_to_binary(children)}
    else
      {:error, :non_scalar_text}
    end
  end

  @doc false
  @spec in_scope_namespaces(xml_node(), map()) :: map()
  def in_scope_namespaces({_name, attributes, _children}, inherited \\ %{}), do: Namespaces.in_scope(attributes, inherited)

  @doc false
  @spec expanded_name(xml_node(), map()) :: {binary(), binary()}
  def expanded_name({name, _attributes, _children} = node, inherited \\ %{}), do: Namespaces.expanded_name(name, in_scope_namespaces(node, inherited))

  @doc false
  @spec namespace_context(xml_node(), xml_node()) :: {:ok, map()} | {:error, :node_not_found}
  def namespace_context(document, target), do: find_namespace_context(document, target, %{})

  defp find_namespace_context(node, target, inherited) when node == target, do: {:ok, inherited}

  defp find_namespace_context(node, target, inherited) do
    available = in_scope_namespaces(node, inherited)

    node
    |> element_children()
    |> Enum.reduce_while({:error, :node_not_found}, fn child, _acc ->
      case find_namespace_context(child, target, available) do
        {:ok, _} = found -> {:halt, found}
        error -> {:cont, error}
      end
    end)
  end

  defp node_name({name, _, _}), do: local_name(name)

  @doc false
  def valid_namespaces?(node, vocabulary, inherited \\ %{})

  def valid_namespaces?({name, attrs, children}, vocabulary, inherited) do
    namespaces = Namespaces.in_scope(attrs, inherited)

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
    case Saxy.parse_string(xml, Samly.SAML.XML.Handler, {[], 0, 0, [%{}]}) do
      {:ok, {:error, reason}} -> {:error, reason}
      {:ok, {tree, 0, _count, _contexts}} -> {:ok, tree}
      {:error, _reason} = error -> error
    end
  end

  defp validate_size(xml, max_bytes) when byte_size(xml) <= max_bytes, do: :ok
  defp validate_size(_xml, _max_bytes), do: {:error, :xml_too_large}

  # XmlBuilder emits literal attribute whitespace and text CRs, which change
  # meaning on a subsequent XML parse. Escape those as character references.
  defp encode_node({name, attributes, children}) do
    attrs = Enum.map(attributes, fn {name, value} -> [" ", encode_name!(name), "=\"", escape_attribute(value), "\""] end)
    ["<", encode_name!(name), attrs, ">", Enum.map(children, &encode_node/1), "</", name, ">"]
  end

  defp encode_node(text) when is_binary(text), do: escape_text(text)

  defp encode_name!(name) do
    if Regex.match?(~r/\A[\p{L}_:][\p{L}\p{N}_.:\-]*\z/u, name), do: name, else: raise(ArgumentError, "invalid XML name")
  end

  defp escape_text(text) do
    text
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\r", "&#xD;")
  end

  defp escape_attribute(value) do
    value
    |> escape_text()
    |> String.replace("\"", "&quot;")
    |> String.replace("\t", "&#x9;")
    |> String.replace("\n", "&#xA;")
  end
end
