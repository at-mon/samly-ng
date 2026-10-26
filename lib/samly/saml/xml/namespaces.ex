defmodule Samly.SAML.XML.Namespaces do
  @moduledoc false

  @xml "http://www.w3.org/XML/1998/namespace"
  @xmlns "http://www.w3.org/2000/xmlns/"
  @ncname ~r/\A[A-Z_a-z\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}][A-Z_a-z0-9.\x{2D}\x{B7}\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{203F}-\x{2040}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}]*\z/u

  @doc false
  @spec in_scope([{binary(), binary()}], map()) :: map()
  def in_scope(attributes, inherited) do
    Enum.reduce(attributes, Map.put(inherited, "xml", @xml), fn
      {"xmlns", uri}, acc -> Map.put(acc, "", uri)
      {"xmlns:" <> prefix, uri}, acc -> Map.put(acc, prefix, uri)
      _, acc -> acc
    end)
  end

  @doc false
  @spec expanded_name(binary(), map(), :element | :attribute) :: {binary(), binary()}
  def expanded_name(name, namespaces, kind \\ :element) do
    case String.split(name, ":") do
      [prefix, local] -> {Map.get(namespaces, prefix, ""), local}
      [local] when kind == :attribute -> {"", local}
      [local] -> {Map.get(namespaces, "", ""), local}
    end
  end

  @doc false
  @spec validate(binary(), [{binary(), binary()}], map()) :: {:ok, map()} | {:error, :invalid_xml}
  def validate(name, attributes, inherited) do
    namespaces = in_scope(attributes, inherited)
    names = Enum.map(attributes, &elem(&1, 0))
    expanded = Enum.map(attributes, fn {name, _} -> expanded_attribute(name, namespaces) end)

    cond do
      not valid_name?(name, namespaces) -> {:error, :invalid_xml}
      length(Enum.uniq(names)) != length(names) -> {:error, :invalid_xml}
      not Enum.all?(attributes, &valid_attribute?(&1, namespaces)) -> {:error, :invalid_xml}
      length(Enum.uniq(expanded)) != length(expanded) -> {:error, :invalid_xml}
      true -> {:ok, namespaces}
    end
  end

  defp expanded_attribute("xmlns", _namespaces), do: {@xmlns, ""}
  defp expanded_attribute("xmlns:" <> prefix, _namespaces), do: {@xmlns, prefix}
  defp expanded_attribute(name, namespaces), do: expanded_name_safe(name, namespaces)

  defp expanded_name_safe(name, namespaces) do
    case String.split(name, ":") do
      [_] -> expanded_name(name, namespaces, :attribute)
      [_, _] -> expanded_name(name, namespaces, :attribute)
      _ -> {:invalid, name}
    end
  end

  defp valid_attribute?({"xmlns", uri}, _namespaces), do: valid_uri?(uri) and uri not in [@xml, @xmlns]
  defp valid_attribute?({"xmlns:xml", uri}, _namespaces), do: uri == @xml
  defp valid_attribute?({"xmlns:xmlns", _uri}, _namespaces), do: false

  defp valid_attribute?({"xmlns:" <> prefix, uri}, _namespaces), do: Regex.match?(@ncname, prefix) and valid_uri?(uri) and uri not in ["", @xml, @xmlns]

  defp valid_attribute?({name, _value}, namespaces), do: valid_name?(name, namespaces)

  defp valid_uri?(""), do: true
  defp valid_uri?(uri), do: Regex.match?(~r/\A[A-Za-z][A-Za-z0-9+.-]*:[^\s]*\z/u, uri)

  defp valid_name?(name, namespaces) do
    case String.split(name, ":") do
      [local] -> Regex.match?(@ncname, local)
      ["xmlns", _] -> false
      [prefix, local] -> Regex.match?(@ncname, prefix) and Regex.match?(@ncname, local) and Map.has_key?(namespaces, prefix)
      _ -> false
    end
  end
end
