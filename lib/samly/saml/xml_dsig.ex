defmodule Samly.SAML.XMLDSig do
  @moduledoc false

  alias Samly.SAML.XML

  @ds "http://www.w3.org/2000/09/xmldsig#"
  @exclusive "http://www.w3.org/2001/10/xml-exc-c14n#"
  @enveloped "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
  @rsa_sha256 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
  @sha256 "http://www.w3.org/2001/04/xmlenc#sha256"
  @rsa_sha1 "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
  @sha1 "http://www.w3.org/2000/09/xmldsig#sha1"
  @vocabulary Map.new(
                ~w(Signature SignedInfo CanonicalizationMethod SignatureMethod Reference Transforms Transform DigestMethod DigestValue SignatureValue KeyInfo X509Data X509Certificate),
                &{&1, @ds}
              )

  @type xml_node :: XML.xml_node()

  @spec sign(binary(), tuple(), binary()) :: {:ok, binary()} | {:error, atom()}
  def sign(xml, private_key, certificate) do
    with {:ok, root} <- XML.parse(xml),
         id when is_binary(id) <- XML.attribute(root, "ID") do
      digest = root |> canonicalize() |> then(&:crypto.hash(:sha256, &1)) |> Base.encode64()
      signed_info = signed_info(id, digest)
      signature_value = signed_info |> canonicalize() |> :public_key.sign(:sha256, private_key)
      signature = signature(signed_info, signature_value, certificate)
      {:ok, root |> insert_signature(signature) |> XML.encode()}
    else
      _ -> {:error, :cannot_sign}
    end
  rescue
    _ -> {:error, :cannot_sign}
  end

  @spec verify(xml_node(), xml_node(), [{:sha256, binary()}], keyword()) ::
          :ok | {:error, atom()}
  def verify(document, signed_node, trusted_fingerprints, opts \\ []) do
    with true <- XML.valid_namespaces?(document, @vocabulary),
         [signature] <- direct_children(signed_node, "Signature"),
         [signed_info] <- direct_children(signature, "SignedInfo"),
         :ok <- supported_structure(signed_info),
         {:ok, hash} <- supported_algorithms(signed_info, opts),
         {:ok, reference_id} <- reference_id(signed_info),
         :ok <- unique_reference(document, signed_node, reference_id),
         :ok <- verify_digest(document, signed_info, signed_node, hash),
         {:ok, certificate} <- trusted_certificate(signature, trusted_fingerprints),
         {:ok, signature_value} <- decode_text(signature, "SignatureValue"),
         true <-
           :public_key.verify(
             canonicalize(signed_info, namespace_context(document, signed_info)),
             hash,
             signature_value,
             public_key(certificate)
           ) do
      :ok
    else
      false -> {:error, :bad_signature}
      [] -> {:error, :no_signature}
      [_ | _] -> {:error, :multiple_signatures}
      {:error, _reason} = error -> error
    end
  rescue
    _ -> {:error, :invalid_signature}
  end

  @spec canonicalize(xml_node()) :: binary()
  def canonicalize(node), do: canonicalize(node, %{})

  defp canonicalize(node, available), do: canonicalize(node, available, %{})

  defp canonicalize({name, attributes, children}, available, rendered) do
    declared = namespace_declarations(attributes)
    namespaces = Map.merge(available, declared)
    visible = visibly_used_prefixes(name, attributes)

    namespace_attrs =
      visible
      |> Enum.reject(&(&1 == "xml"))
      |> Enum.flat_map(fn prefix ->
        changed_namespace(prefix, namespaces, rendered)
      end)
      |> Enum.sort_by(&elem(&1, 0))

    rendered =
      Enum.reduce(namespace_attrs, rendered, fn {name, uri}, acc ->
        Map.put(acc, namespace_prefix(name), uri)
      end)

    regular_attrs =
      attributes
      |> Enum.reject(fn {attribute_name, _} -> namespace_attribute?(attribute_name) end)
      |> Enum.sort_by(fn {attribute_name, _} ->
        attribute_sort_key(attribute_name, namespaces)
      end)

    attrs =
      Enum.map_join(namespace_attrs ++ regular_attrs, "", fn {attribute_name, value} ->
        " " <> attribute_name <> "=\"" <> escape_attribute(value) <> "\""
      end)

    content =
      Enum.map_join(children, "", fn
        text when is_binary(text) -> escape_text(text)
        child -> canonicalize(child, namespaces, rendered)
      end)

    "<" <> name <> attrs <> ">" <> content <> "</" <> name <> ">"
  end

  defp changed_namespace(prefix, namespaces, inherited) do
    case Map.fetch(namespaces, prefix) do
      {:ok, uri} ->
        if Map.get(inherited, prefix) == uri, do: [], else: [{namespace_name(prefix), uri}]

      :error ->
        []
    end
  end

  defp signed_info(id, digest) do
    {"ds:SignedInfo", [{"xmlns:ds", @ds}],
     [
       {"ds:CanonicalizationMethod", [{"Algorithm", @exclusive}], []},
       {"ds:SignatureMethod", [{"Algorithm", @rsa_sha256}], []},
       {"ds:Reference", [{"URI", "#" <> id}],
        [
          {"ds:Transforms", [],
           [
             {"ds:Transform", [{"Algorithm", @enveloped}], []},
             {"ds:Transform", [{"Algorithm", @exclusive}], []}
           ]},
          {"ds:DigestMethod", [{"Algorithm", @sha256}], []},
          {"ds:DigestValue", [], [digest]}
        ]}
     ]}
  end

  defp signature(signed_info, signature_value, certificate) do
    {"ds:Signature", [{"xmlns:ds", @ds}],
     [
       signed_info,
       {"ds:SignatureValue", [], [Base.encode64(signature_value)]},
       {"ds:KeyInfo", [], [{"ds:X509Data", [], [{"ds:X509Certificate", [], [Base.encode64(certificate)]}]}]}
     ]}
  end

  defp insert_signature({name, attributes, children}, signature) do
    {issuer, rest} = Enum.split_while(children, fn child -> node_name(child) == "Issuer" end)
    {name, attributes, issuer ++ [signature] ++ rest}
  end

  defp supported_algorithms(signed_info, opts) do
    signature_method = signed_info |> first("SignatureMethod") |> algorithm()
    digest_method = signed_info |> first("DigestMethod") |> algorithm()
    transforms = signed_info |> descendants("Transform") |> Enum.map(&algorithm/1)

    case {signature_method, digest_method, transforms} do
      {@rsa_sha256, @sha256, [@enveloped, @exclusive]} ->
        {:ok, :sha256}

      {@rsa_sha1, @sha1, [@enveloped, @exclusive]} ->
        if Keyword.get(opts, :allow_legacy_sha1, false),
          do: {:ok, :sha},
          else: {:error, :legacy_sha1_disabled}

      _ ->
        {:error, :unsupported_signature_algorithm}
    end
  end

  defp supported_structure(signed_info) do
    with [method] <- direct_children(signed_info, "CanonicalizationMethod"),
         @exclusive <- algorithm(method),
         [] <- element_children(method),
         [_method] <- direct_children(signed_info, "SignatureMethod"),
         [reference] <- direct_children(signed_info, "Reference"),
         [transforms] <- direct_children(reference, "Transforms"),
         [enveloped, exclusive] <- element_children(transforms),
         [] <- element_children(enveloped),
         [] <- element_children(exclusive),
         [_digest] <- direct_children(reference, "DigestMethod"),
         [_value] <- direct_children(reference, "DigestValue"),
         3 <- length(element_children(signed_info)),
         3 <- length(element_children(reference)) do
      :ok
    else
      _ -> {:error, :unsupported_signature_structure}
    end
  end

  defp element_children({_name, _attrs, children}), do: Enum.filter(children, &is_tuple/1)

  defp reference_id(signed_info) do
    case signed_info |> first("Reference") |> attribute("URI") do
      "#" <> id when id != "" -> {:ok, id}
      _ -> {:error, :invalid_reference}
    end
  end

  defp unique_reference(document, signed_node, reference_id) do
    matches = document |> all_nodes() |> Enum.filter(&(attribute(&1, "ID") == reference_id))

    if matches == [signed_node], do: :ok, else: {:error, :ambiguous_reference}
  end

  defp verify_digest(document, signed_info, signed_node, hash) do
    with {:ok, expected} <- decode_text(signed_info, "DigestValue") do
      context = namespace_context(document, signed_node)

      actual =
        signed_node
        |> remove_direct_signatures()
        |> canonicalize(context)
        |> then(&:crypto.hash(hash, &1))

      if Plug.Crypto.secure_compare(actual, expected), do: :ok, else: {:error, :bad_digest}
    end
  end

  defp trusted_certificate(signature, trusted_fingerprints) do
    with {:ok, certificate} <- decode_text(signature, "X509Certificate"),
         fingerprint = {:sha256, :crypto.hash(:sha256, certificate)},
         true <- Enum.any?(trusted_fingerprints, &secure_fingerprint?(&1, fingerprint)) do
      {:ok, certificate}
    else
      _ -> {:error, :untrusted_certificate}
    end
  end

  defp secure_fingerprint?({:sha256, left}, {:sha256, right}) when byte_size(left) == byte_size(right), do: Plug.Crypto.secure_compare(left, right)

  defp secure_fingerprint?(_, _), do: false

  defp public_key(certificate) do
    certificate
    |> :public_key.pkix_decode_cert(:otp)
    |> elem(1)
    |> elem(7)
    |> elem(2)
  end

  defp decode_text(node, name) do
    case node |> first(name) |> XML.text() |> String.replace(~r/\s+/, "") |> Base.decode64() do
      {:ok, value} -> {:ok, value}
      :error -> {:error, :invalid_base64}
    end
  end

  defp remove_direct_signatures({name, attributes, children}) do
    {name, attributes, Enum.reject(children, &(node_name(&1) == "Signature"))}
  end

  defp all_nodes({_name, _attributes, children} = node) do
    [
      node
      | Enum.flat_map(children, fn child -> if is_tuple(child), do: all_nodes(child), else: [] end)
    ]
  end

  defp direct_children({_name, _attributes, children}, wanted) do
    Enum.filter(children, &(node_name(&1) == wanted))
  end

  defp descendants(node, wanted), do: XML.descendants(node, wanted)
  defp first(node, wanted), do: node |> descendants(wanted) |> List.first()
  defp attribute(nil, _name), do: nil
  defp attribute(node, name), do: XML.attribute(node, name)
  defp algorithm(node), do: attribute(node, "Algorithm")
  defp node_name({name, _, _}), do: XML.local_name(name)
  defp node_name(_), do: nil

  defp namespace_declarations(attributes) do
    attributes
    |> Map.new(fn
      {"xmlns", uri} -> {"", uri}
      {"xmlns:" <> prefix, uri} -> {prefix, uri}
      _ -> {nil, nil}
    end)
    |> Map.delete(nil)
  end

  defp visibly_used_prefixes(name, attributes) do
    ([prefix(name)] ++
       Enum.map(attributes, fn {attribute_name, _} ->
         if namespace_attribute?(attribute_name) or not String.contains?(attribute_name, ":"), do: nil, else: prefix(attribute_name)
       end))
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  defp prefix(name) do
    case String.split(name, ":", parts: 2) do
      [prefix, _local] -> prefix
      [_local] -> ""
    end
  end

  defp namespace_name(""), do: "xmlns"
  defp namespace_name(prefix), do: "xmlns:" <> prefix
  defp namespace_prefix("xmlns"), do: ""
  defp namespace_prefix("xmlns:" <> prefix), do: prefix
  defp namespace_attribute?("xmlns"), do: true
  defp namespace_attribute?("xmlns:" <> _), do: true
  defp namespace_attribute?(_), do: false

  defp attribute_sort_key(name, namespaces) do
    case String.split(name, ":", parts: 2) do
      [prefix, local] -> {Map.get(namespaces, prefix, ""), local}
      [local] -> {"", local}
    end
  end

  defp escape_text(value) do
    value
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

  defp namespace_context(document, target) do
    case find_namespace_context(document, target, %{}) do
      {:ok, context} -> context
      :error -> %{}
    end
  end

  defp find_namespace_context(node, target, inherited) when node == target, do: {:ok, inherited}

  defp find_namespace_context({_name, attributes, children}, target, inherited) do
    available = Map.merge(inherited, namespace_declarations(attributes))

    Enum.reduce_while(children, :error, fn
      child, _acc when is_tuple(child) ->
        case find_namespace_context(child, target, available) do
          {:ok, _context} = found -> {:halt, found}
          :error -> {:cont, :error}
        end

      _text, _acc ->
        {:cont, :error}
    end)
  end
end
