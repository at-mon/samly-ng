defmodule Samly.XMLSecurityTest do
  use ExUnit.Case, async: true

  alias Samly.SAML.Key
  alias Samly.SAML.XML
  alias Samly.SAML.XMLDSig

  describe "strict XML input" do
    for {label, xml} <- [
          {"duplicate attributes", ~s(<r ID="one" ID="two"/>)},
          {"duplicate namespace declarations", ~s(<r xmlns:p="urn:a" xmlns:p="urn:b"/>)},
          {"expanded attribute collisions", ~s(<r xmlns:a="urn:a" xmlns:b="urn:a" a:id="one" b:id="two"/>)},
          {"undeclared prefixes", "<p:r/>"},
          {"undeclared attribute prefixes", ~s(<r p:id="x"/>)},
          {"multiple colons", ~s(<a:b:c xmlns:a="urn:a"/>)},
          {"empty prefix", "<:r/>"},
          {"numeric local name", ~s(<p:1 xmlns:p="urn:p"/>)},
          {"reserved xml rebinding", ~s(<r xmlns:xml="urn:evil"/>)},
          {"reserved xmlns binding", ~s(<r xmlns:xmlns="urn:evil"/>)},
          {"XML namespace alias", ~s(<r xmlns:p="http://www.w3.org/XML/1998/namespace"/>)},
          {"xmlns namespace binding", ~s(<r xmlns="http://www.w3.org/2000/xmlns/"/>)},
          {"prefix undeclaration", ~s(<r xmlns:p=""/>)},
          {"relative namespace", ~s(<r xmlns="relative"/>)},
          {"undeclared entity", "<r>&undeclared;</r>"},
          {"undeclared attribute entity", ~s(<r a="&undeclared;"/>)},
          {"NUL character", "<r>\0</r>"},
          {"illegal literal character", "<r>\x01</r>"},
          {"illegal numeric reference", "<r>&#0;</r>"},
          {"illegal hexadecimal reference", ~s(<r a="&#x1;"/>)},
          {"noncharacter", "<r>&#xFFFF;</r>"},
          {"literal less-than in attribute", ~s(<r a="<nested>"/>)},
          {"processing instruction", "<r><?instruction ignored?></r>"},
          {"trailing processing instruction", "<r/><?instruction ignored?>"},
          {"XML 1.1", ~s(<?xml version="1.1"?><r/>)},
          {"invalid UTF-8", <<"<r>", 255, "</r>">>},
          {"malformed comment", "<r><!-- a--b --></r>"},
          {"CDATA terminator in text", "<r>]]></r>"},
          {"DOCTYPE", "<!DOCTYPE r><r/>"},
          {"surrogate reference", "<r>&#xD800;</r>"}
        ] do
      test "rejects #{label}" do
        assert {:error, _reason} = XML.parse(unquote(xml))
      end
    end

    test "normalizes literal whitespace but preserves character reference whitespace" do
      assert {:ok, root} = XML.parse("<r a=\"A\tB\r\nC\rD\nE&#x9;&#xA;&#xD;\">A\r\nB\rC&#xD;<![CDATA[D\r\nE]]></r>")
      assert XML.attribute(root, "a") == "A B C D E\t\n\r"
      assert XML.text(root) == "A\nB\nC\rD\nE"
    end

    test "allows XML declarations, predefined entities and PI-like literal data" do
      assert {:ok, root} = XML.parse(~s(<?xml version="1.0" encoding="UTF-8"?><r xml:lang="en"><!-- <?ignored?> --><![CDATA[<?literal?> &unknown;]]>&amp;&lt;&gt;&quot;&apos;</r>))
      assert XML.text(root) == "<?literal?> &unknown;&<>\"'"
    end
  end

  describe "parsed values and bounded inputs" do
    test "encoding preserves referenced attribute whitespace and text carriage returns" do
      assert {:ok, root} = XML.parse(~s(<r a="a&#9;&#10;&#13;b">a&#13;b</r>))
      assert {:ok, decoded} = root |> XML.encode() |> XML.parse()
      assert XML.attribute(decoded, "a") == XML.attribute(root, "a")
      assert XML.text(decoded) == XML.text(root)
    end

    test "signing preserves referenced whitespace when serializing" do
      {:ok, key} = Key.load_private_key("test/data/test.pem")
      {:ok, cert} = Key.load_certificate("test/data/test.crt")
      {:ok, signed} = XMLDSig.sign(~s(<r ID="whitespace" a="a&#9;&#10;&#13;b">a&#13;b</r>), key, cert)
      assert {:ok, root} = XML.parse(signed)
      assert :ok = XMLDSig.verify(root, root, [{:sha256, :crypto.hash(:sha256, cert)}])
    end

    test "rejects nonbinary parser input" do
      assert {:error, :invalid_xml} = XML.parse(~c"<r/>")
    end

    test "rejects out of range numeric references without building huge integers" do
      for digits <- ["1114112", String.duplicate("9", 20_000)] do
        assert {:error, :invalid_xml} = XML.parse("<r>&#" <> digits <> ";</r>")
      end
    end

    test "near-limit plain XML does not allocate a list cell per byte" do
      payload = String.duplicate("x", 1_000_000)
      xml = "<r value=\"" <> payload <> "\"/>"
      parent = self()

      {pid, ref} =
        Process.spawn(
          fn ->
            {:ok, root} = XML.parse(xml)
            send(parent, {:parsed_large_xml, XML.attribute(root, "value") == payload})
          end,
          [:monitor, max_heap_size: %{size: 1_000_000, kill: true, error_logger: false}]
        )

      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 5_000
      assert_receive {:parsed_large_xml, true}, 1_000
    end

    test "preserves byte depth and element limits" do
      assert {:error, :xml_too_large} = XML.parse("<r>too large</r>", max_bytes: 8)
      assert {:error, :xml_too_deep} = XML.parse(String.duplicate("<r>", 129) <> String.duplicate("</r>", 129))
      assert {:error, :xml_too_many_elements} = XML.parse("<r>" <> String.duplicate("<c/>", 10_000) <> "</r>")
    end

    test "retains namespace context for subtree validation" do
      {:ok, root} = XML.parse(~s(<r xmlns:s="urn:s"><s:c><s:value>  principal  </s:value></s:c></r>))
      {:ok, child} = XML.exactly_one_child(root, "c")
      {:ok, context} = XML.namespace_context(root, child)
      assert XML.valid_namespaces?(child, %{"c" => "urn:s", "value" => "urn:s"}, context)
      assert {"urn:s", "c"} = XML.expanded_name(child, context)
      {:ok, value} = XML.exactly_one_child(child, "value")
      assert {:ok, "  principal  "} = XML.scalar_text(value)
      assert {:error, :non_scalar_text} = XML.scalar_text(child)
      assert {:ok, nil} = XML.optional_child(root, "missing")
      assert {:error, :missing_element} = XML.exactly_one_child(root, "missing")
    end
  end

  describe "signature cardinality" do
    setup do
      {:ok, key} = Key.load_private_key("test/data/test.pem")
      {:ok, cert} = Key.load_certificate("test/data/test.crt")
      {:ok, signed} = XMLDSig.sign(~s(<Response ID="signature-cardinality"/>), key, cert)
      %{signed: signed, fingerprints: [{:sha256, :crypto.hash(:sha256, cert)}]}
    end

    for name <- ["SignatureValue", "KeyInfo", "X509Data", "X509Certificate"] do
      test "rejects duplicate #{name}", context do
        name = unquote(name)
        [original] = Regex.run(Regex.compile!("<ds:#{name}(?:\\s[^>]*)?>.*?</ds:#{name}>"), context.signed)
        modified = String.replace(context.signed, original, original <> original)
        assert {:ok, root} = XML.parse(modified)
        assert {:error, _} = XMLDSig.verify(root, root, context.fingerprints)
      end
    end

    test "rejects nested signature value", context do
      modified = context.signed |> String.replace("<ds:SignatureValue>", "<wrapper><ds:SignatureValue>") |> String.replace("</ds:SignatureValue>", "</ds:SignatureValue></wrapper>")
      assert {:ok, root} = XML.parse(modified)
      assert {:error, _} = XMLDSig.verify(root, root, context.fingerprints)
    end

    test "rejects markup inside a signature scalar", context do
      modified = context.signed |> String.replace("<ds:SignatureValue>", "<ds:SignatureValue><wrapper>") |> String.replace("</ds:SignatureValue>", "</wrapper></ds:SignatureValue>")
      assert {:ok, root} = XML.parse(modified)
      assert {:error, _} = XMLDSig.verify(root, root, context.fingerprints)
    end
  end

  describe "independently produced XML signatures" do
    @tag :tmp_dir
    test "verifies xmllint canonicalization signed by OpenSSL with inherited namespaces", %{tmp_dir: tmp_dir} do
      # No Samly signing or canonicalization is used to produce this signature.
      unsigned = ~s(<s:Assertion xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="independent" a="x\tY&#x9;&gt;" xml:lang="en"><s:Subject><![CDATA[A\r\nB]]></s:Subject></s:Assertion>)
      input = Path.join(tmp_dir, "unsigned.xml")
      File.write!(input, unsigned)
      assert {canonical, 0} = System.cmd("xmllint", ["--nonet", "--exc-c14n", input])
      digest = canonical |> then(&:crypto.hash(:sha256, &1)) |> Base.encode64()

      signed_info =
        ~s(<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#independent"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>#{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>)

      info_path = Path.join(tmp_dir, "signed-info.xml")
      canonical_path = Path.join(tmp_dir, "signed-info.c14n")
      signature_path = Path.join(tmp_dir, "signature.bin")
      File.write!(info_path, signed_info)
      assert {canonical_info, 0} = System.cmd("xmllint", ["--nonet", "--exc-c14n", info_path])
      File.write!(canonical_path, canonical_info)
      assert {_, 0} = System.cmd("openssl", ["dgst", "-sha256", "-sign", Path.expand("test/data/test.pem"), "-out", signature_path, canonical_path])
      signature = signature_path |> File.read!() |> Base.encode64()
      {:ok, cert} = Key.load_certificate("test/data/test.crt")

      signature_xml =
        ~s(<ds:Signature>#{String.replace(signed_info, ~s( xmlns:ds="http://www.w3.org/2000/09/xmldsig#"), "")}<ds:SignatureValue>#{signature}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>#{Base.encode64(cert)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>)

      assertion = unsigned |> String.replace(~s( xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion"), "") |> String.replace("<s:Subject>", signature_xml <> "<s:Subject>")
      document = ~s(<Response xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">#{assertion}</Response>)
      assert {:ok, root} = XML.parse(document)
      {:ok, assertion_node} = XML.exactly_one_child(root, "Assertion")
      assert :ok = XMLDSig.verify(root, assertion_node, [{:sha256, :crypto.hash(:sha256, cert)}])
      assert {:ok, changed} = document |> String.replace("A\r\nB", "different") |> XML.parse()
      {:ok, assertion_node} = XML.exactly_one_child(changed, "Assertion")
      assert {:error, :bad_digest} = XMLDSig.verify(changed, assertion_node, [{:sha256, :crypto.hash(:sha256, cert)}])
    end
  end

  describe "independent exclusive canonicalization" do
    @tag :tmp_dir
    test "omits comments for the supported no-comments algorithm", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, "comments.xml")
      xml = "<r>A<!--known comment-->B<![CDATA[<value>]]></r>"
      File.write!(path, xml)
      # xmllint's CLI includes comments, unlike the supported algorithm URI.
      assert {with_comments, 0} = System.cmd("xmllint", ["--nonet", "--exc-c14n", path])
      assert with_comments == "<r>A<!--known comment-->B&lt;value&gt;</r>"
      {:ok, root} = XML.parse(xml)
      assert XMLDSig.canonicalize(root) == String.replace(with_comments, "<!--known comment-->", "")
    end

    @tag :tmp_dir
    test "agrees with libxml2 for normalization, namespace reset, CDATA and xml attributes", %{tmp_dir: tmp_dir} do
      xml = ~s(<r xmlns="urn:r" xmlns:z="urn:z" xml:lang="en" z:a="z" xml:space="preserve" a="a\tB\r\nC&#x9;&#xA;&#xD;&gt;">A\r\nB\rC<![CDATA[<d>\rE]]><n xmlns=""><z:c/></n></r>)
      path = Path.join(tmp_dir, "normalization.xml")
      File.write!(path, xml)
      assert {expected, 0} = System.cmd("xmllint", ["--nonet", "--exc-c14n", path])
      assert {:ok, root} = XML.parse(xml)
      assert XMLDSig.canonicalize(root) == expected
    end

    @tag :tmp_dir
    test "agrees with libxml2 for empty default namespace and attribute escaping", %{tmp_dir: tmp_dir} do
      xml = ~s(<r xmlns="" a="&gt;" xml:lang="en" xmlns:z="urn:z" z:a="x"/>)
      path = Path.join(tmp_dir, "empty-default.xml")
      File.write!(path, xml)
      assert {expected, 0} = System.cmd("xmllint", ["--nonet", "--exc-c14n", path])
      assert {:ok, root} = XML.parse(xml)
      assert XMLDSig.canonicalize(root) == expected
    end
  end
end
