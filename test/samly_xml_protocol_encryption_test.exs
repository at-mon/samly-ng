Code.require_file("support/xml_security_fixture.exs", __DIR__)

defmodule Samly.XMLProtocolEncryptionTest do
  use ExUnit.Case, async: true

  alias Samly.Esaml
  alias Samly.SAML.Key
  alias Samly.SAML.Protocol
  alias Samly.SAML.XML
  alias Samly.SAML.XMLDSig
  alias Samly.Test.SAMLFixture
  alias Samly.XMLSecurityFixture

  require Esaml

  @recipient "https://sp.example.test/consume"

  describe "encrypted response ingestion" do
    setup do
      {:ok, key} = Key.load_private_key("test/data/test.pem")
      {:ok, cert} = Key.load_certificate("test/data/test.crt")

      sp =
        Esaml.esaml_sp(
          key: key,
          consume_uri: to_charlist(@recipient),
          entity_id: ~c"urn:test:sp1",
          idp_entity_id: ~c"urn:test:idp",
          trusted_fingerprints: [{:sha256, :crypto.hash(:sha256, cert)}],
          idp_signs_envelopes: true,
          idp_signs_assertions: true,
          encrypt_mandatory: true
        )

      %{key: key, cert: cert, sp: sp}
    end

    test "verifies both signatures with encryption namespace declarations inherited from Response", context do
      xml = encrypted_response(context)
      assert {:ok, assertion} = Protocol.decode_authn_response(xml, context.sp)
      assert assertion.subject.name == "person@example.test"
      assert assertion.attributes["role"] == "member"
      assert {:error, :replayed} = Protocol.decode_authn_response(xml, context.sp)
    end

    test "supports assertion-only and envelope-only authentication", context do
      assertion_only = Esaml.esaml_sp(context.sp, idp_signs_envelopes: false)
      xml = encrypted_response(context, sign_envelope: false)
      assert {:ok, _} = Protocol.decode_authn_response(xml, assertion_only)

      envelope_only = Esaml.esaml_sp(context.sp, idp_signs_assertions: false)
      xml = encrypted_response(context, strip_assertion_signature: true)
      assert {:ok, _} = Protocol.decode_authn_response(xml, envelope_only)
    end

    test "rejects missing decryption key after checking the valid envelope", context do
      xml = encrypted_response(context)
      assert {:error, :missing_decryption_key} = Protocol.decode_authn_response(xml, Esaml.esaml_sp(context.sp, key: :undefined))
    end

    test "rejects modified ciphertext at envelope verification before attempting decryption", context do
      xml = context |> encrypted_response() |> tamper_ciphertext()
      # A missing key makes the sequencing observable without mocking crypto.
      assert {:error, :bad_digest} = Protocol.decode_authn_response(xml, Esaml.esaml_sp(context.sp, key: :undefined))
    end

    test "rejects unauthenticated ciphertext even inside a newly signed valid envelope", context do
      xml = context |> encrypted_response(sign_envelope: false) |> tamper_ciphertext() |> sign_envelope(context)
      assert {:error, :authentication_failed} = Protocol.decode_authn_response(xml, context.sp)
    end

    test "verifies the decrypted assertion signature in the reconstructed document", context do
      xml = encrypted_response(context, tamper_assertion: true)
      assert {:error, :bad_digest} = Protocol.decode_authn_response(xml, context.sp)
    end

    test "requires the decrypted assertion signature when configured", context do
      xml = encrypted_response(context, strip_assertion_signature: true)
      assert {:error, :no_signature} = Protocol.decode_authn_response(xml, context.sp)
    end
  end

  defp encrypted_response(context, opts \\ []) do
    response = SAMLFixture.response(@recipient, response_to: "_encrypted-request", sign_envelope: false)
    {:ok, {name, attributes, children} = root} = XML.parse(response)
    {:ok, assertion} = XML.exactly_one_child(root, "Assertion")
    assertion = prepare_assertion(assertion, opts)
    %{xml: encrypted} = XMLSecurityFixture.encryption(plaintext: XML.encode(assertion), hash: :sha256)
    {:ok, {encrypted_name, declarations, encrypted_children}} = XML.parse(encrypted)
    # Exercise Protocol's inherited namespace-context handoff to Encryption.
    encrypted_node = {encrypted_name, [], encrypted_children}
    children = Enum.map(children, fn child -> if XML.local_name(node_name(child)) == "Assertion", do: encrypted_node, else: child end)
    response = XML.encode({name, attributes ++ declarations, children})

    if Keyword.get(opts, :sign_envelope, true) do
      sign_envelope(response, context)
    else
      response
    end
  end

  defp prepare_assertion({name, attributes, children} = assertion, opts) do
    cond do
      Keyword.get(opts, :strip_assertion_signature, false) ->
        {name, attributes, Enum.reject(children, &(XML.local_name(node_name(&1)) == "Signature"))}

      Keyword.get(opts, :tamper_assertion, false) ->
        assertion |> XML.encode() |> String.replace("person@example.test", "attacker@example.test") |> XMLSecurityFixture.parse!()

      true ->
        assertion
    end
  end

  defp sign_envelope(xml, context) do
    {:ok, signed} = XMLDSig.sign(xml, context.key, context.cert)
    signed
  end

  defp tamper_ciphertext(xml) do
    [_, [_, encoded]] = Regex.scan(~r/<xenc:CipherValue>([^<]*)<\/xenc:CipherValue>/, xml)
    <<first, rest::binary>> = Base.decode64!(encoded)
    String.replace(xml, encoded, Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>))
  end

  defp node_name({name, _, _}), do: name
  defp node_name(_text), do: ""
end
