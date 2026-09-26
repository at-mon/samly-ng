defmodule Samly.SAML.Protocol do
  @moduledoc false

  alias Samly.Assertion
  alias Samly.Esaml
  alias Samly.ReplayCache
  alias Samly.SAML.Encryption
  alias Samly.SAML.XML
  alias Samly.SAML.XMLDSig
  alias Samly.Subject

  require Esaml

  @protocol_ns "urn:oasis:names:tc:SAML:2.0:protocol"
  @assertion_ns "urn:oasis:names:tc:SAML:2.0:assertion"
  @metadata_ns "urn:oasis:names:tc:SAML:2.0:metadata"
  @post_binding "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  @success "urn:oasis:names:tc:SAML:2.0:status:Success"

  def metadata(sp) do
    entity_id = entity_id(sp)
    consume = sp |> Esaml.esaml_sp(:consume_uri) |> to_string()
    logout = sp |> Esaml.esaml_sp(:logout_uri) |> optional_string()
    cert = Esaml.esaml_sp(sp, :certificate)

    descriptor_children =
      Enum.reject(
        [
          {"md:KeyDescriptor", [{"use", "signing"}], [key_info(cert)]},
          {"md:SingleLogoutService", [{"Binding", @post_binding}, {"Location", logout || ""}], []},
          {"md:NameIDFormat", [], ["urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"]},
          {"md:AssertionConsumerService",
           [
             {"Binding", @post_binding},
             {"Location", consume},
             {"index", "0"},
             {"isDefault", "true"}
           ], []}
        ],
        fn
          {"md:KeyDescriptor", _, _} -> cert == :undefined
          {"md:SingleLogoutService", _, _} -> is_nil(logout)
          _ -> false
        end
      )

    {"md:EntityDescriptor", [{"xmlns:md", @metadata_ns}, {"entityID", entity_id}, {"ID", fresh_id()}],
     [
       {"md:SPSSODescriptor",
        [
          {"AuthnRequestsSigned", bool(Esaml.esaml_sp(sp, :sp_sign_requests))},
          {"WantAssertionsSigned", bool(Esaml.esaml_sp(sp, :idp_signs_assertions))},
          {"protocolSupportEnumeration", @protocol_ns}
        ], descriptor_children}
     ]}
    |> XML.encode()
    |> maybe_sign(sp, :sp_sign_metadata)
  end

  def authn_request(destination, sp, nameid_format, opts \\ []) do
    force_authn = Keyword.get(opts, :force_authn, false)

    "AuthnRequest"
    |> request(
      destination,
      sp,
      [
        {"AssertionConsumerServiceURL", sp |> Esaml.esaml_sp(:consume_uri) |> to_string()},
        {"ProtocolBinding", @post_binding},
        {"ForceAuthn", bool(force_authn)}
      ],
      [name_id_policy(nameid_format)]
    )
    |> maybe_sign(sp, :sp_sign_requests)
  end

  def logout_request(destination, sp, subject_rec, session_index) do
    subject = Subject.from_rec(subject_rec)

    "LogoutRequest"
    |> request(destination, sp, [], [
      {"saml:NameID", subject_attributes(subject), [subject.name]},
      {"samlp:SessionIndex", [], [to_string(session_index)]}
    ])
    |> maybe_sign(sp, :sp_sign_requests)
  end

  def logout_response(destination, sp, status, in_response_to \\ nil) do
    status_uri = if status in [:success, @success], do: @success, else: to_string(status)
    correlation = if in_response_to, do: [{"InResponseTo", in_response_to}], else: []

    "LogoutResponse"
    |> request(destination, sp, correlation, [
      {"samlp:Status", [], [{"samlp:StatusCode", [{"Value", status_uri}], []}]}
    ])
    |> maybe_sign(sp, :sp_sign_requests)
  end

  def decode_authn_response(xml, sp) do
    with {:ok, root} <- XML.parse(xml),
         :ok <- root_named(root, "Response"),
         :ok <- require_authentication(sp),
         :ok <- success_status(root),
         :ok <- verify_if_required(root, root, sp, :idp_signs_envelopes),
         {:ok, assertion_node, verification_document} <- extract_assertion(root, sp),
         :ok <- root_named(verification_document, "Response"),
         :ok <- assertion_structure(assertion_node),
         :ok <- verify_if_required(verification_document, assertion_node, sp, :idp_signs_assertions),
         :ok <- validate_destination(root, sp),
         :ok <- validate_issuer(root, sp),
         :ok <- validate_issuer(assertion_node, sp),
         :ok <- validate_assertion(assertion_node, sp),
         :ok <- validate_response_correlation(root, assertion_node, sp),
         :ok <- prevent_replay(root, assertion_node, sp) do
      {:ok, build_assertion(assertion_node, sp)}
    end
  end

  defp require_authentication(sp) do
    if sp_flag(sp, :idp_signs_envelopes) or sp_flag(sp, :idp_signs_assertions), do: :ok, else: {:error, :unsigned_assertions_disabled}
  end

  defp validate_response_correlation(root, assertion, sp) do
    {:ok, confirmation} = valid_bearer_confirmation(assertion, to_string(Esaml.esaml_sp(sp, :consume_uri)))
    response_to = XML.attribute(root, "InResponseTo") || ""
    confirmation_to = XML.attribute(confirmation, "InResponseTo") || ""
    if response_to == confirmation_to, do: :ok, else: {:error, :invalid_in_response_to}
  end

  def decode_logout_response(xml, sp) do
    with {:ok, root} <- XML.parse(xml),
         :ok <- root_named(root, "LogoutResponse"),
         :ok <- verify_if_required(root, root, sp, :idp_signs_logout_requests),
         :ok <- success_status(root),
         :ok <- validate_logout(root, sp) do
      {:ok, Esaml.esaml_logoutresp(status: :success, in_response_to: XML.attribute(root, "InResponseTo") || "")}
    end
  end

  def decode_logout_request(xml, sp) do
    with {:ok, root} <- XML.parse(xml),
         :ok <- root_named(root, "LogoutRequest"),
         :ok <- verify_if_required(root, root, sp, :idp_signs_logout_requests),
         :ok <- validate_logout(root, sp) do
      {:ok,
       Esaml.esaml_logoutreq(
         id: XML.attribute(root, "ID"),
         name: root |> first("NameID") |> XML.text() |> to_charlist(),
         issuer: root |> first("Issuer") |> XML.text() |> to_charlist(),
         session_index: root |> first("SessionIndex") |> XML.text() |> to_charlist()
       )}
    end
  end

  defp validate_logout(root, sp) do
    with :ok <- validate_issuer(root, sp),
         true <- XML.attribute(root, "Destination") == optional_string(Esaml.esaml_sp(sp, :logout_uri)),
         {:ok, issued, _} <- DateTime.from_iso8601(XML.attribute(root, "IssueInstant") || ""),
         age = DateTime.diff(DateTime.utc_now(), issued),
         true <- age >= -120 and age < 420,
         :ok <- after_or_missing(DateTime.utc_now(), XML.attribute(root, "NotOnOrAfter")),
         id when is_binary(id) and id != "" <- XML.attribute(root, "ID") do
      ReplayCache.consume("logout:" <> id, DateTime.shift(issued, minute: 7))
    else
      {:error, :invalid_issuer} = error ->
        error

      false ->
        if XML.attribute(root, "Destination") == optional_string(Esaml.esaml_sp(sp, :logout_uri)), do: {:error, :invalid_logout_time}, else: {:error, :invalid_logout_destination}

      _ ->
        {:error, :invalid_logout_time}
    end
  end

  def message_id(xml) do
    with {:ok, root} <- XML.parse(xml),
         id when is_binary(id) and id != "" <- XML.attribute(root, "ID") do
      {:ok, id}
    else
      _ -> {:error, :missing_message_id}
    end
  end

  defp request(type, destination, sp, extra_attributes, children) do
    attributes =
      [
        {"xmlns:samlp", @protocol_ns},
        {"xmlns:saml", @assertion_ns},
        {"ID", fresh_id()},
        {"Version", "2.0"},
        {"IssueInstant", DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()},
        {"Destination", to_string(destination)}
      ] ++ extra_attributes

    XML.encode({"samlp:" <> type, attributes, [{"saml:Issuer", [], [entity_id(sp)]} | children]})
  end

  defp key_info(:undefined), do: {"md:KeyInfo", [], []}

  defp key_info(cert) do
    {"ds:KeyInfo", [{"xmlns:ds", "http://www.w3.org/2000/09/xmldsig#"}], [{"ds:X509Data", [], [{"ds:X509Certificate", [], [Base.encode64(cert)]}]}]}
  end

  defp name_id_policy(:unknown), do: {"samlp:NameIDPolicy", [{"AllowCreate", "true"}], []}
  defp name_id_policy(:undefined), do: name_id_policy(:unknown)

  defp name_id_policy(format) do
    {"samlp:NameIDPolicy", [{"AllowCreate", "true"}, {"Format", to_string(format)}], []}
  end

  defp subject_attributes(subject) do
    [
      {"NameQualifier", subject.name_qualifier},
      {"SPNameQualifier", subject.sp_name_qualifier},
      {"Format", subject.name_format}
    ]
    |> Enum.reject(fn {_key, value} -> value in [:undefined, nil, ""] end)
    |> Enum.map(fn {key, value} -> {key, to_string(value)} end)
  end

  defp root_named({name, _, _} = root, wanted) do
    vocabulary =
      Map.merge(
        Map.new(~w(Response LogoutResponse LogoutRequest Status StatusCode StatusMessage StatusDetail), &{&1, @protocol_ns}),
        Map.new(
          ~w(Assertion EncryptedAssertion Issuer Subject NameID SubjectConfirmation SubjectConfirmationData Conditions AudienceRestriction Audience AttributeStatement Attribute AttributeValue AuthnStatement AuthnContext AuthnContextClassRef),
          &{&1, @assertion_ns}
        )
      )

    if XML.local_name(name) == wanted and XML.attribute(root, "Version") == "2.0" and
         XML.valid_namespaces?(root, vocabulary), do: :ok, else: {:error, :invalid_request}
  end

  defp assertion_structure(assertion) do
    with "2.0" <- XML.attribute(assertion, "Version"),
         [subject] <- XML.children(assertion, "Subject"),
         [_name] <- XML.children(subject, "NameID"),
         [_conditions] <- XML.children(assertion, "Conditions"),
         [_issuer] <- XML.children(assertion, "Issuer") do
      :ok
    else
      _ -> {:error, :invalid_assertion_structure}
    end
  end

  defp success_status(root) do
    case root |> first("StatusCode") |> then(&if(&1, do: XML.attribute(&1, "Value"))) do
      @success -> :ok
      nil -> {:error, :missing_status}
      status -> {:error, {:saml_error, status}}
    end
  end

  defp extract_assertion(root, sp) do
    assertions = XML.children(root, "Assertion")
    encrypted = XML.children(root, "EncryptedAssertion")

    case {assertions, encrypted} do
      {[assertion], []} ->
        if Esaml.esaml_sp(sp, :encrypt_mandatory), do: {:error, :encryption_required}, else: {:ok, assertion, root}

      {[], [encrypted_assertion]} ->
        with {:ok, assertion} <- Encryption.decrypt(encrypted_assertion, Esaml.esaml_sp(sp, :key)) do
          {name, attrs, children} = root
          document = {name, attrs, replace_child(children, encrypted_assertion, assertion)}
          {:ok, assertion, document}
        end

      {[], []} ->
        {:error, :missing_assertion}

      _ ->
        {:error, :multiple_assertions}
    end
  end

  defp replace_child(children, old, replacement) do
    Enum.map(children, fn
      ^old -> replacement
      child -> child
    end)
  end

  defp validate_destination(root, sp) do
    expected = sp |> Esaml.esaml_sp(:consume_uri) |> to_string()

    case XML.attribute(root, "Destination") do
      ^expected -> :ok
      _ -> {:error, :invalid_destination}
    end
  end

  defp validate_issuer(assertion, sp) do
    expected = sp |> Esaml.esaml_sp(:idp_entity_id) |> optional_string()
    actual = assertion |> XML.child("Issuer") |> XML.text()

    if expected not in [nil, ""] and actual == expected, do: :ok, else: {:error, :invalid_issuer}
  end

  defp validate_assertion(assertion, sp) do
    expected_recipient = sp |> Esaml.esaml_sp(:consume_uri) |> to_string()
    expected_audience = entity_id(sp)

    with {:ok, confirmation} <- valid_bearer_confirmation(assertion, expected_recipient),
         :ok <- validate_audiences(assertion, expected_audience),
         :ok <- validate_unique_attributes(assertion) do
      validate_times(assertion, confirmation)
    end
  end

  defp validate_times(assertion, confirmation) do
    now = DateTime.utc_now()
    conditions = XML.child(assertion, "Conditions")

    with :ok <- before_or_missing(now, attribute(conditions, "NotBefore")),
         :ok <- after_or_missing(now, attribute(conditions, "NotOnOrAfter")) do
      after_or_missing(now, attribute(confirmation, "NotOnOrAfter"))
    end
  end

  defp valid_bearer_confirmation(assertion, expected_recipient) do
    assertion
    |> XML.child("Subject")
    |> XML.children("SubjectConfirmation")
    |> Enum.find_value({:error, :invalid_subject_confirmation}, fn confirmation ->
      data = confirmation |> XML.children("SubjectConfirmationData") |> List.first()

      if attribute(confirmation, "Method") ==
           "urn:oasis:names:tc:SAML:2.0:cm:bearer" and
           attribute(data, "Recipient") == expected_recipient and
           is_binary(attribute(data, "NotOnOrAfter")) do
        {:ok, data}
      end
    end)
  end

  defp validate_audiences(assertion, expected) do
    restrictions = assertion |> XML.child("Conditions") |> XML.children("AudienceRestriction")

    valid? =
      restrictions != [] and
        Enum.all?(restrictions, fn restriction ->
          restriction |> XML.children("Audience") |> Enum.any?(&(XML.text(&1) == expected))
        end)

    if valid?, do: :ok, else: {:error, :invalid_audience}
  end

  defp validate_unique_attributes(assertion) do
    names = assertion |> assertion_attributes() |> Enum.map(&XML.attribute(&1, "Name"))
    if length(names) == length(Enum.uniq(names)), do: :ok, else: {:error, :duplicate_attribute}
  end

  defp prevent_replay(response, assertion, sp) do
    with response_id when is_binary(response_id) and response_id != "" <-
           XML.attribute(response, "ID"),
         assertion_id when is_binary(assertion_id) and assertion_id != "" <-
           XML.attribute(assertion, "ID"),
         {:ok, confirmation} <- valid_bearer_confirmation(assertion, to_string(Esaml.esaml_sp(sp, :consume_uri))),
         {:ok, expires_at} <- replay_expiry(confirmation),
         :ok <- ReplayCache.consume("response:" <> response_id, expires_at),
         :ok <- ReplayCache.consume("assertion:" <> assertion_id, expires_at) do
      :ok
    else
      nil -> {:error, :missing_message_id}
      "" -> {:error, :missing_message_id}
      {:error, _reason} = error -> error
    end
  end

  defp replay_expiry(confirmation) do
    value = attribute(confirmation, "NotOnOrAfter")

    case value && DateTime.from_iso8601(value) do
      {:ok, expires_at, _offset} -> {:ok, DateTime.shift(expires_at, minute: 2)}
      _ -> {:error, :missing_replay_expiry}
    end
  end

  defp before_or_missing(_now, nil), do: :ok
  defp before_or_missing(now, value), do: compare_time(now, value, :before)
  defp after_or_missing(_now, nil), do: :ok
  defp after_or_missing(now, value), do: compare_time(now, value, :after)

  defp compare_time(now, value, direction) do
    case DateTime.from_iso8601(value) do
      {:ok, time, _} when direction == :before ->
        if DateTime.before?(now, DateTime.shift(time, minute: -2)),
          do: {:error, :assertion_not_yet_valid},
          else: :ok

      {:ok, time, _} ->
        if DateTime.before?(now, DateTime.shift(time, minute: 2)),
          do: :ok,
          else: {:error, :assertion_expired}

      _ ->
        {:error, :invalid_timestamp}
    end
  end

  defp build_assertion(node, sp) do
    subject_node = XML.child(node, "Subject")
    name_node = XML.child(subject_node, "NameID")
    {:ok, confirmation} = valid_bearer_confirmation(node, to_string(Esaml.esaml_sp(sp, :consume_uri)))

    %Assertion{
      version: XML.attribute(node, "Version") || "2.0",
      issue_instant: XML.attribute(node, "IssueInstant") || "",
      recipient: attribute(confirmation, "Recipient") || "",
      issuer: node |> first("Issuer") |> XML.text(),
      subject: %Subject{
        name: XML.text(name_node),
        name_qualifier: attribute(name_node, "NameQualifier") || :undefined,
        sp_name_qualifier: attribute(name_node, "SPNameQualifier") || :undefined,
        name_format: attribute(name_node, "Format") || :undefined,
        notonorafter: attribute(confirmation, "NotOnOrAfter") || "",
        in_response_to: attribute(confirmation, "InResponseTo") || ""
      },
      attributes: attributes(node),
      conditions: conditions(node),
      authn: authn(node)
    }
  end

  defp attributes(node) do
    node
    |> assertion_attributes()
    |> Map.new(fn attribute_node ->
      values = attribute_node |> XML.children("AttributeValue") |> Enum.map(&XML.text/1)
      value = if length(values) == 1, do: hd(values), else: values
      {XML.attribute(attribute_node, "Name") || "", value}
    end)
  end

  defp assertion_attributes(assertion) do
    assertion |> XML.children("AttributeStatement") |> Enum.flat_map(&XML.children(&1, "Attribute"))
  end

  defp conditions(node) do
    case XML.child(node, "Conditions") do
      nil ->
        %{}

      conditions ->
        Map.new([
          {"not_before", attribute(conditions, "NotBefore") || ""},
          {"not_on_or_after", attribute(conditions, "NotOnOrAfter") || ""}
        ])
    end
  end

  defp authn(node) do
    case XML.child(node, "AuthnStatement") do
      nil -> %{}
      statement -> %{"session_index" => XML.attribute(statement, "SessionIndex") || ""}
    end
  end

  defp first(node, name), do: node |> XML.descendants(name) |> List.first()
  defp attribute(nil, _name), do: nil
  defp attribute(node, name), do: XML.attribute(node, name)

  defp entity_id(sp) do
    case Esaml.esaml_sp(sp, :entity_id) do
      :undefined -> sp |> Esaml.esaml_sp(:metadata_uri) |> to_string()
      value -> to_string(value)
    end
  end

  defp optional_string(:undefined), do: nil
  defp optional_string(nil), do: nil
  defp optional_string(value), do: to_string(value)
  defp bool(true), do: "true"
  defp bool(false), do: "false"

  defp fresh_id, do: "_" <> Base.url_encode64(:crypto.strong_rand_bytes(20), padding: false)

  defp maybe_sign(xml, sp, flag) do
    if sp_flag(sp, flag) do
      case XMLDSig.sign(xml, Esaml.esaml_sp(sp, :key), Esaml.esaml_sp(sp, :certificate)) do
        {:ok, signed} -> signed
        {:error, reason} -> raise "could not sign SAML document: #{inspect(reason)}"
      end
    else
      xml
    end
  end

  defp verify_if_required(document, node, sp, flag) do
    if sp_flag(sp, flag) do
      XMLDSig.verify(document, node, Esaml.esaml_sp(sp, :trusted_fingerprints), allow_legacy_sha1: Esaml.esaml_sp(sp, :allow_legacy_sha1))
    else
      :ok
    end
  end

  defp sp_flag(sp, :sp_sign_metadata), do: Esaml.esaml_sp(sp, :sp_sign_metadata)
  defp sp_flag(sp, :sp_sign_requests), do: Esaml.esaml_sp(sp, :sp_sign_requests)
  defp sp_flag(sp, :idp_signs_envelopes), do: Esaml.esaml_sp(sp, :idp_signs_envelopes)
  defp sp_flag(sp, :idp_signs_assertions), do: Esaml.esaml_sp(sp, :idp_signs_assertions)

  defp sp_flag(sp, :idp_signs_logout_requests), do: Esaml.esaml_sp(sp, :idp_signs_logout_requests)
end
