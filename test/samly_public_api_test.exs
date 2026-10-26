defmodule Samly.PublicAPITest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Plug.Conn
  alias Samly.Assertion
  alias Samly.Esaml
  alias Samly.Helper
  alias Samly.IdpData
  alias Samly.Provider
  alias Samly.SAML.Key
  alias Samly.SAML.XML
  alias Samly.State
  alias Samly.State.Session
  alias Samly.Subject
  alias Samly.Test.SAMLFixture

  require Esaml

  setup do
    keys = [Provider, State, :service_providers, :identity_providers, :state_store, :idp_id_from]
    previous = Map.new(keys, &{&1, Application.fetch_env(:samly, &1)})

    on_exit(fn ->
      for {key, value} <- previous do
        case value do
          {:ok, value} -> Application.put_env(:samly, key, value)
          :error -> Application.delete_env(:samly, key)
        end
      end
    end)

    :ok
  end

  describe "application-facing assertion accessors" do
    test "missing authentication has no attributes or NameID" do
      conn = Plug.Test.init_test_session(Plug.Test.conn(:get, "/"), %{})
      assert Samly.get_active_assertion(conn) == nil
      assert Samly.get_attribute(nil, "role") == nil
      assert Samly.get_nameid(nil) == nil
    end

    test "computed attributes override IdP attributes while multivalues and Unicode remain intact" do
      assertion = %Assertion{
        subject: %Subject{name: "  José@example.test  "},
        attributes: %{"role" => "member", "groups" => ["engineering", "support"], "displayName" => "José"},
        computed: %{"role" => "admin", "empty" => ""}
      }

      assert Samly.get_attribute(assertion, "role") == "admin"
      assert Samly.get_attribute(assertion, "groups") == ["engineering", "support"]
      assert Samly.get_attribute(assertion, "displayName") == "José"
      assert Samly.get_attribute(assertion, "empty") == ""
      assert Samly.get_attribute(assertion, "missing") == nil
      assert Samly.get_nameid(assertion) == "  José@example.test  "
    end

    test "an opaque session locator resolves its own assertion and rejects another session" do
      State.init(Session)
      assertion = live_assertion()
      key = {"idp1", State.gen_id()}
      {idp_id, session_id} = key

      conn =
        :get
        |> Plug.Test.conn("/")
        |> Plug.Test.init_test_session(%{"samly_session" => {:v1, idp_id, session_id}})
        |> State.put_assertion(key, assertion)

      assert Samly.get_active_assertion(conn) == assertion
      assert Samly.get_active_assertion(Conn.put_session(conn, "samly_session", {:v1, idp_id, State.gen_id()})) == nil
      assert Samly.get_active_assertion(Conn.put_session(conn, "samly_session", {idp_id, assertion.subject.name})) == nil
    end
  end

  describe "legacy record compatibility" do
    test "subject roundtrip preserves identity whitespace, Unicode and qualifiers" do
      subject = %Subject{
        name: " user-é@example.test ",
        name_qualifier: "urn:issuer:tenant",
        sp_name_qualifier: "urn:sp:tenant",
        name_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        confirmation_method: :bearer,
        notonorafter: future(),
        in_response_to: "_request"
      }

      record = Subject.to_rec(subject)
      assert Esaml.esaml_subject(record, :name) == String.to_charlist(subject.name)
      assert Esaml.esaml_subject(record, :name_qualifier) == ~c"urn:issuer:tenant"
      assert Subject.from_rec(record) == subject
    end

    test "omitted optional subject fields stay undefined rather than literal strings" do
      subject = %Subject{name: "person@example.test"}
      assert Subject.from_rec(Subject.to_rec(subject)) == subject
      assert Esaml.esaml_subject(Subject.to_rec(subject), :name_format) == :undefined
    end

    test "assertion conversion preserves empty, scalar and multivalued record attributes" do
      expires = future()
      issued = DateTime.to_iso8601(DateTime.utc_now())
      subject = %Subject{name: "  principal  ", notonorafter: expires}

      record =
        Esaml.esaml_assertion(
          version: ~c"2.0",
          issue_instant: String.to_charlist(issued),
          recipient: ~c"https://sp.example/consume",
          issuer: ~c"urn:test:idp",
          subject: Subject.to_rec(subject),
          conditions: [not_on_or_after: String.to_charlist(expires), not_before: []],
          attributes: [{~c"displayName", ~c"José"}, {~c"groups", [~c"staff", ~c"admins"]}, {~c"empty", []}],
          authn: [session_index: ~c"session-1"]
        )

      assertion = Assertion.from_rec(record)
      assert assertion.version == "2.0"
      assert assertion.issue_instant == issued
      assert assertion.recipient == "https://sp.example/consume"
      assert assertion.issuer == "urn:test:idp"
      assert assertion.subject == subject
      assert assertion.conditions == %{"not_on_or_after" => expires, "not_before" => ""}
      assert assertion.attributes == %{"displayName" => "José", "groups" => ["staff", "admins"], "empty" => ""}
      assert assertion.authn == %{"session_index" => "session-1"}
      assert assertion.computed == %{}
      assert assertion.idp_id == ""
    end
  end

  describe "URI compatibility helpers" do
    test "defer endpoint construction when the base URL is unspecified" do
      assert Helper.get_metadata_uri(nil, "idp1") == nil
      assert Helper.get_consume_uri(nil, "idp1") == nil
      assert Helper.get_logout_uri(nil, "idp1") == nil
    end

    test "subdomain routing omits the IdP path segment" do
      assert Helper.get_metadata_uri("https://tenant.example/sso", nil) == ~c"https://tenant.example/sso/sp/metadata"
      assert Helper.get_consume_uri("https://tenant.example/sso", nil) == ~c"https://tenant.example/sso/sp/consume"
      assert Helper.get_logout_uri("https://tenant.example/sso", nil) == ~c"https://tenant.example/sso/sp/logout"
    end

    test "path routing returns legacy charlist endpoints" do
      assert Helper.get_metadata_uri("https://app.example/sso", "idp1") == ~c"https://app.example/sso/sp/metadata/idp1"
      assert Helper.get_consume_uri("https://app.example/sso", "idp1") == ~c"https://app.example/sso/sp/consume/idp1"
      assert Helper.get_logout_uri("https://app.example/sso", "idp1") == ~c"https://app.example/sso/sp/logout/idp1"
    end
  end

  describe "SAML compatibility helpers" do
    test "generates authentication requests with selected destination and ForceAuthn" do
      sp = signing_sp()
      metadata = idp_metadata()
      {destination, xml} = Helper.gen_idp_signin_req(sp, metadata, :unknown)
      assert destination == ~c"https://idp.example/sso"
      assert {:ok, root} = XML.parse(xml)
      assert XML.attribute(root, "Destination") == "https://idp.example/sso"
      assert XML.attribute(root, "AssertionConsumerServiceURL") == "https://sp.example/consume"
      assert XML.attribute(root, "ForceAuthn") == "false"
      assert XML.child(root, "Signature")

      {^destination, forced} = Helper.gen_idp_signin_req(sp, metadata, ~c"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", force_authn: true)
      assert {:ok, forced_root} = XML.parse(forced)
      assert XML.attribute(forced_root, "ForceAuthn") == "true"
      assert XML.attribute(XML.child(forced_root, "NameIDPolicy"), "Format") == "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    end

    test "generates metadata with the SP identity and consumer endpoint" do
      assert {:ok, root} = signing_sp() |> Helper.sp_metadata() |> XML.parse()
      assert XML.attribute(root, "entityID") == "urn:test:sp1"
      descriptor = XML.child(root, "SPSSODescriptor")
      assert XML.attribute(XML.child(descriptor, "AssertionConsumerService"), "Location") == "https://sp.example/consume"
      assert XML.child(root, "Signature")
    end

    test "generates logout requests preserving subject qualifiers and SessionIndex" do
      subject = %Subject{name: "person@example.test", name_qualifier: "urn:test:idp", sp_name_qualifier: "urn:test:sp1"}
      {destination, xml} = Helper.gen_idp_signout_req(signing_sp(), idp_metadata(), Subject.to_rec(subject), ~c"session-1")
      assert destination == ~c"https://idp.example/logout"
      assert {:ok, root} = XML.parse(xml)
      name = XML.child(root, "NameID")
      assert XML.text(name) == subject.name
      assert XML.attribute(name, "NameQualifier") == subject.name_qualifier
      assert XML.attribute(name, "SPNameQualifier") == subject.sp_name_qualifier
      assert XML.text(XML.child(root, "SessionIndex")) == "session-1"
    end

    test "generates successful logout responses with optional request correlation" do
      {destination, xml} = Helper.gen_idp_signout_resp(signing_sp(), idp_metadata(), :success, "_logout_request")
      assert destination == ~c"https://idp.example/logout"
      assert {:ok, root} = XML.parse(xml)
      assert XML.attribute(root, "InResponseTo") == "_logout_request"
      assert XML.attribute(XML.child(XML.child(root, "Status"), "StatusCode"), "Value") == "urn:oasis:names:tc:SAML:2.0:status:Success"

      {^destination, uncorrelated} = Helper.gen_idp_signout_resp(signing_sp(), idp_metadata(), :success)
      assert {:ok, root} = XML.parse(uncorrelated)
      assert XML.attribute(root, "InResponseTo") == nil
    end

    test "decodes authenticated responses and consumes each assertion only once" do
      sp = signing_sp()
      payload = "https://sp.example/consume" |> SAMLFixture.response() |> Base.encode64()
      assert {:ok, assertion, entries} = Helper.verify_idp_auth_resp(sp, nil, payload)
      assert assertion.subject.name == "person@example.test"
      assert [_ | _] = entries
      assert {:ok, ^assertion} = Helper.decode_idp_auth_resp(sp, nil, payload)
      assert {:error, _} = Helper.decode_idp_auth_resp(sp, nil, payload)
    end

    test "authentication and logout decoders return errors for malformed transport and XML" do
      sp = signing_sp()
      assert {:error, :invalid_base64} = Helper.decode_idp_auth_resp(sp, nil, "%%invalid%%")
      assert {:error, :invalid_base64} = Helper.verify_idp_auth_resp(sp, nil, "%%invalid%%")
      assert {:error, :invalid_request} = Helper.decode_idp_signout_req(sp, nil, "%%invalid%%")
      assert {:error, :invalid_request} = Helper.decode_idp_signout_resp(sp, nil, "%%invalid%%")
      assert {:error, :invalid_base64} = Helper.verify_idp_signout_resp(sp, nil, "%%invalid%%")
      assert {:error, _} = Helper.decode_idp_auth_resp(sp, nil, Base.encode64("<bad"))
      assert {:error, _} = Helper.decode_idp_signout_req(sp, nil, Base.encode64("<bad"))
      assert {:error, _} = Helper.decode_idp_signout_resp(sp, nil, Base.encode64("<bad"))
      assert {:error, _} = Helper.verify_idp_signout_resp(sp, nil, Base.encode64("<bad"))
    end
  end

  describe "provider initialization and refresh" do
    test "defaults to path routing and initializes ready ETS storage" do
      Application.delete_env(:samly, Provider)
      Application.delete_env(:samly, State)
      start_supervised!(Provider)
      assert Application.fetch_env!(:samly, :idp_id_from) == :path_segment
      assert %{provider: Samly.State.ETS, opts: table} = Application.fetch_env!(:samly, :state_store)
      assert :ets.info(table, :protection) == :protected
      assert Application.fetch_env!(:samly, :identity_providers) == %{}
      assert Application.fetch_env!(:samly, :service_providers) == %{}
      assert Helper.get_idp("missing") == nil
    end

    test "applies subdomain routing before loading records and passes store options" do
      Application.put_env(:samly, State, store: Session, opts: [key: "custom_assertion"])
      Application.put_env(:samly, Provider, provider_options(idp_id_from: :subdomain))
      start_supervised!(Provider)
      assert Application.fetch_env!(:samly, :idp_id_from) == :subdomain
      assert Application.fetch_env!(:samly, :state_store) == %{provider: Session, opts: %{key: "custom_assertion"}}
      assert %IdpData{valid?: true} = idp = Helper.get_idp("idp1")
      assert Esaml.esaml_sp(idp.esaml_sp_rec, :consume_uri) == ~c"https://sp.example/sso/sp/consume"
    end

    test "invalid routing options fall back safely without logging their content" do
      Application.put_env(:samly, State, store: Session)
      Application.put_env(:samly, Provider, provider_options(idp_id_from: "PRIVATE-CONFIG-SECRET"))

      logs = capture_log(fn -> start_supervised!(Provider) end)
      refute logs =~ "PRIVATE-CONFIG-SECRET"
      assert Application.fetch_env!(:samly, :idp_id_from) == :path_segment
      assert Esaml.esaml_sp(Helper.get_idp("idp1").esaml_sp_rec, :consume_uri) == ~c"https://sp.example/sso/sp/consume/idp1"
    end

    test "refresh replaces previous providers and drops invalid trust configuration" do
      Application.put_env(:samly, State, store: Session)
      Application.put_env(:samly, Provider, provider_options(idp_id_from: :path_segment))
      start_supervised!(Provider)
      assert Helper.get_idp("idp1")

      Application.put_env(:samly, Provider, service_providers: [], identity_providers: [%{id: "invalid", sp_id: "missing", metadata: "<bad"}])
      assert {:ok, %{}} = Provider.refresh_providers()
      assert Helper.get_idp("idp1") == nil
      assert Helper.get_idp("invalid") == nil
      assert Application.fetch_env!(:samly, :service_providers) == %{}
    end

    test "provider process status redacts sensitive runtime state" do
      status = Provider.format_status(%{state: %{key: "secret"}, message: {"secret", :request}, reason: "secret", log: ["secret"]})
      assert status == %{state: :redacted, message: :redacted, reason: :redacted, log: []}
    end
  end

  defp future, do: DateTime.to_iso8601(DateTime.shift(DateTime.utc_now(), minute: 5))

  defp live_assertion do
    expires = future()
    %Assertion{subject: %Subject{name: "person@example.test", notonorafter: expires}, conditions: %{"not_on_or_after" => expires}}
  end

  defp signing_sp do
    {:ok, key} = Key.load_private_key("test/data/test.pem")
    {:ok, certificate} = Key.load_certificate("test/data/test.crt")

    Esaml.esaml_sp(
      entity_id: ~c"urn:test:sp1",
      idp_entity_id: ~c"urn:test:idp",
      consume_uri: ~c"https://sp.example/consume",
      logout_uri: ~c"https://sp.example/logout",
      key: key,
      certificate: certificate,
      trusted_fingerprints: [{:sha256, :crypto.hash(:sha256, certificate)}],
      sp_sign_requests: true,
      sp_sign_metadata: true
    )
  end

  defp idp_metadata do
    Esaml.esaml_idp_metadata(entity_id: ~c"urn:test:idp", login_location: ~c"https://idp.example/sso", logout_location: ~c"https://idp.example/logout")
  end

  defp provider_options(extra) do
    Keyword.merge(
      [
        service_providers: [%{id: "sp1", entity_id: "urn:test:sp1", certfile: "test/data/test.crt", keyfile: "test/data/test.pem"}],
        identity_providers: [%{id: "idp1", sp_id: "sp1", base_url: "https://sp.example/sso", metadata_file: "test/data/idp_metadata.xml"}]
      ],
      extra
    )
  end
end
