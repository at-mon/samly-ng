defmodule Samly.Test.SAMLFixture do
  @moduledoc false
  alias Samly.SAML.Key
  alias Samly.SAML.XMLDSig

  def response(recipient, opts \\ []) do
    {:ok, key} = Key.load_private_key("test/data/test.pem")
    {:ok, cert} = Key.load_certificate("test/data/test.crt")
    id = System.unique_integer([:positive])
    issued = DateTime.to_iso8601(DateTime.utc_now())
    expires = DateTime.to_iso8601(DateTime.shift(DateTime.utc_now(), minute: 5))
    response_to = Keyword.get(opts, :response_to)
    correlation = if response_to, do: ~s( InResponseTo="#{response_to}"), else: ""
    name = Keyword.get(opts, :name, "person@example.test")
    role = Keyword.get(opts, :role, "member")
    session_index = Keyword.get(opts, :session_index, "session-#{id}")

    assertion = """
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a#{id}" Version="2.0" IssueInstant="#{issued}"><saml:Issuer>urn:test:idp</saml:Issuer><saml:Subject><saml:NameID>#{name}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="#{recipient}"#{correlation} NotOnOrAfter="#{expires}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotOnOrAfter="#{expires}"><saml:AudienceRestriction><saml:Audience>urn:test:sp1</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="#{issued}" SessionIndex="#{session_index}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>#{role}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>
    """

    assertion = Keyword.get(opts, :transform, &Function.identity/1).(assertion)
    {:ok, assertion} = XMLDSig.sign(assertion, key, cert)

    response = """
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r#{id}"#{correlation} Version="2.0" IssueInstant="#{issued}" Destination="#{recipient}"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:test:idp</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>#{assertion}</samlp:Response>
    """

    if Keyword.get(opts, :sign_envelope, true) do
      {:ok, signed} = XMLDSig.sign(response, key, cert)
      signed
    else
      response
    end
  end
end
