defmodule Samly.Esaml do
  @moduledoc false

  import Record, only: [defrecord: 2, extract: 2]

  require Record

  @public_key_hrl "public_key/include/OTP-PUB-KEY.hrl"

  defrecord :esaml_org, name: "", displayname: "", url: ""
  defrecord :esaml_contact, name: "", email: ""

  defrecord :esaml_sp_metadata,
    org: {:esaml_org, "", "", ""},
    tech: {:esaml_contact, "", ""},
    signed_requests: true,
    signed_assertions: true,
    certificate: :undefined,
    cert_chain: [],
    entity_id: "",
    consumer_location: "",
    logout_location: :undefined

  defrecord :esaml_idp_metadata,
    org: {:esaml_org, "", "", ""},
    tech: {:esaml_contact, "", ""},
    signed_requests: true,
    certificate: :undefined,
    entity_id: "",
    login_location: "",
    logout_location: :undefined,
    name_format: :unknown

  defrecord :esaml_authnreq,
    version: "2.0",
    issue_instant: "",
    destination: "",
    issuer: "",
    name_format: :undefined,
    consumer_location: ""

  defrecord :esaml_subject,
    name: "",
    name_qualifier: :undefined,
    sp_name_qualifier: :undefined,
    name_format: :undefined,
    confirmation_method: :bearer,
    notonorafter: "",
    in_response_to: ""

  defrecord :esaml_assertion,
    version: "2.0",
    issue_instant: "",
    recipient: "",
    issuer: "",
    subject: {:esaml_subject, "", :undefined, :undefined, :undefined, :bearer, "", ""},
    conditions: [],
    attributes: [],
    authn: []

  defrecord :esaml_logoutreq,
    version: "2.0",
    issue_instant: "",
    destination: "",
    issuer: "",
    name: "",
    name_qualifier: :undefined,
    sp_name_qualifier: :undefined,
    name_format: :undefined,
    session_index: "",
    reason: :user,
    id: ""

  defrecord :esaml_logoutresp,
    version: "2.0",
    issue_instant: "",
    destination: "",
    issuer: "",
    status: :unknown,
    in_response_to: ""

  defrecord :esaml_response,
    version: "2.0",
    issue_instant: "",
    destination: "",
    issuer: "",
    status: :unknown,
    assertion: {:esaml_assertion, "2.0", "", "", "", {:esaml_subject, "", :undefined, :undefined, :undefined, :bearer, "", ""}, [], [], []}

  defrecord :esaml_sp,
    org: {:esaml_org, "", "", ""},
    tech: {:esaml_contact, "", ""},
    key: :undefined,
    certificate: :undefined,
    cert_chain: [],
    sp_sign_requests: false,
    idp_signs_assertions: true,
    idp_signs_envelopes: true,
    idp_signs_logout_requests: true,
    sp_sign_metadata: false,
    trusted_fingerprints: [],
    metadata_uri: "",
    consume_uri: "",
    logout_uri: :undefined,
    encrypt_mandatory: false,
    entity_id: :undefined,
    idp_entity_id: :undefined,
    allow_legacy_sha1: false

  defrecord :RSAPrivateKey, extract(:RSAPrivateKey, from_lib: @public_key_hrl)
end
