package com.jamesward.zioauthserver

import zio.json.*

/** RFC 8414 authorization server metadata, served at `/.well-known/oauth-authorization-server`. */
final case class OAuthServerMetadata(
    issuer:                                        String,
    authorization_endpoint:                        String,
    token_endpoint:                                String,
    introspection_endpoint:                        String,
    revocation_endpoint:                           String,
    registration_endpoint:                         String,
    jwks_uri:                                      String,
    response_types_supported:                      List[String],
    grant_types_supported:                         List[String],
    code_challenge_methods_supported:              List[String],
    token_endpoint_auth_methods_supported:         List[String],
    revocation_endpoint_auth_methods_supported:    List[String],
    introspection_endpoint_auth_methods_supported: List[String],
    resource_indicators_supported:                 Boolean,
    client_id_metadata_document_supported:         Boolean,
)

object OAuthServerMetadata:
  given JsonEncoder[OAuthServerMetadata] = DeriveJsonEncoder.gen

  def forIssuer(issuer: String): OAuthServerMetadata =
    OAuthServerMetadata(
      issuer = issuer,
      authorization_endpoint = s"$issuer/oauth/authorize",
      token_endpoint = s"$issuer/oauth/token",
      introspection_endpoint = s"$issuer/oauth/introspect",
      revocation_endpoint = s"$issuer/oauth/revoke",
      registration_endpoint = s"$issuer/oauth/register",
      jwks_uri = s"$issuer/oauth/jwks",
      response_types_supported = List("code"),
      grant_types_supported = List("authorization_code", "refresh_token"),
      code_challenge_methods_supported = List("S256"),
      // 'none' lets Public clients (loopback MCP, browser clients) call /token without HTTP Basic: PKCE substitutes for
      // client auth.
      token_endpoint_auth_methods_supported = List("client_secret_basic", "none"),
      revocation_endpoint_auth_methods_supported = List("client_secret_basic", "none"),
      introspection_endpoint_auth_methods_supported = List("client_secret_basic", "none"),
      resource_indicators_supported = true,
      // CIMD (draft-ietf-oauth-client-id-metadata-document): a client may use an HTTPS URL as its `client_id`, which is
      // dereferenced to a metadata document instead of requiring pre-registration or DCR.
      client_id_metadata_document_supported = true,
    )
