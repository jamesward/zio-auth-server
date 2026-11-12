package com.jamesward.zioauthserver

import com.nimbusds.jwt.JWTClaimsSet

import java.time.Instant
import java.util.Date

/**
 * The claims of the first-party session access token, the short-lived JWT in the access cookie. It is the same RS256
 * family as the OAuth access tokens: one signing key, one `/oauth/jwks`.
 */
object SessionClaims:

  /**
   * base64url HMAC of the session's csrf token. Binds the double-submit cookie to this access token so other
   * first-party servers can validate CSRF without reloading the session row.
   */
  val CsrfClaim = "csrf_hash"

  def build(
      issuer:    String,
      subject:   UserId,
      scopes:    Set[OAuthScope],
      csrfHash:  CsrfTokenHash,
      now:       Instant,
      expiresAt: Instant,
      jti:       String,
  ): JWTClaimsSet =
    new JWTClaimsSet.Builder()
      .issuer(issuer)
      .subject(subject.value.toString)
      .issueTime(Date.from(now))
      .notBeforeTime(Date.from(now))
      .expirationTime(Date.from(expiresAt))
      .jwtID(jti)
      .claim("scope", OAuthScopeSet.render(scopes))
      .claim(CsrfClaim, Crypto.encodeB64Url(csrfHash.bytes))
      .build()
