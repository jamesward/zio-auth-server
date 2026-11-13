package com.jamesward.zioauthserver.testkit

import com.jamesward.zioauthserver.*
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.jwk.{KeyUse, RSAKey}
import zio.*
import zio.http.URL

import java.time.Instant

/** Settings for local development over HTTP and for tests. */
object DevConfig:

  /** Plain cookie names and `secure = false`. */
  val cookies: CookieConfig =
    CookieConfig(sessionName = "sid", csrfName = "csrf", secure = false, accessName = "access", otpName = "otp")

  val pepper: Pepper = Pepper.of("dev-pepper-not-secret")

  def authServer(baseUrl: URL): AuthServerConfig =
    // Loopback CIMD documents: a dev or test client's metadata is served from localhost.
    AuthServerConfig(baseUrl = baseUrl, cookies = cookies, pepper = pepper, cimdAllowLoopback = true)

object DevSessions:

  /**
   * A session from caller-chosen session-id and csrf plaintext rather than random ones. A dev login can set a stable
   * cookie that matches a session row its dev seed re-creates on every boot, so the login survives restarts.
   */
  def fixed(cfg: AuthServerConfig, now: Instant, sid: SessionId, csrf: CsrfToken): Sessions.MintedSession =
    Sessions.fixed(cfg, now, sid, csrf)

object DevJwtSigner:

  /** A new RS256 key with a random `kid`. Also what an operator tool can print to bootstrap `JWT_SIGNING_KEY_JWK`. */
  def freshKey(): RSAKey =
    new RSAKeyGenerator(2048)
      .keyID(java.util.UUID.randomUUID().toString)
      .keyUse(KeyUse.SIGNATURE)
      .algorithm(JWSAlgorithm.RS256)
      .generate()

  /** A signer with a key made when the layer is built. Tokens don't verify across restarts. */
  val fresh: ULayer[JwtSigner] = ZLayer.succeed(JwtSigner.fromKey(freshKey()))

  /** A signer from a private JWK in JSON, for a dev key that stays the same across restarts. */
  def fromJson(privateJwk: String): Layer[Throwable, JwtSigner] =
    ZLayer(ZIO.attempt(JwtSigner.fromKey(RSAKey.parse(privateJwk))))
