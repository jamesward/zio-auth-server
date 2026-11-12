package com.jamesward.zioauthserver

import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.{JWKSet, RSAKey}
import com.nimbusds.jose.{JOSEObjectType, JWSAlgorithm, JWSHeader}
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import zio.*

/** Signs the access JWTs (session cookies and OAuth access tokens) and publishes the public key set at `/oauth/jwks`. */
trait JwtSigner:

  def sign(claims: JWTClaimsSet): UIO[String]

  def publicJwkSet: UIO[JWKSet]

object JwtSigner:

  /**
   * Reads the RS256 private JWK from `JWT_SIGNING_KEY_JWK`. Fails the layer on a missing variable, a malformed or
   * public-only JWK, a missing `kid`, or an `alg` other than RS256: silently falling back to an ephemeral key would mask
   * the misconfiguration and produce tokens that don't verify against `/oauth/jwks`.
   */
  val fromEnv: ZLayer[Any, Throwable, JwtSigner] = ZLayer {
    for
      raw <- System
               .env("JWT_SIGNING_KEY_JWK")
               .someOrFail(new Exception("missing env var: JWT_SIGNING_KEY_JWK"))
      key <- ZIO
               .attempt(RSAKey.parse(raw))
               .mapError(t => new Exception(s"JWT_SIGNING_KEY_JWK is not a valid JWK: ${t.getMessage}"))
      _   <- validateProdKey(key)
    yield fromKey(key)
  }

  def fromKey(rsaKey: RSAKey): JwtSigner =
    val kid        = rsaKey.getKeyID
    val signer     = new RSASSASigner(rsaKey)
    val publicKeys = new JWKSet(rsaKey.toPublicJWK)
    new JwtSigner:
      override def sign(claims: JWTClaimsSet): UIO[String] =
        ZIO.succeed {
          val header = new JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID(kid)
            .`type`(JOSEObjectType.JWT)
            .build()
          val signed = new SignedJWT(header, claims)
          signed.sign(signer)
          signed.serialize()
        }

      override def publicJwkSet: UIO[JWKSet] =
        ZIO.succeed(publicKeys)

  private def validateProdKey(key: RSAKey): IO[Exception, Unit] =
    for
      _ <- ZIO.unless(key.isPrivate)(
             ZIO.fail(new Exception(
               "JWT_SIGNING_KEY_JWK must include private key parameters (d, p, q, ...) — " +
                 "you appear to have given the public-only JWK"
             ))
           )
      _ <- Option(key.getKeyID).filter(_.nonEmpty) match
             case Some(_) => ZIO.unit
             case None    =>
               ZIO.fail(new Exception(
                 "JWT_SIGNING_KEY_JWK must include a non-empty 'kid' so resource " +
                   "servers can match signatures against entries in /oauth/jwks"
               ))
      _ <- Option(key.getAlgorithm).map(_.getName) match
             case Some("RS256") => ZIO.unit
             case Some(other)   => ZIO.fail(new Exception(s"JWT_SIGNING_KEY_JWK alg must be RS256, got: $other"))
             case None          => ZIO.fail(new Exception("JWT_SIGNING_KEY_JWK must declare alg=RS256"))
    yield ()
