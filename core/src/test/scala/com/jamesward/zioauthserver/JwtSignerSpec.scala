package com.jamesward.zioauthserver

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.jwk.{KeyUse, RSAKey}
import com.nimbusds.jwt.JWTClaimsSet
import zio.*
import zio.test.*

object JwtSignerSpec extends ZIOSpecDefault:

  private val build: ZIO[Any, Throwable, JwtSigner] =
    JwtSigner.fromEnv.build.provide(Scope.default).map(_.get[JwtSigner])

  private val validJwk: String =
    new RSAKeyGenerator(2048)
      .keyID("test-kid")
      .keyUse(KeyUse.SIGNATURE)
      .algorithm(JWSAlgorithm.RS256)
      .generate()
      .toJSONString

  private val publicOnlyJwk: String =
    RSAKey.parse(validJwk).toPublicJWK.toJSONString

  private val noKidJwk: String =
    new RSAKeyGenerator(2048)
      .keyUse(KeyUse.SIGNATURE)
      .algorithm(JWSAlgorithm.RS256)
      .generate()
      .toJSONString

  private val wrongAlgJwk: String =
    val k = new RSAKeyGenerator(2048)
      .keyID("test-kid")
      .keyUse(KeyUse.SIGNATURE)
      .algorithm(JWSAlgorithm.RS256)
      .generate()
    new RSAKey.Builder(k).algorithm(JWSAlgorithm.PS256).build().toJSONString

  override val spec = suite("JwtSigner.fromEnv")(

    test("fails when JWT_SIGNING_KEY_JWK is missing") {
      for
        result <- build.either
      yield assertTrue(
        result.isLeft,
        result.left.toOption.exists(_.getMessage.contains("missing env var: JWT_SIGNING_KEY_JWK")),
      )
    },

    test("fails when value is not valid JSON") {
      for
        _      <- TestSystem.putEnv("JWT_SIGNING_KEY_JWK", "not-json")
        result <- build.either
      yield assertTrue(
        result.isLeft,
        result.left.toOption.exists(_.getMessage.contains("not a valid JWK")),
      )
    },

    test("fails when value is JSON but not a JWK") {
      for
        _      <- TestSystem.putEnv("JWT_SIGNING_KEY_JWK", """{"foo":"bar"}""")
        result <- build.either
      yield assertTrue(
        result.isLeft,
        result.left.toOption.exists(_.getMessage.contains("not a valid JWK")),
      )
    },

    test("fails when JWK is public-only (no private params)") {
      for
        _      <- TestSystem.putEnv("JWT_SIGNING_KEY_JWK", publicOnlyJwk)
        result <- build.either
      yield assertTrue(
        result.isLeft,
        result.left.toOption.exists(_.getMessage.contains("private key parameters")),
      )
    },

    test("fails when JWK has no kid") {
      for
        _      <- TestSystem.putEnv("JWT_SIGNING_KEY_JWK", noKidJwk)
        result <- build.either
      yield assertTrue(
        result.isLeft,
        result.left.toOption.exists(_.getMessage.contains("kid")),
      )
    },

    test("fails when alg is not RS256") {
      for
        _      <- TestSystem.putEnv("JWT_SIGNING_KEY_JWK", wrongAlgJwk)
        result <- build.either
      yield assertTrue(
        result.isLeft,
        result.left.toOption.exists(_.getMessage.contains("RS256")),
      )
    },

    test("succeeds with a valid private RSA JWK and signs a token whose kid matches") {
      for
        _      <- TestSystem.putEnv("JWT_SIGNING_KEY_JWK", validJwk)
        signer <- build
        claims  = new JWTClaimsSet.Builder().subject("alice").build()
        jwtStr <- signer.sign(claims)
        parts   = jwtStr.split('.')
        header  = new String(java.util.Base64.getUrlDecoder.decode(parts(0)))
        jwks   <- signer.publicJwkSet
      yield assertTrue(
        parts.length == 3,
        header.contains(""""kid":"test-kid""""),
        header.contains(""""alg":"RS256""""),
        jwks.getKeys.size == 1,
        jwks.getKeys.get(0).getKeyID == "test-kid",
        !jwks.getKeys.get(0).asInstanceOf[RSAKey].isPrivate,
      )
    },

  )
