package com.jamesward.zioauthserver

import zio.*

import java.nio.charset.StandardCharsets.UTF_8
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.{GCMParameterSpec, SecretKeySpec}

/**
 * Encrypts upstream tokens before they are stored (AES-256-GCM, a random 12-byte nonce per value). The sealed form is
 * `v1.<base64url(nonce ++ ciphertext)>`; the version prefix leaves room to rotate the key or the algorithm.
 * `associatedData` (for example the user id and provider) binds a sealed value to its row, so it can't be copied to
 * another.
 */
final class TokenSealer private (key: SecretKeySpec):
  private val random = new SecureRandom()

  def seal(plaintext: String, associatedData: String): String =
    val nonce  = Array.ofDim[Byte](12)
    random.nextBytes(nonce)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce))
    cipher.updateAAD(associatedData.getBytes(UTF_8))
    "v1." + Crypto.encodeB64Url(nonce ++ cipher.doFinal(plaintext.getBytes(UTF_8)))

  def open(sealedValue: String, associatedData: String): Either[String, String] =
    for
      body  <- Option.when(sealedValue.startsWith("v1."))(sealedValue.drop(3)).toRight("unknown sealed-token version")
      bytes <- Crypto.decodeB64Url(body)
      _     <- Either.cond(bytes.length > 12, (), "sealed token too short")
      plain <- scala.util.Try {
                 val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                 cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, bytes.take(12)))
                 cipher.updateAAD(associatedData.getBytes(UTF_8))
                 new String(cipher.doFinal(bytes.drop(12)), UTF_8)
               }.toEither.left.map(_ => "sealed token does not open with this key")
    yield plain

object TokenSealer:
  /** From a 32-byte key, base64url (generate one with `openssl rand -base64 32 | tr '+/' '-_' | tr -d =`). */
  def fromBase64Url(key: String): Either[String, TokenSealer] =
    Crypto.decodeB64Url(key).flatMap { bytes =>
      Either.cond(bytes.length == 32, new TokenSealer(new SecretKeySpec(bytes, "AES")), "the key must be 32 bytes")
    }

  /** Reads `TOKEN_SEALING_KEY`. */
  val fromEnv: ZLayer[Any, Throwable, TokenSealer] = ZLayer {
    System
      .env("TOKEN_SEALING_KEY")
      .someOrFail(new Exception("missing env var: TOKEN_SEALING_KEY"))
      .flatMap(k => ZIO.fromEither(fromBase64Url(k)).mapError(m => new Exception(s"TOKEN_SEALING_KEY: $m")))
  }
