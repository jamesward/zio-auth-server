package com.jamesward.zioauthserver

import java.nio.charset.StandardCharsets.UTF_8
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object Crypto:

  private val b64UrlEncoder = Base64.getUrlEncoder.withoutPadding
  private val b64UrlDecoder = Base64.getUrlDecoder

  def encodeB64Url(bytes: Array[Byte]): String =
    b64UrlEncoder.encodeToString(bytes)

  def decodeB64Url(s: String): Either[String, Array[Byte]] =
    try Right(b64UrlDecoder.decode(s))
    catch case _: IllegalArgumentException => Left("not valid base64url")

  def hmacSha256(message: String, pepper: String): Array[Byte] =
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(pepper.getBytes(UTF_8), "HmacSHA256"))
    mac.doFinal(message.getBytes(UTF_8))

  /** Keyed variant taking the raw key bytes directly, rather than UTF-8-encoding a String pepper. */
  def hmacSha256(message: String, key: Array[Byte]): Array[Byte] =
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(key, "HmacSHA256"))
    mac.doFinal(message.getBytes(UTF_8))

  /**
   * Plain SHA-256, no pepper, used only for PKCE: the authorization server computes `base64UrlNoPad(SHA-256(verifier))`
   * and constant-time-compares it to the stored code_challenge. The verifier is high-entropy and client-private, so a
   * pepper would add no value and just diverge from RFC 7636.
   */
  def sha256(message: String): Array[Byte] =
    MessageDigest.getInstance("SHA-256").digest(message.getBytes(UTF_8))
