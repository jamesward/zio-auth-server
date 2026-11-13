package com.jamesward.zioauthserver.testkit

import com.fasterxml.jackson.dataformat.cbor.{CBORFactory, CBORGenerator}
import com.jamesward.zioauthserver.Crypto
import zio.json.*
import zio.json.ast.Json

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets.UTF_8
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.{KeyPair, KeyPairGenerator, MessageDigest, SecureRandom, Signature}

/**
 * A passkey authenticator in memory, for tests: it answers the server's WebAuthn options the way a browser's
 * `navigator.credentials.create` / `get` would, with one ES256 credential and "none" attestation. Takes the `options`
 * JSON the passkey routes send and returns the credential JSON the browser would post back.
 */
final class SoftwareAuthenticator(origin: String):

  private val random                     = new SecureRandom()
  private var credential: Option[Stored] = None

  private final case class Stored(id: Array[Byte], keys: KeyPair, userHandle: Array[Byte], rpId: String, var count: Int)

  /** Answers `{"publicKey": {...}}` creation options; returns the registration credential JSON. */
  def register(options: Json): String =
    val pk        = publicKeyOf(options)
    val rpId      = pk.get(zio.json.ast.JsonCursor.field("rp").isObject.field("id").isString).toOption.map(_.value).get
    val user      = pk.get(zio.json.ast.JsonCursor.field("user").isObject.field("id").isString).toOption.map(_.value).get
    val challenge = stringField(pk, "challenge")
    val gen       = KeyPairGenerator.getInstance("EC")
    gen.initialize(new ECGenParameterSpec("secp256r1"))
    val keys      = gen.generateKeyPair()
    val id        = Array.ofDim[Byte](16)
    random.nextBytes(id)
    val stored    = Stored(id, keys, Crypto.decodeB64Url(user).toOption.get, rpId, 0)
    credential = Some(stored)

    val cose     = coseKey(keys.getPublic.asInstanceOf[ECPublicKey])
    val authData =
      sha256(rpId.getBytes(UTF_8)) ++ Array[Byte](0x45) ++ int32(0) ++ Array.ofDim[Byte](16) ++
        Array[Byte]((id.length >> 8).toByte, id.length.toByte) ++ id ++ cose
    val attestation = cbor { g =>
      g.writeStartObject()
      g.writeStringField("fmt", "none")
      g.writeFieldName("attStmt"); g.writeStartObject(); g.writeEndObject()
      g.writeFieldName("authData"); g.writeBinary(authData)
      g.writeEndObject()
    }
    val clientData = clientDataJson("webauthn.create", challenge)
    Json
      .Obj(
        "id"                     -> Json.Str(b64(id)),
        "rawId"                  -> Json.Str(b64(id)),
        "type"                   -> Json.Str("public-key"),
        "response"               -> Json.Obj(
          "clientDataJSON"    -> Json.Str(b64(clientData)),
          "attestationObject" -> Json.Str(b64(attestation)),
          "transports"        -> Json.Arr(Json.Str("internal")),
        ),
        "clientExtensionResults" -> Json.Obj(),
      )
      .toJson

  /** Answers `{"publicKey": {...}}` request options with the registered credential; returns the assertion JSON. */
  def signIn(options: Json): String =
    val stored    = credential.getOrElse(throw new IllegalStateException("no credential registered"))
    val challenge = stringField(publicKeyOf(options), "challenge")
    stored.count += 1
    val authData   = sha256(stored.rpId.getBytes(UTF_8)) ++ Array[Byte](0x05) ++ int32(stored.count)
    val clientData = clientDataJson("webauthn.get", challenge)
    val signer     = Signature.getInstance("SHA256withECDSA")
    signer.initSign(stored.keys.getPrivate)
    signer.update(authData ++ sha256(clientData))
    Json
      .Obj(
        "id"                     -> Json.Str(b64(stored.id)),
        "rawId"                  -> Json.Str(b64(stored.id)),
        "type"                   -> Json.Str("public-key"),
        "response"               -> Json.Obj(
          "clientDataJSON"    -> Json.Str(b64(clientData)),
          "authenticatorData" -> Json.Str(b64(authData)),
          "signature"         -> Json.Str(b64(signer.sign())),
          "userHandle"        -> Json.Str(b64(stored.userHandle)),
        ),
        "clientExtensionResults" -> Json.Obj(),
      )
      .toJson

  private def publicKeyOf(options: Json): Json =
    options.get(zio.json.ast.JsonCursor.field("publicKey")).toOption.getOrElse(options)

  private def stringField(json: Json, name: String): String =
    json.get(zio.json.ast.JsonCursor.field(name).isString).toOption.map(_.value).getOrElse(throw new IllegalArgumentException(s"no $name"))

  private def clientDataJson(kind: String, challenge: String): Array[Byte] =
    Json
      .Obj("type" -> Json.Str(kind), "challenge" -> Json.Str(challenge), "origin" -> Json.Str(origin), "crossOrigin" -> Json.Bool(false))
      .toJson
      .getBytes(UTF_8)

  // COSE_Key for EC2 P-256 / ES256: {1: 2, 3: -7, -1: 1, -2: x, -3: y}, with integer map keys.
  private def coseKey(key: ECPublicKey): Array[Byte] =
    cbor { g =>
      g.writeStartObject()
      g.writeFieldId(1); g.writeNumber(2)
      g.writeFieldId(3); g.writeNumber(-7)
      g.writeFieldId(-1); g.writeNumber(1)
      g.writeFieldId(-2); g.writeBinary(fixed32(key.getW.getAffineX.toByteArray))
      g.writeFieldId(-3); g.writeBinary(fixed32(key.getW.getAffineY.toByteArray))
      g.writeEndObject()
    }

  private def cbor(write: CBORGenerator => Unit): Array[Byte] =
    val out = new ByteArrayOutputStream()
    val g   = new CBORFactory().createGenerator(out)
    write(g)
    g.close()
    out.toByteArray

  private def fixed32(bytes: Array[Byte]): Array[Byte] =
    val trimmed = bytes.dropWhile(_ == 0)
    Array.fill[Byte](32 - trimmed.length)(0) ++ trimmed

  private def int32(n: Int): Array[Byte] = ByteBuffer.allocate(4).putInt(n).array()
  private def sha256(b: Array[Byte]): Array[Byte] = MessageDigest.getInstance("SHA-256").digest(b)
  private def b64(b: Array[Byte]): String = Crypto.encodeB64Url(b)
