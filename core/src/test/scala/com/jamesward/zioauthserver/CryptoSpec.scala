package com.jamesward.zioauthserver

import zio.test.*

object CryptoSpec extends ZIOSpecDefault:

  override def spec = suite("Crypto")(

    suite("encodeB64Url / decodeB64Url")(
      test("round-trips arbitrary bytes (incl. zero, max, full byte range)") {
        val cases: List[Array[Byte]] = List(
          Array.empty[Byte],
          Array[Byte](0),
          Array[Byte](-1),
          Array[Byte](0, 1, 2, 3, 4, 5, 6, 7),
          (0 to 255).map(_.toByte).toArray,
        )
        val ok = cases.forall { bs =>
          Crypto.decodeB64Url(Crypto.encodeB64Url(bs)) match
            case Right(out) => out.toSeq == bs.toSeq
            case Left(_)    => false
        }
        assertTrue(ok)
      },
      test("encodes without padding (URL-safe)") {
        val s = Crypto.encodeB64Url(Array[Byte](0))
        assertTrue(!s.contains('='))
      },
      test("decodeB64Url rejects malformed input as Left, not throw") {
        val r = Crypto.decodeB64Url("not!valid!base64")
        assertTrue(r == Left("not valid base64url"))
      },
    ),

    suite("hmacSha256")(
      test("different peppers produce different output for the same message") {
        val a = Crypto.hmacSha256("hello", "pepper-1")
        val b = Crypto.hmacSha256("hello", "pepper-2")
        assertTrue(a.toSeq != b.toSeq)
      },
      test("different messages produce different output for the same pepper") {
        val a = Crypto.hmacSha256("hello", "pepper-1")
        val b = Crypto.hmacSha256("world", "pepper-1")
        assertTrue(a.toSeq != b.toSeq)
      },
      test("matches RFC 4231 test case 1: key=0x0b*20, data='Hi There'") {
        // RFC 4231 §4.2 test case 1 — 20 bytes of 0x0b, data "Hi There".
        // Expected: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
        val key = String(Array.fill[Byte](20)(0x0b), java.nio.charset.StandardCharsets.UTF_8)
        val out = Crypto.hmacSha256("Hi There", key)
        val hex = out.map("%02x".format(_)).mkString
        assertTrue(hex == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
      },
    ),

    suite("sha256")(
      test("matches the well-known SHA-256 of the empty string") {
        val out = Crypto.sha256("")
        val hex = out.map("%02x".format(_)).mkString
        assertTrue(hex == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
      },
      test("matches the well-known SHA-256 of 'abc'") {
        val out = Crypto.sha256("abc")
        val hex = out.map("%02x".format(_)).mkString
        assertTrue(hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
      },
    ),

  )
