package com.jamesward.zioauthserver

import zio.*
import zio.test.*

import java.time.Instant

object EmailOtpChallengeSpec extends ZIOSpecDefault:

  private given CanEqual[EmailOtpChallenge, EmailOtpChallenge] = CanEqual.derived
  private given CanEqual[Instant, Instant]                     = CanEqual.derived

  private val email    = Email.parse("alice@example.com").toOption.get
  private val code     = OtpCode.parse("123456").toOption.get
  private val pepper   = "otp-spec-pepper"
  private val codeHash = OtpCodeHash.hash(email, code, pepper)
  private val wrong    = OtpCodeHash.hash(email, OtpCode.parse("654321").toOption.get, pepper)
  private val cid      = EmailOtpChallengeId.fresh(java.util.UUID.fromString("00000000-0000-0000-0000-0000000000bb"))
  private val now      = Instant.parse("2025-01-01T12:00:00Z")

  private val pending: EmailOtpChallenge = EmailOtpChallenge(
    id         = cid,
    email      = email,
    codeHash   = codeHash,
    issuedAt   = now,
    expiresAt  = now.plusSeconds(600),
    consumedAt = None,
    attempts   = 0,
  )

  override def spec = suite("EmailOtpChallenge")(

    suite("OtpCode.parse")(
      test("accepts exactly six digits") {
        assertTrue(OtpCode.parse("012345").map(_.value) == Right("012345"))
      },
      test("strips the spacing people paste along with the code") {
        assertTrue(
          OtpCode.parse("123 456").map(_.value) == Right("123456"),
          OtpCode.parse("123-456").map(_.value) == Right("123456"),
          OtpCode.parse(" 123456\n").map(_.value) == Right("123456"),
        )
      },
      test("rejects empty, non-digit and wrong-length input") {
        assertTrue(
          OtpCode.parse("")        == Left(OtpCode.InvalidOtpCode.Empty),
          OtpCode.parse("   ")     == Left(OtpCode.InvalidOtpCode.Empty),
          OtpCode.parse("12345a")  == Left(OtpCode.InvalidOtpCode.NotDigits),
          OtpCode.parse("12345")   == Left(OtpCode.InvalidOtpCode.WrongLength),
          OtpCode.parse("1234567") == Left(OtpCode.InvalidOtpCode.WrongLength),
        )
      },
    ),

    suite("OtpCode.mint")(
      test("always mints a parseable six-digit code") {
        ZIO
          .foreach(1 to 200)(_ => OtpCode.mint)
          .map { codes =>
            assertTrue(
              codes.forall(c => c.value.length == OtpCode.length),
              codes.forall(c => OtpCode.parse(c.value).isRight),
              // Leading zeros must survive: "000123" is a valid code, and a
              // numeric formatting slip would show up as a short string.
              codes.forall(c => c.value.forall(ch => ch >= '0' && ch <= '9')),
            )
          }
          .provide(SecureRandomGen.live)
      },
      test("does not keep minting the same code") {
        ZIO
          .foreach(1 to 50)(_ => OtpCode.mint)
          .map(codes => assertTrue(codes.map(_.value).distinct.length > 1))
          .provide(SecureRandomGen.live)
      },
    ),

    suite("OtpCodeHash")(
    ),

    suite("consume")(

      test("Expired at and after expiresAt (boundary: end-exclusive)") {
        assertTrue(
          EmailOtpChallenge.consume(pending, codeHash, pending.expiresAt) == Left(EmailOtpChallenge.ConsumeError.Expired),
          EmailOtpChallenge.consume(pending, codeHash, pending.expiresAt.plusSeconds(1)) == Left(EmailOtpChallenge.ConsumeError.Expired),
        )
      },

      test("just before expiry still succeeds") {
        val at = pending.expiresAt.minusNanos(1)
        assertTrue(EmailOtpChallenge.consume(pending, codeHash, at).map(_.consumedAt).contains(Some(at)))
      },

      test("the last attempt within the budget still works") {
        val nearly = pending.copy(attempts = EmailOtpChallenge.maxAttempts - 1)
        assertTrue(EmailOtpChallenge.consume(nearly, codeHash, now).map(_.consumedAt) == Right(Some(now)))
      },

      test("TooManyAttempts outranks every other failure: a locked challenge answers nothing else") {
        val locked = pending.copy(
          attempts   = EmailOtpChallenge.maxAttempts + 1,
          consumedAt = Some(now),
          expiresAt  = now.minusSeconds(1),
        )
        assertTrue(EmailOtpChallenge.consume(locked, wrong, now) == Left(EmailOtpChallenge.ConsumeError.TooManyAttempts))
      },

      test("CodeMismatch is checked before AlreadyConsumed and Expired (fail closed on a bad code)") {
        val used    = pending.copy(consumedAt = Some(now.minusSeconds(1)))
        val expired = pending.copy(expiresAt = now.minusSeconds(1))
        assertTrue(
          EmailOtpChallenge.consume(used, wrong, now)    == Left(EmailOtpChallenge.ConsumeError.CodeMismatch),
          EmailOtpChallenge.consume(expired, wrong, now) == Left(EmailOtpChallenge.ConsumeError.CodeMismatch),
        )
      },
    ),

  )
