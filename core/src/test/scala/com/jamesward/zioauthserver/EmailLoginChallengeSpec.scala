package com.jamesward.zioauthserver

import zio.test.*

import java.time.Instant

object EmailLoginChallengeSpec extends ZIOSpecDefault:

  private given CanEqual[EmailLoginChallenge, EmailLoginChallenge] = CanEqual.derived
  private given CanEqual[Instant, Instant]                         = CanEqual.derived

  private val email     = Email.parse("alice@example.com").toOption.get
  private val tokenHash = MagicTokenHash.fromBytes(Array[Byte](1, 2, 3, 4))
  private val otherHash = MagicTokenHash.fromBytes(Array[Byte](9, 9, 9, 9))
  private val cid       = EmailLoginChallengeId.fresh(java.util.UUID.fromString("00000000-0000-0000-0000-0000000000aa"))
  private val now       = Instant.parse("2025-01-01T12:00:00Z")

  private val pending: EmailLoginChallenge = EmailLoginChallenge(
    id         = cid,
    email      = email,
    tokenHash  = tokenHash,
    issuedAt   = now,
    expiresAt  = now.plusSeconds(900),
    consumedAt = None,
  )

  override def spec = suite("EmailLoginChallenge.consume")(

    test("happy path: returns consumed copy, consumedAt = now, all other fields intact") {
      val r = EmailLoginChallenge.consume(pending, tokenHash, now)
      assertTrue(
        r.map(_.consumedAt) == Right(Some(now)),
        r.map(_.copy(consumedAt = None)) == Right(pending),
      )
    },

    test("AlreadyConsumed when consumedAt is set") {
      val used = pending.copy(consumedAt = Some(now.minusSeconds(1)))
      val r = EmailLoginChallenge.consume(used, tokenHash, now)
      assertTrue(r == Left(EmailLoginChallenge.ConsumeError.AlreadyConsumed))
    },

    test("Expired when now == expiresAt (boundary: end-exclusive)") {
      val r = EmailLoginChallenge.consume(pending, tokenHash, pending.expiresAt)
      assertTrue(r == Left(EmailLoginChallenge.ConsumeError.Expired))
    },

    test("Expired when now > expiresAt") {
      val r = EmailLoginChallenge.consume(pending, tokenHash, pending.expiresAt.plusSeconds(1))
      assertTrue(r == Left(EmailLoginChallenge.ConsumeError.Expired))
    },

    test("TokenMismatch when presented hash differs from stored hash") {
      val r = EmailLoginChallenge.consume(pending, otherHash, now)
      assertTrue(r == Left(EmailLoginChallenge.ConsumeError.TokenMismatch))
    },

    test("TokenMismatch is checked before AlreadyConsumed (fail-closed on bad hash)") {
      val used = pending.copy(consumedAt = Some(now.minusSeconds(1)))
      val r = EmailLoginChallenge.consume(used, otherHash, now)
      assertTrue(r == Left(EmailLoginChallenge.ConsumeError.TokenMismatch))
    },

    test("TokenMismatch is checked before Expired") {
      val expired = pending.copy(expiresAt = now.minusSeconds(1))
      val r = EmailLoginChallenge.consume(expired, otherHash, now)
      assertTrue(r == Left(EmailLoginChallenge.ConsumeError.TokenMismatch))
    },

    test("just before expiry still succeeds") {
      val r = EmailLoginChallenge.consume(pending, tokenHash, pending.expiresAt.minusNanos(1))
      assertTrue(r.map(_.consumedAt).contains(Some(pending.expiresAt.minusNanos(1))))
    },

  )
