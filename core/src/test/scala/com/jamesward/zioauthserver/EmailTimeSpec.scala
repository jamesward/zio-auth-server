package com.jamesward.zioauthserver

import zio.test.*

import java.time.Instant

object EmailTimeSpec extends ZIOSpecDefault:

  override def spec = suite("EmailTimeSpec")(
    test("formats absolute email dates for humans in an explicit timezone") {
      val instant = Instant.parse("2026-09-03T22:05:00Z")
      assertTrue(EmailTime.format(instant) == "Sep 3, 2026 at 10:05 PM UTC")
    },
    test("describes future expirations relative to the email send time") {
      val now = Instant.parse("2026-09-03T22:05:00Z")
      assertTrue(
        EmailTime.describeExpiration(now, now.plusSeconds(3 * 3600)) == "expires in 3 hours",
        EmailTime.describeExpiration(now, now.plusSeconds(60)) == "expires in 1 minute",
        EmailTime.describeExpiration(now, now.plusSeconds(14 * 86400)) == "expires in 14 days",
      )
    },
    test("describes elapsed expirations without a negative duration") {
      val now = Instant.parse("2026-09-03T22:05:00Z")
      assertTrue(
        EmailTime.describeExpiration(now, now) == "has expired",
        EmailTime.describeExpiration(now, now.minusSeconds(1)) == "has expired",
      )
    },
  )
