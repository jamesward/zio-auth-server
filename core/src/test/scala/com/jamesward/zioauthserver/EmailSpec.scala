package com.jamesward.zioauthserver

import zio.test.*
import zio.test.Assertion.*

object EmailSpec extends ZIOSpecDefault:

  override def spec = suite("Email")(
    suite("Email.parse")(
      test("trims and lowercases the local-part") {
        val r = Email.parse("Alice@example.com").map(_.value)
        assertTrue(r == Right("alice@example.com"))
      },
      test("trims and lowercases the domain") {
        val r = Email.parse("alice@Example.COM").map(_.value)
        assertTrue(r == Right("alice@example.com"))
      },
      test("strips surrounding whitespace") {
        val r = Email.parse("  alice@example.com  ").map(_.value)
        assertTrue(r == Right("alice@example.com"))
      },
      test("rejects whitespace inside the address") {
        val r = Email.parse("alice @example.com")
        assertTrue(r == Left(Email.InvalidEmail.ContainsWhitespace))
      },
      test("rejects no @-sign") {
        val r = Email.parse("alice.example.com")
        assertTrue(r == Left(Email.InvalidEmail.NoAtSign))
      },
      test("rejects multiple @-signs") {
        val r = Email.parse("a@b@c")
        assertTrue(r == Left(Email.InvalidEmail.MultipleAtSigns))
      },
      test("rejects empty local part") {
        val r = Email.parse("@example.com")
        assertTrue(r == Left(Email.InvalidEmail.EmptyLocalPart))
      },
      test("rejects empty domain") {
        val r = Email.parse("alice@")
        assertTrue(r == Left(Email.InvalidEmail.EmptyDomain))
      },
      test("rejects empty string") {
        val r = Email.parse("")
        assertTrue(r == Left(Email.InvalidEmail.Empty))
      },
    ),
  )
