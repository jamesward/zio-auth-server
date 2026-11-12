package com.jamesward.zioauthserver

import zio.test.*

import java.time.Instant

object OAuthDomainSpec extends ZIOSpecDefault:

  private given CanEqual[AuthorizationGrant, AuthorizationGrant] = CanEqual.derived
  private given CanEqual[zio.Duration, zio.Duration]             = CanEqual.derived
  private given CanEqual[Instant, Instant]                       = CanEqual.derived

  private val anClientId    = ClientId.of("client-1")
  private val otherClientId = ClientId.of("client-2")

  private val redirect = RedirectUri.parse("http://127.0.0.1:9999/cb").toOption.get
  private val redirect2 = RedirectUri.parse("http://127.0.0.1:1234/cb").toOption.get

  private val codeHash = AuthorizationCodeHash.fromBytes(Array[Byte](1, 2, 3))

  private val challenge = CodeChallenge.of("EXPECTED_CHALLENGE")

  private val now = Instant.parse("2025-01-01T12:00:00Z")

  private val freshGrant: AuthorizationGrant = AuthorizationGrant(
    codeHash         = codeHash,
    clientId         = anClientId,
    userId           = UserId.fresh(java.util.UUID.fromString("00000000-0000-0000-0000-000000000001")),
    redirectUri      = redirect,
    scopes           = Set(OAuthScope.of("role:user")),
    resource         = None,
    codeChallenge    = challenge,
    challengeMethod  = ChallengeMethod.S256,
    issuedAt         = now,
    expiresAt        = now.plusSeconds(60),
    consumedAt       = None,
  )

  override def spec = suite("OAuthDomain")(

    suite("RedirectUri.parse")(
      test("rejects empty string") {
        assertTrue(RedirectUri.parse("") == Left(RedirectUri.InvalidRedirectUri.Empty))
      },
      test("rejects whitespace-only string") {
        assertTrue(RedirectUri.parse("   ") == Left(RedirectUri.InvalidRedirectUri.Empty))
      },
      test("rejects relative path") {
        assertTrue(RedirectUri.parse("/cb") == Left(RedirectUri.InvalidRedirectUri.NotAbsolute))
      },
      test("accepts http loopback per RFC 8252") {
        val r = RedirectUri.parse("http://127.0.0.1:8080/cb").map(_.value)
        assertTrue(r == Right("http://127.0.0.1:8080/cb"))
      },
      test("accepts https") {
        val r = RedirectUri.parse("https://example.com/cb").map(_.value)
        assertTrue(r == Right("https://example.com/cb"))
      },
      test("trims surrounding whitespace") {
        val r = RedirectUri.parse("  https://example.com/cb  ").map(_.value)
        assertTrue(r == Right("https://example.com/cb"))
      },
    ),

    suite("RedirectUri.matchesRegistered")(
      test("exact match") {
        val reg = RedirectUri.parse("https://app.example.com/cb").toOption.get
        assertTrue(reg.matchesRegistered(Set(reg)))
      },
      test("non-loopback must match exactly — a different port fails") {
        val requested  = RedirectUri.parse("https://app.example.com:8443/cb").toOption.get
        val registered = RedirectUri.parse("https://app.example.com/cb").toOption.get
        assertTrue(!requested.matchesRegistered(Set(registered)))
      },
      // MCP Inspector registers `http://localhost:6274/oauth/callback` (via its
      // CIMD doc) but requests `http://127.0.0.1:6274/oauth/callback` — same
      // loopback, different host form. RFC 8252 treats loopback forms as equivalent.
      test("loopback: localhost registered matches 127.0.0.1 requested (MCP Inspector)") {
        val requested  = RedirectUri.parse("http://127.0.0.1:6274/oauth/callback").toOption.get
        val registered = RedirectUri.parse("http://localhost:6274/oauth/callback").toOption.get
        assertTrue(requested.matchesRegistered(Set(registered)))
      },
      test("loopback: 127.0.0.1 registered matches localhost requested") {
        val requested  = RedirectUri.parse("http://localhost:6274/oauth/callback").toOption.get
        val registered = RedirectUri.parse("http://127.0.0.1:6274/oauth/callback").toOption.get
        assertTrue(requested.matchesRegistered(Set(registered)))
      },
      test("loopback: the port is ignored (ephemeral port matches the registered port)") {
        val requested  = RedirectUri.parse("http://127.0.0.1:54321/cb").toOption.get
        val registered = RedirectUri.parse("http://localhost:6274/cb").toOption.get
        assertTrue(requested.matchesRegistered(Set(registered)))
      },
      test("loopback: the path must still match") {
        val requested  = RedirectUri.parse("http://127.0.0.1:6274/other").toOption.get
        val registered = RedirectUri.parse("http://localhost:6274/oauth/callback").toOption.get
        assertTrue(!requested.matchesRegistered(Set(registered)))
      },
      test("loopback: the scheme must still match") {
        val requested  = RedirectUri.parse("https://127.0.0.1:6274/cb").toOption.get
        val registered = RedirectUri.parse("http://localhost:6274/cb").toOption.get
        assertTrue(!requested.matchesRegistered(Set(registered)))
      },
      test("a non-loopback host is never treated as loopback-equivalent") {
        val requested  = RedirectUri.parse("http://evil.example.com:6274/cb").toOption.get
        val registered = RedirectUri.parse("http://localhost:6274/cb").toOption.get
        assertTrue(!requested.matchesRegistered(Set(registered)))
      },
    ),

    suite("ResourceIndicator.parse")(
      test("rejects empty") {
        assertTrue(ResourceIndicator.parse("") == Left(ResourceIndicator.InvalidResource.Empty))
      },
      test("rejects relative path") {
        assertTrue(ResourceIndicator.parse("/mcp") == Left(ResourceIndicator.InvalidResource.NotAbsolute))
      },
      test("accepts absolute URL") {
        val r = ResourceIndicator.parse("https://mcp.example.com").map(_.value)
        assertTrue(r == Right("https://mcp.example.com"))
      },
      test("strips path to the origin (host-wide audience)") {
        val r = ResourceIndicator.parse("http://localhost:8083/echo").map(_.value)
        assertTrue(r == Right("http://localhost:8083"))
      },
      test("strips query and fragment, keeps explicit port") {
        val r = ResourceIndicator.parse("https://mcp.example.com:9443/a/b?x=1#frag").map(_.value)
        assertTrue(r == Right("https://mcp.example.com:9443"))
      },
      test("lowercases scheme and host") {
        val r = ResourceIndicator.parse("HTTPS://MCP.Example.COM/Mcp").map(_.value)
        assertTrue(r == Right("https://mcp.example.com"))
      },
      test("two resources differing only by path canonicalize equal") {
        val a = ResourceIndicator.parse("http://localhost:8083/echo")
        val b = ResourceIndicator.parse("http://localhost:8083/other")
        assertTrue(a == b)
      },
      test("rejects host-less absolute URI (no origin to form)") {
        assertTrue(ResourceIndicator.parse("urn:example:resource") == Left(ResourceIndicator.InvalidResource.Malformed))
      },
    ),

    suite("CodeVerifier.parse")(
      test("rejects too short (<43 chars)") {
        val r = CodeVerifier.parse("a" * 42)
        assertTrue(r == Left(CodeVerifier.InvalidVerifier.TooShort))
      },
      test("rejects too long (>128 chars)") {
        val r = CodeVerifier.parse("a" * 129)
        assertTrue(r == Left(CodeVerifier.InvalidVerifier.TooLong))
      },
      test("rejects characters outside RFC 7636 charset") {
        val r = CodeVerifier.parse("a" * 42 + "!")
        assertTrue(r == Left(CodeVerifier.InvalidVerifier.BadChars))
      },
      test("accepts minimum-length all-allowed-chars verifier") {
        val v = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
        assertTrue(CodeVerifier.parse(v).map(_.value) == Right(v))
      },
      test("accepts the four punctuation chars in the unreserved set") {
        val v = "-._~" + ("a" * 39)
        assertTrue(CodeVerifier.parse(v).map(_.value) == Right(v))
      },
    ),

    suite("ChallengeMethod.parse")(
      test("accepts S256") {
        assertTrue(ChallengeMethod.parse("S256") == Right(ChallengeMethod.S256))
      },
      test("rejects 'plain' per SPEC §10.2") {
        assertTrue(ChallengeMethod.parse("plain").isLeft)
      },
      test("rejects unknown methods") {
        assertTrue(ChallengeMethod.parse("S384").isLeft)
      },
      test("S256.asString round-trips") {
        assertTrue(ChallengeMethod.parse(ChallengeMethod.S256.asString) == Right(ChallengeMethod.S256))
      },
    ),

    suite("OAuthScopeSet")(
      test("parse splits on whitespace, drops empties") {
        val s = OAuthScopeSet.parse("read   write \tdelete  ")
        assertTrue(s == Set(OAuthScope.of("read"), OAuthScope.of("write"), OAuthScope.of("delete")))
      },
      test("render is sorted (deterministic wire format)") {
        val s = Set(OAuthScope.of("write"), OAuthScope.of("admin"), OAuthScope.of("read"))
        assertTrue(OAuthScopeSet.render(s) == "admin read write")
      },
      test("render(parse(x)) preserves the same set") {
        val raw = "role:admin role:author role:user"
        assertTrue(OAuthScopeSet.parse(OAuthScopeSet.render(OAuthScopeSet.parse(raw))) == OAuthScopeSet.parse(raw))
      },
      test("empty input parses to empty set") {
        assertTrue(OAuthScopeSet.parse("") == Set.empty[OAuthScope])
      },
    ),

    suite("AuthorizationGrant.consume")(
      test("AlreadyConsumed when consumedAt is set") {
        val used = freshGrant.copy(consumedAt = Some(now.minusSeconds(1)))
        val r = AuthorizationGrant.consume(used, anClientId, redirect, challenge.value, now)
        assertTrue(r == Left(AuthorizationGrant.ConsumeError.AlreadyConsumed))
      },
      test("Expired when now == expiresAt (boundary: end-exclusive)") {
        val r = AuthorizationGrant.consume(freshGrant, anClientId, redirect, challenge.value, freshGrant.expiresAt)
        assertTrue(r == Left(AuthorizationGrant.ConsumeError.Expired))
      },
      test("ClientMismatch when /token's client_id differs") {
        val r = AuthorizationGrant.consume(freshGrant, otherClientId, redirect, challenge.value, now)
        assertTrue(r == Left(AuthorizationGrant.ConsumeError.ClientMismatch))
      },
      test("RedirectUriMismatch when /token's redirect_uri differs") {
        val r = AuthorizationGrant.consume(freshGrant, anClientId, redirect2, challenge.value, now)
        assertTrue(r == Left(AuthorizationGrant.ConsumeError.RedirectUriMismatch))
      },
      test("PkceMismatch when presented challenge differs") {
        val r = AuthorizationGrant.consume(freshGrant, anClientId, redirect, "WRONG", now)
        assertTrue(r == Left(AuthorizationGrant.ConsumeError.PkceMismatch))
      },
      test("error ordering: AlreadyConsumed wins over Expired") {
        val both = freshGrant.copy(
          consumedAt = Some(now.minusSeconds(1)),
          expiresAt  = now.minusSeconds(10),
        )
        val r = AuthorizationGrant.consume(both, anClientId, redirect, challenge.value, now)
        assertTrue(r == Left(AuthorizationGrant.ConsumeError.AlreadyConsumed))
      },
      test("error ordering: Expired wins over ClientMismatch") {
        val expired = freshGrant.copy(expiresAt = now.minusSeconds(1))
        val r = AuthorizationGrant.consume(expired, otherClientId, redirect, challenge.value, now)
        assertTrue(r == Left(AuthorizationGrant.ConsumeError.Expired))
      },
    ),

    suite("IssuedAccessToken.isActive")(
      test("active when unrevoked and now < expiresAt") {
        val tok = activeToken(expiresAt = now.plusSeconds(60), revokedAt = None)
        assertTrue(tok.isActive(now))
      },
      test("inactive at the exact expiresAt second (end-exclusive)") {
        val tok = activeToken(expiresAt = now, revokedAt = None)
        assertTrue(!tok.isActive(now))
      },
      test("inactive after expiresAt") {
        val tok = activeToken(expiresAt = now.minusSeconds(1), revokedAt = None)
        assertTrue(!tok.isActive(now))
      },
      test("inactive when revoked, even before expiry") {
        val tok = activeToken(expiresAt = now.plusSeconds(3600), revokedAt = Some(now.minusSeconds(1)))
        assertTrue(!tok.isActive(now))
      },
    ),

    suite("ClientProfile.accessTokenTtl")(
      test("Standard is 1 hour") {
        assertTrue(ClientProfile.Standard.accessTokenTtl == zio.Duration.fromJava(java.time.Duration.ofHours(1)))
      },
      test("Mcp is 1 day") {
        assertTrue(ClientProfile.Mcp.accessTokenTtl == zio.Duration.fromJava(java.time.Duration.ofDays(1)))
      },
    ),

    suite("ClientProfile.refreshTokenTtl")(
      test("Standard is 30 days") {
        assertTrue(ClientProfile.Standard.refreshTokenTtl == zio.Duration.fromJava(java.time.Duration.ofDays(30)))
      },
      test("Mcp is 90 days") {
        assertTrue(ClientProfile.Mcp.refreshTokenTtl == zio.Duration.fromJava(java.time.Duration.ofDays(90)))
      },
    ),

    suite("enum round-trips")(
      test("ClientKind") {
        assertTrue(
          ClientKind.parse(ClientKind.Public.asString) == Right(ClientKind.Public),
          ClientKind.parse(ClientKind.Confidential.asString) == Right(ClientKind.Confidential),
          ClientKind.parse("nope").isLeft,
        )
      },
      test("ClientProfile") {
        assertTrue(
          ClientProfile.parse(ClientProfile.Standard.asString) == Right(ClientProfile.Standard),
          ClientProfile.parse(ClientProfile.Mcp.asString) == Right(ClientProfile.Mcp),
          ClientProfile.parse("nope").isLeft,
        )
      },
      test("ClientRegistration") {
        assertTrue(
          ClientRegistration.parse(ClientRegistration.Static.asString) == Right(ClientRegistration.Static),
          ClientRegistration.parse(ClientRegistration.Dynamic.asString) == Right(ClientRegistration.Dynamic),
          ClientRegistration.parse("nope").isLeft,
        )
      },
      test("GrantType") {
        assertTrue(
          GrantType.parse(GrantType.AuthorizationCode.asString) == Right(GrantType.AuthorizationCode),
          GrantType.parse(GrantType.ClientCredentials.asString) == Right(GrantType.ClientCredentials),
          GrantType.parse(GrantType.RefreshToken.asString) == Right(GrantType.RefreshToken),
          GrantType.parse("nope").isLeft,
        )
      },
      test("SubjectKind") {
        assertTrue(
          SubjectKind.parse(SubjectKind.User.asString) == Right(SubjectKind.User),
          SubjectKind.parse(SubjectKind.Client.asString) == Right(SubjectKind.Client),
          SubjectKind.parse("nope").isLeft,
        )
      },
      test("UserStatus") {
        assertTrue(
          UserStatus.parse(UserStatus.Active.asString) == Right(UserStatus.Active),
          UserStatus.parse(UserStatus.Disabled.asString) == Right(UserStatus.Disabled),
          UserStatus.parse("nope").isLeft,
        )
      },
    ),

  )

  private def activeToken(
      expiresAt: Instant,
      revokedAt: Option[Instant],
  ): IssuedAccessToken =
    IssuedAccessToken(
      hash        = AccessTokenHash.fromBytes(Array[Byte](9, 9, 9)),
      clientId    = anClientId,
      subjectKind = SubjectKind.User,
      userId      = Some(UserId.fresh(java.util.UUID.fromString("00000000-0000-0000-0000-000000000002"))),
      scopes      = Set(OAuthScope.of("role:user")),
      resource    = None,
      issuedAt    = now,
      expiresAt   = expiresAt,
      revokedAt   = revokedAt,
    )
