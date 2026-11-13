package com.jamesward.zioauthserver.testkit

import com.jamesward.zioauthserver.*
import zio.*
import zio.http.*
import zio.json.*
import zio.test.*

import java.time.Instant

/** The connection helper against a fake OAuth provider, and the token sealing it relies on. */
object OAuthConnectorSpec extends ZIOSpecDefault:

  final case class TestUser(id: UserId, email: Email)

  given AccountView[TestUser] with
    def id(user: TestUser): UserId               = user.id
    def email(user: TestUser): Email             = user.email
    def scopes(user: TestUser): Set[OAuthScope] = Set.empty

  private val sealer = TokenSealer.fromBase64Url(Crypto.encodeB64Url(Array.fill[Byte](32)(7))).toOption.get

  /** The provider: counts token requests, issues `access-N`/`refresh-N`, expiring in `expiresIn` seconds. */
  final case class Provider(port: Int, issued: Ref[Int], expiresIn: Ref[Long], subject: Ref[String], refreshOk: Ref[Boolean])

  private val provider: ZLayer[Server, Nothing, Provider] = ZLayer {
    for
      issued    <- Ref.make(0)
      expiresIn <- Ref.make(3600L)
      subject   <- Ref.make("42")
      refreshOk <- Ref.make(true)
      routes     = Routes(
                     Method.POST / "token" -> handler { (req: Request) =>
                       for
                         form  <- req.body.asURLEncodedForm.orDie
                         grant  = form.get("grant_type").flatMap(_.stringValue).getOrElse("")
                         ok    <- refreshOk.get
                         n     <- issued.updateAndGet(_ + 1)
                         ttl   <- expiresIn.get
                         body   = if grant == "refresh_token" && !ok then """{"error":"bad_refresh_token"}"""
                                  else s"""{"access_token":"access-$n","refresh_token":"refresh-$n","expires_in":$ttl,"token_type":"bearer"}"""
                       yield Response.json(body)
                     },
                     Method.GET / "user" -> handler(subject.get.map(s => Response.json(s"""{"id":$s}"""))),
                   )
      port      <- Server.install(routes)
    yield Provider(port, issued, expiresIn, subject, refreshOk)
  }

  private def connector(p: Provider): OAuthConnector =
    OAuthConnector(
      OAuthProvider("github", s"http://localhost:${p.port}/authorize", s"http://localhost:${p.port}/token", "cid", "secret",
        "http://localhost:9000/connect/github/callback"),
      sealer,
      GitHub.userId(s"http://localhost:${p.port}"),
      allowSubject = _ == "42",
    )

  private type Env = InMemoryAuthStore.Stores[TestUser] & InMemoryAuthStore[TestUser] & SecureRandomGen & Client & Provider

  private val env =
    InMemoryAuthStore.layer[TestUser]((id, e, _) => TestUser(id, e), (u, e) => u.copy(email = e)) ++ SecureRandomGen.live ++
      Client.default ++ (Server.defaultWith(_.onAnyOpenPort) >>> provider)

  private val owner = UserId.fresh(java.util.UUID.randomUUID())

  /** Starts a flow and returns the `state` the provider would send back. */
  private def startFlow(c: OAuthConnector): ZIO[Env, Throwable, String] =
    c.start(owner, Some("/settings")).mapError(e => new AssertionError(e.toString))
      .map(_.queryParams.queryParam("state").get)

  private def seedOwner: ZIO[Env, Nothing, Unit] =
    ZIO.serviceWithZIO[InMemoryAuthStore[TestUser]](_.putUser(TestUser(owner, Email.parse("owner@example.com").toOption.get)))

  def spec = suite("OAuthConnector")(
    test("sealed tokens open only with the same key and associated data") {
      val sealedValue = sealer.seal("secret-token", "user:github")
      val other       = TokenSealer.fromBase64Url(Crypto.encodeB64Url(Array.fill[Byte](32)(8))).toOption.get
      assertTrue(
        sealedValue.startsWith("v1."),
        !sealedValue.contains("secret-token"),
        sealer.open(sealedValue, "user:github") == Right("secret-token"),
        sealer.open(sealedValue, "other:github").isLeft,
        other.open(sealedValue, "user:github").isLeft,
        TokenSealer.fromBase64Url("c2hvcnQ").isLeft,
      )
    },
    test("the authorize URL carries PKCE S256 and a state, and the callback stores the sealed tokens") {
      for
        p      <- ZIO.service[Provider]
        _      <- seedOwner
        c       = connector(p)
        url    <- c.start(owner, Some("/settings")).mapError(e => new AssertionError(e.toString))
        q       = url.queryParams
        result <- c.callback("the-code", q.queryParam("state").get, owner).mapError(e => new AssertionError(e.toString))
        stored <- ZIO.serviceWithZIO[ConnectionStore](_.findConnection(owner, "github"))
        token  <- c.accessToken(owner).mapError(e => new AssertionError(e.toString))
      yield assertTrue(
        q.queryParam("code_challenge_method").contains("S256"),
        q.queryParam("code_challenge").exists(_.nonEmpty),
        q.queryParam("client_id").contains("cid"),
        result._2.contains("/settings"),
        stored.map(_.subject).contains("42"),
        stored.exists(!_.sealedTokens.contains("access-")),
        token.startsWith("access-"),
      )
    },
    test("a callback in another user's browser is refused: an attacker can't connect a victim's account to themselves") {
      for
        p       <- ZIO.service[Provider]
        _       <- seedOwner
        _       <- ZIO.serviceWithZIO[ConnectionStore](_.deleteConnection(owner, "github"))
        c        = connector(p)
        state   <- startFlow(c) // started by `owner`, whose link is opened by someone else
        victim   = UserId.fresh(java.util.UUID.randomUUID())
        res     <- c.callback("code", state, victim).either
        none    <- ZIO.serviceWithZIO[ConnectionStore](_.findConnection(owner, "github"))
      yield assertTrue(res == Left(ConnectError.InvalidState), none.isEmpty)
    },
    test("a state works once") {
      for
        p      <- ZIO.service[Provider]
        _      <- seedOwner
        c       = connector(p)
        state  <- startFlow(c)
        first  <- c.callback("code", state, owner).either
        second <- c.callback("code", state, owner).either
      yield assertTrue(first.isRight, second == Left(ConnectError.InvalidState))
    },
    test("an account other than the allowed one is refused and not stored") {
      for
        p     <- ZIO.service[Provider]
        _     <- seedOwner
        _     <- ZIO.serviceWithZIO[ConnectionStore](_.deleteConnection(owner, "github"))
        _     <- p.subject.set("999")
        c      = connector(p)
        state <- startFlow(c)
        res   <- c.callback("code", state, owner).either
        _     <- p.subject.set("42")
        none  <- ZIO.serviceWithZIO[ConnectionStore](_.findConnection(owner, "github"))
      yield assertTrue(res == Left(ConnectError.SubjectNotAllowed("999")), none.isEmpty)
    },
    test("an expiring access token is refreshed; a refused refresh means connect again") {
      for
        p       <- ZIO.service[Provider]
        _       <- seedOwner
        _       <- p.expiresIn.set(30) // inside the one-minute margin, so every use refreshes
        c        = connector(p)
        state   <- startFlow(c)
        _       <- c.callback("code", state, owner).mapError(e => new AssertionError(e.toString))
        before  <- p.issued.get
        token   <- c.accessToken(owner).mapError(e => new AssertionError(e.toString))
        after   <- p.issued.get
        _       <- p.refreshOk.set(false)
        lapsed  <- c.accessToken(owner).either
        _       <- p.refreshOk.set(true) *> p.expiresIn.set(3600)
      yield assertTrue(after == before + 1, token == s"access-$after", lapsed == Left(ConnectError.NotConnected))
    },
    test("disconnect removes the connection") {
      for
        p       <- ZIO.service[Provider]
        _       <- seedOwner
        c        = connector(p)
        state   <- startFlow(c)
        _       <- c.callback("code", state, owner).mapError(e => new AssertionError(e.toString))
        removed <- c.disconnect(owner).mapError(e => new AssertionError(e.toString))
        token   <- c.accessToken(owner).either
      yield assertTrue(removed, token == Left(ConnectError.NotConnected))
    },
  ).provideShared(env) @@ TestAspect.sequential @@ TestAspect.withLiveClock @@ TestAspect.withLiveRandom
