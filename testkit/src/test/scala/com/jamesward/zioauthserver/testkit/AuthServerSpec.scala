package com.jamesward.zioauthserver.testkit

import com.jamesward.zioauthserver.*
import zio.*
import zio.http.*
import zio.json.*
import zio.test.*

import java.security.MessageDigest
import java.time.Instant

/** The whole server, end to end, over the in-memory store. */
object AuthServerSpec extends ZIOSpecDefault:

  final case class TestUser(id: UserId, email: Email)

  given AccountView[TestUser] with
    def id(user: TestUser): UserId               = user.id
    def email(user: TestUser): Email             = user.email
    def scopes(user: TestUser): Set[OAuthScope] = Set(OAuthScope.of("role:user"))

  private val baseUrl = URL.decode("http://localhost:9000").toOption.get

  private def url(path: String): URL = URL.decode(s"http://localhost:9000$path").toOption.get
  private val cfg     = DevConfig.authServer(baseUrl)
  private val server  = AuthServer[TestUser](cfg, Pages.default[TestUser], Messages.default("Test"))
  private val routes  = server.routes
  // A first-party client that skips the consent page, and `mcp` a scope clients may ask for.
  private val trusted = AuthServer[TestUser](
    cfg.copy(skipConsent = c => Set("test-client", "escalating-client").contains(c.id.value), clientScopes = Set(OAuthScope.of("mcp"))),
    Pages.default[TestUser],
    Messages.default("Test"),
  ).routes

  private val clientId    = ClientId.of("test-client")
  private val redirectRaw = "http://127.0.0.1:9999/cb"
  private val redirect    = RedirectUri.parse(redirectRaw).toOption.get
  private val verifier    = "v" * 43
  private val challenge   =
    Crypto.encodeB64Url(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes("US-ASCII")))

  private def client(now: Instant) = OAuthClient(
    id = clientId,
    kind = ClientKind.Public,
    profile = ClientProfile.Mcp,
    name = "Test client",
    secretHash = None,
    grants = Set(GrantType.AuthorizationCode, GrantType.RefreshToken),
    scopes = Set(OAuthScope.of("mcp")),
    registration = ClientRegistration.Dynamic,
    registeredAt = now,
    createdAt = now,
    redirectUris = Set(redirect),
  )

  private given CanEqual[Status, Status] = CanEqual.derived

  final case class TokenBody(access_token: String, refresh_token: Option[String], scope: String) derives JsonDecoder
  final case class TokenError(error: String) derives JsonDecoder

  private type Env = InMemoryAuthStore.Stores[TestUser] & InMemoryAuthStore[TestUser] & Mailer & RecordingMailer & SecureRandomGen &
    JwtSigner & Client

  private val env: ZLayer[Any, Throwable, Env] =
    InMemoryAuthStore.layer[TestUser]((id, email, _) => TestUser(id, email), (u, e) => u.copy(email = e)) ++ RecordingMailer.layer ++
      SecureRandomGen.live ++ DevJwtSigner.fresh ++ Client.default

  private def run(req: Request): ZIO[Env & Scope, Nothing, Response] = routes.runZIO(req)

  private def withCookies(req: Request, cookies: Map[String, String]): Request =
    NonEmptyChunk.fromIterableOption(cookies.map((n, v) => Cookie.Request(n, v))) match
      case Some(cs) => req.addHeader(Header.Cookie(cs))
      case None     => req

  private def setCookies(resp: Response): Map[String, String] =
    resp.headers(Header.SetCookie).map(h => h.value.name -> h.value.content).toMap

  private def location(resp: Response): Option[URL] = resp.header(Header.Location).map(_.url)

  private def form(fields: (String, String)*): Body =
    Body.fromURLEncodedForm(Form(fields.map((k, v) => FormField.simpleField(k, v))*))

  // Each sign-in uses its own address: the tests run in parallel against one store and one mailbox.
  private val freshEmail: UIO[Email] =
    Random.nextUUID.map(u => Email.parse(s"$u@example.com").toOption.get)

  /** Signs in through the magic link and returns the cookies the browser would keep. */
  private def signIn(email: Email): ZIO[Env & Scope, Throwable, Map[String, String]] =
    for
      start  <- run(Request.post(url("/auth/email/start"), form("email" -> email.value)))
      _      <- ZIO.fail(new AssertionError(s"start: ${start.status}")).unless(start.status == (Status.SeeOther: Status))
      mail   <- ZIO.serviceWithZIO[RecordingMailer](_.lastTo(email)).someOrFail(new AssertionError("no mail"))
      token  <- ZIO
                  .fromOption("token=([A-Za-z0-9_-]+)".r.findFirstMatchIn(mail.text).map(_.group(1)))
                  .orElseFail(new AssertionError(s"no link in: ${mail.text}"))
      verify <- run(Request.get(url("/auth/email/verify").addQueryParam("token", token)))
      cookies = setCookies(verify)
      _      <- ZIO
                  .fail(new AssertionError(s"verify: ${verify.status} ${location(verify)} $cookies"))
                  .unless(cookies.contains(DevConfig.cookies.sessionName))
    yield cookies

  private def authorizeQuery(scope: String = "mcp", cid: ClientId = clientId): QueryParams =
    QueryParams(
      "response_type"         -> "code",
      "client_id"             -> cid.value,
      "redirect_uri"          -> redirectRaw,
      "code_challenge"        -> challenge,
      "code_challenge_method" -> "S256",
      "scope"                 -> scope,
      "state"                 -> "xyz",
    )

  private def registerClient(scopes: Set[OAuthScope] = Set(OAuthScope.of("mcp")), cid: ClientId = clientId): ZIO[Env, Throwable, Unit] =
    Clock.instant.flatMap(now =>
      ZIO.serviceWithZIO[AuthStore[TestUser]](_.createClient(client(now).copy(id = cid, scopes = scopes))).mapError(e => new AssertionError(e.toString))
    )

  /** The consent page's answer, as the user's browser would post it. */
  private def decide(cookies: Map[String, String], q: QueryParams, decision: String, csrf: Option[String] = None) =
    run(withCookies(
      Request.post(url("/oauth/authorize"), form(
        "_csrf"    -> csrf.getOrElse(cookies.getOrElse(DevConfig.cookies.csrfName, "")),
        "request"  -> q.encode.stripPrefix("?"),
        "decision" -> decision,
      )),
      cookies,
    ))

  private def codeIn(resp: Response): IO[AssertionError, String] =
    ZIO
      .fromOption(location(resp).flatMap(_.queryParams.queryParam("code")))
      .orElseFail(new AssertionError(s"no code: ${resp.status} ${location(resp)}"))

  /** Authorizes the test client for the signed-in user: the consent page, then Allow. */
  private def authorize(cookies: Map[String, String], scope: String = "mcp"): ZIO[Env & Scope, Throwable, String] =
    for
      _       <- registerClient()
      q        = authorizeQuery(scope)
      consent <- run(withCookies(Request.get(url("/oauth/authorize").addQueryParams(q)), cookies))
      _       <- ZIO.fail(new AssertionError(s"expected the consent page, got ${consent.status}")).unless(consent.status == (Status.Ok: Status))
      allowed <- decide(cookies, q, "approve")
      code    <- codeIn(allowed)
    yield code

  private def exchange(code: String): ZIO[Env & Scope, Nothing, Response] =
    run(
      Request.post(
        url("/oauth/token"),
        form(
          "grant_type"    -> "authorization_code",
          "code"          -> code,
          "client_id"     -> clientId.value,
          "redirect_uri"  -> redirectRaw,
          "code_verifier" -> verifier,
        ),
      )
    )

  private def refresh(token: String): ZIO[Env & Scope, Nothing, Response] =
    run(
      Request.post(
        url("/oauth/token"),
        form("grant_type" -> "refresh_token", "refresh_token" -> token, "client_id" -> clientId.value),
      )
    )

  private def json[A: JsonDecoder](resp: Response): Task[A] =
    resp.body.asString.flatMap(s => ZIO.fromEither(s.fromJson[A]).mapError(e => new AssertionError(s"$e: $s")))

  def spec = suite("AuthServer")(
    test("a magic link signs in, and the session cookie shows the home page") {
      for
        email   <- freshEmail
        cookies <- signIn(email)
        home    <- run(withCookies(Request.get(url("/")), cookies))
        body    <- home.body.asString
        users   <- ZIO.serviceWithZIO[InMemoryAuthStore[TestUser]](_.users)
      yield assertTrue(
        cookies.contains(DevConfig.cookies.sessionName),
        home.status == (Status.Ok: Status),
        body.contains(email.value),
        users.exists(_.email == email),
      )
    },
    test("without a session, the home page sends the browser to /login") {
      run(Request.get(url("/"))).map(resp => assertTrue(location(resp).map(_.encode).contains("/login")))
    },
    test("an authorization code with PKCE gives access and refresh tokens, once") {
      for
        cookies <- freshEmail.flatMap(signIn)
        code    <- authorize(cookies)
        first   <- exchange(code)
        tokens  <- json[TokenBody](first)
        second  <- exchange(code)
        err     <- json[TokenError](second)
      yield assertTrue(
        first.status == (Status.Ok: Status),
        tokens.access_token.nonEmpty,
        tokens.refresh_token.isDefined,
        second.status == (Status.BadRequest: Status),
        err.error == "invalid_grant",
      )
    },
    test("a refresh token rotates, and replaying the old one revokes the whole chain") {
      for
        cookies  <- freshEmail.flatMap(signIn)
        code     <- authorize(cookies)
        tokens   <- exchange(code).flatMap(json[TokenBody])
        rt1       = tokens.refresh_token.get
        rotated  <- refresh(rt1).flatMap(json[TokenBody])
        rt2       = rotated.refresh_token.get
        replay   <- refresh(rt1)
        afterRt2 <- refresh(rt2)
      yield assertTrue(
        rt2 != rt1,
        replay.status == (Status.BadRequest: Status),
        afterRt2.status == (Status.BadRequest: Status),
      )
    },
    test("a signed-in user gets the consent page, not a code: a link alone can't hand an attacker's client a code") {
      for
        cookies <- freshEmail.flatMap(signIn)
        _       <- registerClient()
        resp    <- run(withCookies(Request.get(url("/oauth/authorize").addQueryParams(authorizeQuery())), cookies))
        body    <- resp.body.asString
      yield assertTrue(
        resp.status == (Status.Ok: Status),
        location(resp).isEmpty,
        body.contains("Allow access?"),
        body.contains("127.0.0.1"),
        resp.headers.get("X-Frame-Options").contains("DENY"),
      )
    },
    test("the consent page escapes the client's own name") {
      for
        cookies <- freshEmail.flatMap(signIn)
        now     <- Clock.instant
        _       <- ZIO.serviceWithZIO[AuthStore[TestUser]](_.createClient(client(now).copy(name = "<script>alert(1)</script>")))
                     .mapError(e => new AssertionError(e.toString))
        body    <- run(withCookies(Request.get(url("/oauth/authorize").addQueryParams(authorizeQuery())), cookies)).flatMap(_.body.asString)
      yield assertTrue(!body.contains("<script>alert(1)"), body.contains("&lt;script&gt;"))
    },
    test("the consent decision needs the session's csrf token, and Deny answers access_denied") {
      for
        cookies <- freshEmail.flatMap(signIn)
        _       <- registerClient()
        forged  <- decide(cookies, authorizeQuery(), "approve", csrf = Some("not-the-token"))
        noUser  <- decide(Map.empty, authorizeQuery(), "approve", csrf = Some("x"))
        denied  <- decide(cookies, authorizeQuery(), "deny")
      yield assertTrue(
        forged.status == (Status.Forbidden: Status),
        noUser.status == (Status.Forbidden: Status),
        location(denied).exists(_.queryParams.queryParam("error").contains("access_denied")),
        location(denied).exists(_.queryParams.queryParam("code").isEmpty),
      )
    },
    test("a session without its csrf cookie gets an error, not a login bounce that would loop") {
      for
        cookies <- freshEmail.flatMap(signIn)
        _       <- registerClient()
        resp    <- run(withCookies(Request.get(url("/oauth/authorize").addQueryParams(authorizeQuery())), cookies - DevConfig.cookies.csrfName))
      yield assertTrue(resp.status == (Status.Forbidden: Status), location(resp).isEmpty)
    },
    test("a client in skipConsent gets the code at once") {
      for
        cookies <- freshEmail.flatMap(signIn)
        _       <- registerClient()
        resp    <- trusted.runZIO(withCookies(Request.get(url("/oauth/authorize").addQueryParams(authorizeQuery())), cookies))
        code    <- codeIn(resp)
      yield assertTrue(code.nonEmpty)
    },
    test("a client that registered role:admin and asks for it gets only the user's own scopes and allowed client scopes") {
      for
        cookies <- freshEmail.flatMap(signIn)
        escalating = ClientId.of("escalating-client")
        _       <- registerClient(Set(OAuthScope.of("role:admin"), OAuthScope.of("mcp")), escalating)
        // The default config: no client scopes, so only the user's own.
        q        = authorizeQuery("role:admin mcp", escalating)
        _       <- run(withCookies(Request.get(url("/oauth/authorize").addQueryParams(q)), cookies))
        code    <- decide(cookies, q, "approve").flatMap(codeIn)
        tokens  <- run(Request.post(url("/oauth/token"), form(
                     "grant_type" -> "authorization_code", "code" -> code, "client_id" -> escalating.value,
                     "redirect_uri" -> redirectRaw, "code_verifier" -> verifier,
                   ))).flatMap(json[TokenBody])
        // With `mcp` allowed for clients: that, plus the user's own, never role:admin.
        direct  <- trusted.runZIO(withCookies(Request.get(url("/oauth/authorize").addQueryParams(q)), cookies))
        code2   <- codeIn(direct)
        tokens2 <- trusted.runZIO(Request.post(url("/oauth/token"), form(
                     "grant_type" -> "authorization_code", "code" -> code2, "client_id" -> escalating.value,
                     "redirect_uri" -> redirectRaw, "code_verifier" -> verifier,
                   ))).flatMap(json[TokenBody])
      yield assertTrue(
        OAuthScopeSet.parse(tokens.scope) == Set(OAuthScope.of("role:user")),
        OAuthScopeSet.parse(tokens2.scope) == Set(OAuthScope.of("role:user"), OAuthScope.of("mcp")),
      )
    },
    test("concurrent exchanges of one code: exactly one succeeds") {
      for
        cookies  <- freshEmail.flatMap(signIn)
        code     <- authorize(cookies)
        statuses <- ZIO.foreachPar(1 to 20)(_ => exchange(code).map(_.status))
      yield assertTrue(statuses.count(_ == (Status.Ok: Status)) == 1)
    },
  ).provideSomeLayerShared[Scope](env.orDie) @@ TestAspect.withLiveClock @@ TestAspect.withLiveRandom
