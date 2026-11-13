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

  final case class TokenBody(access_token: String, refresh_token: Option[String]) derives JsonDecoder
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

  private def authorize(cookies: Map[String, String]): ZIO[Env & Scope, Throwable, String] =
    for
      now  <- Clock.instant
      _    <- ZIO.serviceWithZIO[AuthStore[TestUser]](_.createClient(client(now))).mapError(e => new AssertionError(e.toString))
      authz = url("/oauth/authorize").addQueryParams(
                QueryParams(
                  "response_type"         -> "code",
                  "client_id"             -> clientId.value,
                  "redirect_uri"          -> redirectRaw,
                  "code_challenge"        -> challenge,
                  "code_challenge_method" -> "S256",
                  "scope"                 -> "mcp",
                  "state"                 -> "xyz",
                )
              )
      resp <- run(withCookies(Request.get(authz), cookies))
      code <- ZIO
                .fromOption(location(resp).flatMap(_.queryParams.queryParam("code")))
                .orElseFail(new AssertionError(s"authorize: ${resp.status} ${location(resp)}"))
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
    test("concurrent exchanges of one code: exactly one succeeds") {
      for
        cookies  <- freshEmail.flatMap(signIn)
        code     <- authorize(cookies)
        statuses <- ZIO.foreachPar(1 to 20)(_ => exchange(code).map(_.status))
      yield assertTrue(statuses.count(_ == (Status.Ok: Status)) == 1)
    },
  ).provideSomeLayerShared[Scope](env.orDie) @@ TestAspect.withLiveClock @@ TestAspect.withLiveRandom
