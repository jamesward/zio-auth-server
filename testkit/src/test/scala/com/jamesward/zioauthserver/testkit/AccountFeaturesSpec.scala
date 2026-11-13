package com.jamesward.zioauthserver.testkit

import com.jamesward.zioauthserver.*
import zio.*
import zio.http.*
import zio.test.*

/** Email change with step-up, the sign-up gate, `/login?reauth`, the in-process token verifier, and the Mailgun call. */
object AccountFeaturesSpec extends ZIOSpecDefault:

  private given CanEqual[Status, Status] = CanEqual.derived

  final case class TestUser(id: UserId, email: Email)

  given AccountView[TestUser] with
    def id(user: TestUser): UserId               = user.id
    def email(user: TestUser): Email             = user.email
    def scopes(user: TestUser): Set[OAuthScope] = Set.empty

  private val origin   = "http://localhost:9000"
  private val cfg      = DevConfig.authServer(URL.decode(origin).toOption.get)
  private val messages = Messages.default("Test")
  private val routes   = LoginRoutes[TestUser](cfg, Pages.default[TestUser], messages).routes ++
    AccountRoutes[TestUser](cfg, messages).routes
  private val strict   = AccountRoutes[TestUser](cfg, messages, stepUpAge = Duration.Zero).routes

  private type Env = InMemoryAuthStore.Stores[TestUser] & InMemoryAuthStore[TestUser] & Mailer & RecordingMailer &
    SecureRandomGen & JwtSigner

  private def env(policy: SignUpPolicy): ULayer[Env] =
    InMemoryAuthStore.layer[TestUser]((id, e, _) => TestUser(id, e), (u, e) => u.copy(email = e), policy) ++
      RecordingMailer.layer ++ SecureRandomGen.live ++ DevJwtSigner.fresh

  private def url(path: String): URL = URL.decode(s"$origin$path").toOption.get

  private def withCookies(req: Request, cookies: Map[String, String]): Request =
    NonEmptyChunk.fromIterableOption(cookies.map((n, v) => Cookie.Request(n, v))).fold(req)(cs => req.addHeader(Header.Cookie(cs)))

  private def setCookies(resp: Response): Map[String, String] =
    resp.headers(Header.SetCookie).map(h => h.value.name -> h.value.content).toMap

  private def form(fields: (String, String)*): Body = Body.fromURLEncodedForm(Form(fields.map(FormField.simpleField)*))

  private val freshEmail: UIO[Email] = Random.nextUUID.map(u => Email.parse(s"$u@example.com").toOption.get)

  private def linkIn(email: Email): ZIO[RecordingMailer, Throwable, String] =
    ZIO.serviceWithZIO[RecordingMailer](_.lastTo(email)).someOrFail(new AssertionError(s"no mail to $email"))
      .map(m => "token=([A-Za-z0-9_-]+)".r.findFirstMatchIn(m.text).get.group(1))

  private def signIn(email: Email): ZIO[Env & Scope, Throwable, Map[String, String]] =
    for
      _      <- routes.runZIO(Request.post(url("/auth/email/start"), form("email" -> email.value)))
      token  <- linkIn(email)
      verify <- routes.runZIO(Request.get(url("/auth/email/verify").addQueryParam("token", token)))
    yield setCookies(verify)

  def spec = suite("Account features")(
    test("a fresh session changes the address after the new address confirms it") {
      (for
        oldEmail <- freshEmail
        newEmail <- freshEmail
        cookies  <- signIn(oldEmail)
        csrf      = cookies(DevConfig.cookies.csrfName)
        start    <- routes.runZIO(withCookies(Request.post(url("/account/email"), form("email" -> newEmail.value, "_csrf" -> csrf)), cookies))
        before   <- ZIO.serviceWithZIO[InMemoryAuthStore[TestUser]](_.users)
        token    <- linkIn(newEmail)
        confirm  <- routes.runZIO(Request.get(url("/account/email/verify").addQueryParam("token", token)))
        again    <- routes.runZIO(Request.get(url("/account/email/verify").addQueryParam("token", token)))
        after    <- ZIO.serviceWithZIO[InMemoryAuthStore[TestUser]](_.users)
      yield assertTrue(
        start.status == Status.Ok,
        before.map(_.email) == List(oldEmail),
        confirm.status == Status.Ok,
        again.status == Status.BadRequest,
        after.map(_.email) == List(newEmail),
      )).provideSomeLayer[Scope](env(SignUpPolicy.Open))
    },
    test("an old session is sent to sign in again, and a missing CSRF token is refused") {
      (for
        email   <- freshEmail
        cookies <- signIn(email)
        csrf     = cookies(DevConfig.cookies.csrfName)
        old     <- strict.runZIO(withCookies(Request.post(url("/account/email"), form("email" -> "x@example.com", "_csrf" -> csrf)), cookies))
        noCsrf  <- routes.runZIO(withCookies(Request.post(url("/account/email"), form("email" -> "x@example.com")), cookies))
      yield assertTrue(
        old.status == Status.SeeOther,
        old.header(Header.Location).exists(_.url.encode.startsWith("/login?reauth=1")),
        noCsrf.status == Status.Forbidden,
      )).provideSomeLayer[Scope](env(SignUpPolicy.Open))
    },
    test("/login?reauth shows the sign-in form even with a live session") {
      (for
        email   <- freshEmail
        cookies <- signIn(email)
        resume  <- routes.runZIO(withCookies(Request.get(url("/login")), cookies))
        reauth  <- routes.runZIO(withCookies(Request.get(url("/login?reauth=1")), cookies))
      yield assertTrue(resume.status == Status.SeeOther, reauth.status == Status.Ok))
        .provideSomeLayer[Scope](env(SignUpPolicy.Open))
    },
    test("with ExistingUsersOnly, a stranger's address gets no email but the same page") {
      (for
        stranger <- freshEmail
        resp     <- routes.runZIO(Request.post(url("/auth/email/start"), form("email" -> stranger.value)))
        otp      <- routes.runZIO(Request.post(url("/auth/otp/start"), form("email" -> stranger.value)))
        sent     <- ZIO.serviceWithZIO[RecordingMailer](_.sent)
      yield assertTrue(
        resp.status == Status.SeeOther,
        resp.header(Header.Location).exists(_.url.encode == "/login?sent=1"),
        otp.status == Status.SeeOther,
        sent.isEmpty,
      )).provideSomeLayer[Scope](env(SignUpPolicy.ExistingUsersOnly))
    },
    test("the token verifier accepts an active token for its resource only, and never a revoked one") {
      (for
        store    <- ZIO.service[InMemoryAuthStore[TestUser]]
        now      <- Clock.instant
        client    = ClientId.of("c")
        resource  = ResourceIndicator.parse("https://factory.example.com/mcp").toOption.get
        bearer    = "the-bearer-token"
        hash      = AccessTokenHash.fromBytes(Crypto.hmacSha256(bearer, cfg.pepper.value))
        _        <- store.createAccessToken(IssuedAccessToken(hash, client, SubjectKind.User, None, Set.empty, Some(resource), now,
                      now.plusSeconds(3600), None))
        verifier  = AccessTokenVerifier[TestUser](cfg, store)
        ok       <- verifier.verify(bearer, Some(resource))
        wrongAud <- verifier.verify(bearer, Some(ResourceIndicator.parse("https://other.example.com/mcp").toOption.get))
        unknown  <- verifier.verify("not-a-token", None)
        _        <- store.revokeAccessTokenIfOwned(RevokeAccessTokenRequest(hash, client))
        revoked  <- verifier.verify(bearer, Some(resource))
      yield assertTrue(ok.map(_.clientId) == Some(client), wrongAud.isEmpty, unknown.isEmpty, revoked.isEmpty))
        .provideSomeLayer[Scope](env(SignUpPolicy.Open))
    },
    test("the Mailgun mailer posts the message form with basic auth to the domain's endpoint") {
      for
        seen <- Ref.make(Option.empty[(String, Option[String], Map[String, String])])
        port <- Server.install(Routes(Method.POST / "v3" / "mg.example.com" / "messages" -> handler { (req: Request) =>
                  for
                    f <- req.body.asURLEncodedForm.orDie
                    _ <- seen.set(Some((req.url.path.encode, req.headers.get("Authorization"),
                           f.formData.map(d => d.name -> d.stringValue.getOrElse("")).toMap)))
                  yield Response.json("""{"id":"x","message":"Queued"}""")
                }))
        client <- ZIO.service[Client]
        mailer  = MailgunMailer(MailgunConfig("key-123", "mg.example.com", "Login <login@mg.example.com>", s"http://localhost:$port"), client)
        _      <- mailer.send(EmailMessage(Email.parse("a@example.com").toOption.get, "Hi", "Body"))
        got    <- seen.get
      yield assertTrue(
        got.map(_._1).contains("/v3/mg.example.com/messages"),
        got.flatMap(_._2).contains("Basic " + java.util.Base64.getEncoder.encodeToString("api:key-123".getBytes)),
        got.map(_._3).contains(Map("from" -> "Login <login@mg.example.com>", "to" -> "a@example.com", "subject" -> "Hi", "text" -> "Body")),
      )
    }.provide(Server.defaultWith(_.onAnyOpenPort), Client.default),
  ) @@ TestAspect.withLiveClock @@ TestAspect.withLiveRandom
