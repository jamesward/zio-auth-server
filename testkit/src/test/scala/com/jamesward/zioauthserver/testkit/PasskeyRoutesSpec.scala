package com.jamesward.zioauthserver.testkit

import com.jamesward.zioauthserver.*
import zio.*
import zio.http.*
import zio.json.*
import zio.json.ast.{Json, JsonCursor}
import zio.test.*

/** Passkey registration (with step-up and CSRF) and passkey sign-in, end to end with a software authenticator. */
object PasskeyRoutesSpec extends ZIOSpecDefault:

  private given CanEqual[Status, Status] = CanEqual.derived

  final case class TestUser(id: UserId, email: Email)

  given AccountView[TestUser] with
    def id(user: TestUser): UserId               = user.id
    def email(user: TestUser): Email             = user.email
    def scopes(user: TestUser): Set[OAuthScope] = Set.empty

  private val origin  = "http://localhost:9000"
  private val cfg     = DevConfig.authServer(URL.decode(origin).toOption.get)
  private val pkCfg   = PasskeyConfig.forBaseUrl(cfg, "Test")
  private val login   = LoginRoutes[TestUser](cfg, Pages.default[TestUser], Messages.default("Test"))
  private val routes  = login.routes ++ PasskeyRoutes[TestUser](cfg, pkCfg).routes
  // Every session is too old for this one: step-up always asks for a fresh sign-in.
  private val strict  = PasskeyRoutes[TestUser](cfg, pkCfg.copy(stepUpAge = Duration.Zero)).routes

  private type Env = InMemoryAuthStore.Stores[TestUser] & InMemoryAuthStore[TestUser] & Mailer & RecordingMailer &
    SecureRandomGen & JwtSigner

  private val env: ULayer[Env] =
    InMemoryAuthStore.layer[TestUser]((id, e, _) => TestUser(id, e), (u, e) => u.copy(email = e)) ++ RecordingMailer.layer ++
      SecureRandomGen.live ++ DevJwtSigner.fresh

  private def url(path: String): URL = URL.decode(s"$origin$path").toOption.get

  private def cookieHeader(cookies: Map[String, String]): Option[Header] =
    NonEmptyChunk.fromIterableOption(cookies.map((n, v) => Cookie.Request(n, v))).map(Header.Cookie(_))

  private def postJson(r: Routes[Env, Response], path: String, body: String, cookies: Map[String, String], csrf: Boolean) =
    val base = Request
      .post(url(path), Body.fromString(body))
      .addHeader(Header.ContentType(MediaType.application.json))
    val withCookies = cookieHeader(cookies).fold(base)(base.addHeader)
    val req = if csrf then withCookies.addHeader("X-CSRF-Token", cookies.getOrElse(DevConfig.cookies.csrfName, "")) else withCookies
    r.runZIO(req)

  private def setCookies(resp: Response): Map[String, String] =
    resp.headers(Header.SetCookie).map(h => h.value.name -> h.value.content).toMap

  private def json(resp: Response): Task[Json] =
    resp.body.asString.flatMap(s => ZIO.fromEither(s.fromJson[Json]).mapError(e => new AssertionError(s"$e: $s")))

  private def field(j: Json, name: String): String =
    j.get(JsonCursor.field(name).isString).toOption.map(_.value).getOrElse(throw new AssertionError(s"no $name in $j"))

  private def obj(j: Json, name: String): Json = j.get(JsonCursor.field(name)).toOption.get

  private val signInByEmail: ZIO[Env & Scope, Throwable, (Email, Map[String, String])] =
    for
      email  <- Random.nextUUID.map(u => Email.parse(s"$u@example.com").toOption.get)
      _      <- routes.runZIO(Request.post(url("/auth/email/start"), Body.fromURLEncodedForm(Form(FormField.simpleField("email", email.value)))))
      mail   <- ZIO.serviceWithZIO[RecordingMailer](_.lastTo(email)).someOrFail(new AssertionError("no mail"))
      token   = "token=([A-Za-z0-9_-]+)".r.findFirstMatchIn(mail.text).get.group(1)
      verify <- routes.runZIO(Request.get(url("/auth/email/verify").addQueryParam("token", token)))
    yield (email, setCookies(verify))

  private def register(auth: SoftwareAuthenticator, cookies: Map[String, String]): ZIO[Env & Scope, Throwable, Response] =
    for
      start   <- postJson(routes, "/account/passkeys/options", "{}", cookies, csrf = true).flatMap(json)
      created  = auth.register(obj(start, "options"))
      done    <- postJson(routes, "/account/passkeys/register",
                   s"""{"ceremony":"${field(start, "ceremony")}","credential":$created,"name":"Laptop"}""", cookies, csrf = true)
    yield done

  def spec = suite("PasskeyRoutes")(
    test("a fresh session registers a passkey, which then signs in without email") {
      for
        (email, cookies) <- signInByEmail
        auth              = SoftwareAuthenticator(origin)
        registered       <- register(auth, cookies)
        start            <- postJson(routes, "/auth/passkey/options", "{}", Map.empty, csrf = false).flatMap(json)
        assertion         = auth.signIn(obj(start, "options"))
        verifyBody        = s"""{"ceremony":"${field(start, "ceremony")}","credential":$assertion,"returnTo":"/"}"""
        verified         <- postJson(routes, "/auth/passkey/verify", verifyBody, Map.empty, csrf = false)
        newCookies        = setCookies(verified)
        home             <- routes.runZIO(cookieHeader(newCookies).fold(Request.get(url("/")))(Request.get(url("/")).addHeader))
        homeBody         <- home.body.asString
        replayed         <- postJson(routes, "/auth/passkey/verify", verifyBody, Map.empty, csrf = false)
      yield assertTrue(
        registered.status == (Status.Ok: Status),
        verified.status == (Status.Ok: Status),
        newCookies.contains(DevConfig.cookies.sessionName),
        homeBody.contains(email.value),
        replayed.status == (Status.BadRequest: Status), // the ceremony was used
      )
    },
    test("registration needs the CSRF header") {
      for
        (_, cookies) <- signInByEmail
        resp         <- postJson(routes, "/account/passkeys/options", "{}", cookies, csrf = false)
      yield assertTrue(resp.status == (Status.Forbidden: Status))
    },
    test("an old session is sent to sign in again before it can add a passkey") {
      for
        (_, cookies) <- signInByEmail
        resp         <- postJson(strict, "/account/passkeys/options", "{}", cookies, csrf = true)
        body         <- json(resp)
      yield assertTrue(resp.status == (Status.Unauthorized: Status), field(body, "reauth").startsWith("/login?reauth=1"))
    },
    test("an unknown passkey doesn't sign in") {
      for
        _          <- signInByEmail
        stranger    = SoftwareAuthenticator(origin)
        // Registered against a different store, so this store has never seen the credential.
        _          <- ZIO.succeed(stranger.register(Json.Obj("publicKey" -> Json.Obj(
                        "rp" -> Json.Obj("id" -> Json.Str("localhost")),
                        "user" -> Json.Obj("id" -> Json.Str(Crypto.encodeB64Url(Array.fill[Byte](16)(1)))),
                        "challenge" -> Json.Str("AAAA"),
                      ))))
        start      <- postJson(routes, "/auth/passkey/options", "{}", Map.empty, csrf = false).flatMap(json)
        assertion   = stranger.signIn(obj(start, "options"))
        resp       <- postJson(routes, "/auth/passkey/verify",
                        s"""{"ceremony":"${field(start, "ceremony")}","credential":$assertion}""", Map.empty, csrf = false)
      yield assertTrue(resp.status == (Status.Unauthorized: Status))
    },
    test("the routes need application/json") {
      routes.runZIO(Request.post(url("/auth/passkey/options"), Body.fromString("{}")))
        .map(resp => assertTrue(resp.status == (Status.UnsupportedMediaType: Status)))
    },
  ).provideSomeLayerShared[Scope](env) @@ TestAspect.withLiveClock @@ TestAspect.withLiveRandom
