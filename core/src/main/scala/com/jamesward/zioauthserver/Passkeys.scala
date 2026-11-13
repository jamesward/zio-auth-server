package com.jamesward.zioauthserver

import com.yubico.webauthn.*
import com.yubico.webauthn.data.*
import zio.*
import zio.http.*
import zio.json.*
import zio.json.ast.Json

import java.nio.ByteBuffer
import java.time.Instant
import java.util.Optional
import scala.jdk.CollectionConverters.*

/**
 * The relying party: `rpId` is the domain passkeys are bound to (the sign-in host, or a parent domain), `origins` the
 * pages allowed to use them, for example `Set("https://factory.example.com")`.
 */
final case class PasskeyConfig(
    rpId:        String,
    rpName:      String,
    origins:     Set[String],
    ceremonyTtl: Duration = 5.minutes,
    stepUpAge:   Duration = StepUp.defaultMaxAge,
)

object PasskeyConfig:
  /** The relying party is the base URL's host, and the only origin is the base URL's. */
  def forBaseUrl(cfg: AuthServerConfig, rpName: String): PasskeyConfig =
    val host = cfg.baseUrl.host.getOrElse("localhost")
    PasskeyConfig(rpId = host, rpName = rpName, origins = Set(cfg.issuer))

/**
 * Passkey sign-in and registration (WebAuthn, verified with Yubico's `java-webauthn-server`). Opt-in: mount these
 * routes next to [[LoginRoutes]] and include [[Passkeys.script]] in the pages that have the buttons.
 *
 *   - `POST /auth/passkey/options`, then `POST /auth/passkey/verify`: sign in with a discoverable passkey. Only
 *     registered passkeys sign in, so this never creates an account.
 *   - `POST /account/passkeys/options`, then `POST /account/passkeys/register`: add a passkey. Needs a session that
 *     started within `stepUpAge` ([[StepUp]]); an older one answers 401 with `{"reauth": "/login?reauth=1&..."}`.
 *   - `POST /account/passkeys/remove`: remove one (also step-up).
 *
 * The account routes need the `X-CSRF-Token` header (the csrf cookie's value). All of them need
 * `Content-Type: application/json`, which a cross-site form can't send.
 */
final class PasskeyRoutes[U: Tag](cfg: AuthServerConfig, passkeys: PasskeyConfig)(using view: AccountView[U]):
  import PasskeyRoutes.*

  type Env = AuthStore[U] & AccountStore[U] & PasskeyStore & SecureRandomGen & JwtSigner

  val routes: Routes[Env, Response] =
    Routes(
      Method.POST / "auth" / "passkey" / "options"     -> handler(signInOptions),
      Method.POST / "auth" / "passkey" / "verify"      -> handler(signInVerify),
      Method.POST / "account" / "passkeys" / "options" -> handler(registerOptions),
      Method.POST / "account" / "passkeys" / "register" -> handler(registerFinish),
      Method.POST / "account" / "passkeys" / "remove"  -> handler(remove),
    )

  // The Yubico library reads credentials through a synchronous repository; each ceremony loads what it needs from the
  // store first and hands the library this snapshot.
  private def relyingParty(known: List[Passkey]): RelyingParty =
    RelyingParty
      .builder()
      .identity(RelyingPartyIdentity.builder().id(passkeys.rpId).name(passkeys.rpName).build())
      .credentialRepository(SnapshotRepository(known))
      .origins(passkeys.origins.asJava)
      .build()

  // ── sign-in ──────────────────────────────────────────────────────────────

  private def signInOptions(req: Request): URIO[Env, Response] =
    val effect =
      for
        _       <- requireJson(req)
        request  = relyingParty(Nil).startAssertion(
                     StartAssertionOptions.builder().userVerification(UserVerificationRequirement.PREFERRED).build()
                   )
        id      <- PasskeyCeremonyId.mint
        now     <- Clock.instant
        _       <- ZIO.serviceWithZIO[PasskeyStore](
                     _.createCeremony(PasskeyCeremony(id, PasskeyCeremonyKind.Assertion, None, request.toJson, expiry(now)))
                   ).mapError(Sessions.asThrowable)
      yield jsonResponse(s"""{"ceremony":"${id.value}","options":${request.toCredentialsGetJson}}""")
    effect.catchAll(handleFailure)

  private def signInVerify(req: Request): URIO[Env, Response] =
    val effect =
      for
        _          <- requireJson(req)
        body       <- decodeBody[VerifyBody](req)
        now        <- Clock.instant
        ceremony   <- takeCeremony(body.ceremony, PasskeyCeremonyKind.Assertion, now)
        credential <- ZIO.attempt(PublicKeyCredential.parseAssertionResponseJson(body.credential.toJson))
                        .orElseFail(failure(Status.BadRequest, "bad credential"))
        known      <- ZIO.serviceWithZIO[PasskeyStore](_.findPasskey(PasskeyCredentialId.of(credential.getId.getBase64Url)))
                        .mapError(Sessions.asThrowable)
        passkey    <- ZIO.fromOption(known).orElseFail(failure(Status.Unauthorized, "unknown passkey"))
        result     <- ZIO
                        .attempt(
                          relyingParty(List(passkey)).finishAssertion(
                            FinishAssertionOptions
                              .builder()
                              .request(AssertionRequest.fromJson(ceremony.requestJson))
                              .response(credential)
                              .build()
                          )
                        )
                        .tapError(t => ZIO.logInfo(s"passkey sign-in rejected: ${t.getMessage}"))
                        .orElseFail(failure(Status.Unauthorized, "passkey verification failed"))
        _          <- ZIO.unless(result.isSuccess)(ZIO.fail(failure(Status.Unauthorized, "passkey verification failed")))
        _          <- ZIO.serviceWithZIO[PasskeyStore](_.recordPasskeyUse(passkey.credentialId, result.getSignatureCount, now))
                        .mapError(Sessions.asThrowable)
        minted     <- Sessions.mint(cfg, now)
        userOpt    <- ZIO.serviceWithZIO[AccountStore[U]](
                        _.startSession(passkey.userId, minted.sessionIdHash, minted.csrfHash, minted.expiresAt)
                      ).mapError(Sessions.asThrowable)
        user       <- ZIO.fromOption(userOpt).orElseFail(failure(Status.Unauthorized, "account not active"))
        access     <- Sessions.accessCookie(cfg, user, minted.csrfHash, now)
        target      = body.returnTo.flatMap(cfg.safeReturnTo).getOrElse("/")
      yield (minted.cookies :+ access).foldLeft(jsonResponse(Json.Obj("redirect" -> Json.Str(target)).toJson))(_.addCookie(_))
    effect.catchAll(handleFailure)

  // ── registration (step-up) ───────────────────────────────────────────────

  private def registerOptions(req: Request): URIO[Env, Response] =
    val effect =
      for
        (_, user) <- freshSession(req)
        existing  <- ZIO.serviceWithZIO[PasskeyStore](_.passkeys(view.id(user))).mapError(Sessions.asThrowable)
        request    = relyingParty(existing).startRegistration(
                       StartRegistrationOptions
                         .builder()
                         .user(
                           UserIdentity
                             .builder()
                             .name(view.email(user).value)
                             .displayName(view.email(user).value)
                             .id(userHandle(view.id(user)))
                             .build()
                         )
                         .authenticatorSelection(
                           AuthenticatorSelectionCriteria
                             .builder()
                             .residentKey(ResidentKeyRequirement.REQUIRED)
                             .userVerification(UserVerificationRequirement.PREFERRED)
                             .build()
                         )
                         .build()
                     )
        id        <- PasskeyCeremonyId.mint
        now       <- Clock.instant
        _         <- ZIO.serviceWithZIO[PasskeyStore](
                       _.createCeremony(
                         PasskeyCeremony(id, PasskeyCeremonyKind.Registration, Some(view.id(user)), request.toJson, expiry(now))
                       )
                     ).mapError(Sessions.asThrowable)
      yield jsonResponse(s"""{"ceremony":"${id.value}","options":${request.toCredentialsCreateJson}}""")
    effect.catchAll(handleFailure)

  private def registerFinish(req: Request): URIO[Env, Response] =
    val effect =
      for
        (_, user)  <- freshSession(req)
        body       <- decodeBody[RegisterBody](req)
        now        <- Clock.instant
        ceremony   <- takeCeremony(body.ceremony, PasskeyCeremonyKind.Registration, now)
        _          <- ZIO.unless(ceremony.userId.contains(view.id(user)))(
                        ZIO.fail(failure(Status.BadRequest, "ceremony belongs to another user"))
                      )
        credential <- ZIO.attempt(PublicKeyCredential.parseRegistrationResponseJson(body.credential.toJson))
                        .orElseFail(failure(Status.BadRequest, "bad credential"))
        existing   <- ZIO.serviceWithZIO[PasskeyStore](_.passkeys(view.id(user))).mapError(Sessions.asThrowable)
        result     <- ZIO
                        .attempt(
                          relyingParty(existing).finishRegistration(
                            FinishRegistrationOptions
                              .builder()
                              .request(PublicKeyCredentialCreationOptions.fromJson(ceremony.requestJson))
                              .response(credential)
                              .build()
                          )
                        )
                        .tapError(t => ZIO.logInfo(s"passkey registration rejected: ${t.getMessage}"))
                        .orElseFail(failure(Status.BadRequest, "passkey registration failed"))
        passkey     = Passkey(
                        credentialId = PasskeyCredentialId.of(result.getKeyId.getId.getBase64Url),
                        userId = view.id(user),
                        userHandle = userHandle(view.id(user)).getBase64Url,
                        publicKeyCose = result.getPublicKeyCose.getBase64Url,
                        signatureCount = result.getSignatureCount,
                        name = body.name.map(_.trim).filter(_.nonEmpty).getOrElse("Passkey").take(100),
                        createdAt = now,
                        lastUsedAt = None,
                      )
        _          <- ZIO.serviceWithZIO[PasskeyStore](_.addPasskey(passkey)).mapError {
                        case PasskeyError.DuplicateCredential => failure(Status.Conflict, "passkey already registered")
                        case PasskeyError.Internal(m)         => new RuntimeException(m)
                      }
        _          <- ZIO.logInfo(s"passkey added for user ${view.id(user).value}")
      yield jsonResponse(Json.Obj("credentialId" -> Json.Str(passkey.credentialId.value)).toJson)
    effect.catchAll(handleFailure)

  private def remove(req: Request): URIO[Env, Response] =
    val effect =
      for
        (_, user) <- freshSession(req)
        body      <- decodeBody[RemoveBody](req)
        removed   <- ZIO.serviceWithZIO[PasskeyStore](_.removePasskey(view.id(user), PasskeyCredentialId.of(body.credentialId)))
                       .mapError(Sessions.asThrowable)
        _         <- ZIO.unless(removed)(ZIO.fail(failure(Status.NotFound, "no such passkey")))
        _         <- ZIO.logInfo(s"passkey removed for user ${view.id(user).value}")
      yield jsonResponse("{}")
    effect.catchAll(handleFailure)

  // ── helpers ──────────────────────────────────────────────────────────────

  private def expiry(now: Instant): Instant = now.plus(java.time.Duration.ofMillis(passkeys.ceremonyTtl.toMillis))

  private def takeCeremony(raw: String, kind: PasskeyCeremonyKind, now: Instant): ZIO[PasskeyStore, Throwable, PasskeyCeremony] =
    for
      id       <- ZIO.attempt(PasskeyCeremonyId.fresh(java.util.UUID.fromString(raw))).orElseFail(failure(Status.BadRequest, "bad ceremony"))
      taken    <- ZIO.serviceWithZIO[PasskeyStore](_.takeCeremony(id, now)).mapError(Sessions.asThrowable)
      ceremony <- ZIO.fromOption(taken.filter(_.kind == kind)).orElseFail(failure(Status.BadRequest, "ceremony expired or unknown"))
    yield ceremony

  /** A signed-in user whose session is fresh enough for an identity change, with a valid `X-CSRF-Token`. */
  private def freshSession(req: Request): ZIO[Env, Throwable, (Session, U)] =
    for
      _       <- requireJson(req)
      current <- Sessions.current[U](cfg, req)
      pair    <- ZIO.fromOption(current).orElseFail(failure(Status.Unauthorized, "not signed in"))
      csrf     = req.headers.get("X-CSRF-Token").getOrElse("")
      _       <- ZIO.unless(Csrf.isValid(cfg, csrf, pair._1))(ZIO.fail(failure(Status.Forbidden, "bad csrf")))
      now     <- Clock.instant
      _       <- ZIO.unless(StepUp.isFresh(pair._1, now, passkeys.stepUpAge))(
                   ZIO.fail(
                     Failure(
                       jsonResponse(Json.Obj("reauth" -> Json.Str(StepUp.reauthPath(req.url.path.encode))).toJson)
                         .status(Status.Unauthorized)
                     )
                   )
                 )
    yield pair

object PasskeyRoutes:

  private final case class VerifyBody(ceremony: String, credential: Json, returnTo: Option[String]) derives JsonDecoder
  private final case class RegisterBody(ceremony: String, credential: Json, name: Option[String]) derives JsonDecoder
  private final case class RemoveBody(credentialId: String) derives JsonDecoder

  /** A response to send as is, carried in the error channel. */
  private final case class Failure(response: Response) extends RuntimeException("passkey request failed", null, false, false)

  private def failure(status: Status, message: String): Failure =
    Failure(jsonResponse(Json.Obj("error" -> Json.Str(message)).toJson).status(status))

  private def jsonResponse(body: String): Response =
    Response(
      status = Status.Ok,
      headers = Headers(Header.ContentType(MediaType.application.json), Header.CacheControl.NoStore),
      body = Body.fromString(body),
    )

  private def handleFailure(t: Throwable): UIO[Response] = t match
    case Failure(response) => ZIO.succeed(response)
    case other             => ZIO.logErrorCause("passkey route failed", Cause.fail(other)).as(Response.status(Status.InternalServerError))

  private def requireJson(req: Request): IO[Failure, Unit] =
    ZIO.unless(req.header(Header.ContentType).exists(_.mediaType.matches(MediaType.application.json)))(
      ZIO.fail(failure(Status.UnsupportedMediaType, "application/json required"))
    ).unit

  private def decodeBody[A: JsonDecoder](req: Request): Task[A] =
    req.body.asString.flatMap(s => ZIO.fromEither(s.fromJson[A]).mapError(e => failure(Status.BadRequest, s"bad request: $e")))

  /** The WebAuthn user handle: the user id's 16 bytes. */
  def userHandle(id: UserId): ByteArray =
    val buf = ByteBuffer.allocate(16)
    buf.putLong(id.value.getMostSignificantBits).putLong(id.value.getLeastSignificantBits)
    new ByteArray(buf.array())

  private final class SnapshotRepository(known: List[Passkey]) extends CredentialRepository:
    private def registered(p: Passkey): RegisteredCredential =
      RegisteredCredential
        .builder()
        .credentialId(ByteArray.fromBase64Url(p.credentialId.value))
        .userHandle(ByteArray.fromBase64Url(p.userHandle))
        .publicKeyCose(ByteArray.fromBase64Url(p.publicKeyCose))
        .signatureCount(p.signatureCount)
        .build()

    // The library's "username" is the user id.
    def getCredentialIdsForUsername(username: String): java.util.Set[PublicKeyCredentialDescriptor] =
      known
        .filter(_.userId.value.toString == username)
        .map(p => PublicKeyCredentialDescriptor.builder().id(ByteArray.fromBase64Url(p.credentialId.value)).build())
        .toSet
        .asJava

    def getUserHandleForUsername(username: String): Optional[ByteArray] =
      Optional.ofNullable(known.find(_.userId.value.toString == username).map(p => ByteArray.fromBase64Url(p.userHandle)).orNull)

    def getUsernameForUserHandle(handle: ByteArray): Optional[String] =
      Optional.ofNullable(known.find(_.userHandle == handle.getBase64Url).map(_.userId.value.toString).orNull)

    def lookup(credentialId: ByteArray, handle: ByteArray): Optional[RegisteredCredential] =
      Optional.ofNullable(
        known
          .find(p => p.credentialId.value == credentialId.getBase64Url && p.userHandle == handle.getBase64Url)
          .map(registered)
          .orNull
      )

    def lookupAll(credentialId: ByteArray): java.util.Set[RegisteredCredential] =
      known.filter(_.credentialId.value == credentialId.getBase64Url).map(registered).toSet.asJava

object Passkeys:

  /**
   * Browser side, for the app's pages: `zioAuthPasskeySignIn(returnTo)` and `zioAuthPasskeyRegister(name)`. Both
   * follow the server's `redirect`, or `reauth` when a registration needs a fresh sign-in. Uses the WebAuthn JSON helpers
   * (`PublicKeyCredential.parse…OptionsFromJSON`, `credential.toJSON()`), in current Chrome, Safari and Firefox.
   */
  def script(csrfCookieName: String): String =
    s"""(function () {
       |  function csrf() {
       |    var m = document.cookie.match(new RegExp('(?:^|; )' + ${Json.Str(csrfCookieName).toJson} + '=([^;]*)'));
       |    return m ? decodeURIComponent(m[1]) : '';
       |  }
       |  async function post(path, body, withCsrf) {
       |    var headers = { 'Content-Type': 'application/json' };
       |    if (withCsrf) headers['X-CSRF-Token'] = csrf();
       |    var r = await fetch(path, { method: 'POST', headers: headers, body: JSON.stringify(body), credentials: 'same-origin' });
       |    var json = await r.json().catch(function () { return {}; });
       |    if (json.reauth) { window.location.assign(json.reauth); throw new Error('sign in again'); }
       |    if (!r.ok) throw new Error(json.error || ('HTTP ' + r.status));
       |    return json;
       |  }
       |  window.zioAuthPasskeySignIn = async function (returnTo) {
       |    var start = await post('/auth/passkey/options', {}, false);
       |    var options = PublicKeyCredential.parseRequestOptionsFromJSON(start.options.publicKey);
       |    var credential = await navigator.credentials.get({ publicKey: options, mediation: start.options.mediation });
       |    var done = await post('/auth/passkey/verify', { ceremony: start.ceremony, credential: credential.toJSON(), returnTo: returnTo || null }, false);
       |    window.location.assign(done.redirect);
       |  };
       |  window.zioAuthPasskeyRegister = async function (name) {
       |    var start = await post('/account/passkeys/options', {}, true);
       |    var options = PublicKeyCredential.parseCreationOptionsFromJSON(start.options.publicKey);
       |    var credential = await navigator.credentials.create({ publicKey: options });
       |    return post('/account/passkeys/register', { ceremony: start.ceremony, credential: credential.toJSON(), name: name || null }, true);
       |  };
       |})();
       |""".stripMargin
