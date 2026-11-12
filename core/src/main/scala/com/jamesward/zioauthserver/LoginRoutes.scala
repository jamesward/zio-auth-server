package com.jamesward.zioauthserver

import zio.*
import zio.http.*

/**
 * First-party sign-in: the email magic link, the emailed one-time code, the session-resume bounce at `/login`, and
 * sign-out.
 */
final class LoginRoutes[U: Tag](cfg: AuthServerConfig, pages: Pages[U], messages: Messages)(using AccountView[U]):

  type Env = AuthStore[U] & Mailer & SecureRandomGen & JwtSigner

  val routes: Routes[Env, Response] =
    Routes(
      Method.GET / ""                           -> handler(homeOrLogin),
      Method.GET / "login"                      -> handler(loginPage),
      Method.POST / "auth" / "email" / "start"  -> handler(startEmailAuth),
      Method.GET / "auth" / "email" / "verify"  -> handler(verifyEmailAuth),
      Method.GET / "login" / "otp"              -> handler(otpPage),
      Method.POST / "auth" / "otp" / "start"    -> handler(startOtpAuth),
      Method.POST / "auth" / "otp" / "verify"   -> handler(verifyOtpAuth),
      Method.GET / "logout"                     -> handler(logoutPage),
      Method.POST / "auth" / "logout"           -> handler(logoutSubmit),
    )

  private def htmlResponse(dom: zio.http.template2.Dom): Response =
    Response.html(dom)

  private def redirect(path: String): Response =
    Response
      .status(Status.SeeOther)
      .addHeader(Header.Location(URL.decode(path).toOption.get))

  extension (r: Response)
    private def addCookies(cs: List[Cookie.Response]): Response =
      cs.foldLeft(r)((acc, c) => acc.addCookie(c))

  private def crash(c: Cause[Throwable]): UIO[Response] =
    ZIO.logErrorCause("route failure", c).as(Response.status(Status.InternalServerError))

  private def store: URIO[AuthStore[U], AuthStore[U]] = ZIO.service[AuthStore[U]]

  private def homeOrLogin(req: Request): URIO[Env, Response] =
    val effect =
      Sessions.current[U](cfg, req).map {
        case Some((_, user)) => htmlResponse(pages.home(user))
        case None            => redirect("/login")
      }
    effect.catchAllCause(crash)

  /**
   * `/login` is the bounce target when another first-party server finds no valid access cookie. Before showing the
   * email form, try to RESUME an existing session: if the session cookie still resolves to a live session, re-mint a
   * fresh short-lived access cookie and 303 straight back to `return_to`. This is the transparent refresh that keeps a
   * signed-in user signed in across access-JWT expiry without a round trip through email. The `sent`/`invalid` query
   * params are explicit post-action states and always render as-is.
   */
  private def loginPage(req: Request): URIO[Env, Response] =
    val q  = req.url.queryParams
    val rt = q.queryParam("return_to").flatMap(cfg.safeReturnTo)
    if q.hasQueryParam("sent") then ZIO.succeed(htmlResponse(pages.magicLinkSent))
    else if q.hasQueryParam("invalid") then ZIO.succeed(htmlResponse(pages.invalidLink))
    else
      val effect =
        for
          sess <- Sessions.current[U](cfg, req)
          now  <- Clock.instant
          resp <- sess match
                    case Some((session, user)) =>
                      Sessions
                        .accessCookie(cfg, user, session.csrfHash, now)
                        .map(access => redirect(rt.getOrElse("/")).addCookie(access))
                    case None =>
                      ZIO.succeed(htmlResponse(pages.login(None, rt)))
        yield resp
      effect.catchAllCause(crash)

  private def startEmailAuth(req: Request): URIO[Env, Response] =
    val effect =
      for
        form    <- req.body.asURLEncodedForm
        emailStr = form.get("email").flatMap(_.stringValue).getOrElse("")
        rt       = form.get("return_to").flatMap(_.stringValue).flatMap(cfg.safeReturnTo)
        email   <- ZIO.fromEither(Email.parse(emailStr)).orElseFail(badRequest("invalid email"))
        _       <- mintAndSend(email, rt)
      yield redirect("/login?sent=1")
    effect.catchAll {
      case r: Response  => ZIO.succeed(r)
      case t: Throwable => crash(Cause.fail(t))
    }

  private def mintAndSend(email: Email, returnTo: Option[String]): RIO[Env, Unit] =
    for
      now    <- Clock.instant
      minted <- MagicTokenOps.mint(cfg)
      cid    <- EmailLoginChallengeId.mint
      ttl     = java.time.Duration.ofMillis(cfg.challengeTtl.toMillis)
      ch      = EmailLoginChallenge(
                  id = cid,
                  email = email,
                  tokenHash = minted.hash,
                  issuedAt = now,
                  expiresAt = now.plus(ttl),
                  consumedAt = None,
                )
      _      <- store.flatMap(_.createChallenge(ch)).mapError(Sessions.asThrowable)
      rtParam = returnTo.fold("")(t => s"&return_to=${java.net.URLEncoder.encode(t, "UTF-8")}")
      link    = s"${cfg.baseUrl.encode}/auth/email/verify?token=${minted.token.value}$rtParam"
      _      <- ZIO
                  .serviceWithZIO[Mailer](_.send(messages.magicLink(email, link, now, ch.expiresAt)))
                  .mapError(Sessions.asThrowable)
    yield ()

  // ── One-time passcode ────────────────────────────────────────────────────
  // The second first-party sign-in option. Same proof as the magic link (you control the mailbox), different delivery:
  // six digits are emailed and the visitor types them back. Useful when the link can't be clicked where it arrives — a
  // link opened in the mail app's browser lands in a session the original tab can't see, while a code carries across
  // devices.

  private def otpPath(returnTo: Option[String]): String =
    returnTo.fold("/login/otp")(t => s"/login/otp?return_to=${java.net.URLEncoder.encode(t, "UTF-8")}")

  private def startOtpAuth(req: Request): URIO[Env, Response] =
    val effect =
      for
        form    <- req.body.asURLEncodedForm
        emailStr = form.get("email").flatMap(_.stringValue).getOrElse("")
        rt       = form.get("return_to").flatMap(_.stringValue).flatMap(cfg.safeReturnTo)
        email   <- ZIO.fromEither(Email.parse(emailStr)).orElseFail(badRequest("invalid email"))
        _       <- mintAndSendCode(email)
      yield redirect(otpPath(rt)).addCookie(OtpPending.cookie(cfg, email))
    effect.catchAll {
      case r: Response  => ZIO.succeed(r)
      case t: Throwable => crash(Cause.fail(t))
    }

  private def mintAndSendCode(email: Email): RIO[Env, Unit] =
    for
      now    <- Clock.instant
      minted <- OtpOps.mint(cfg, email)
      cid    <- EmailOtpChallengeId.mint
      ttl     = java.time.Duration.ofMillis(cfg.otpTtl.toMillis)
      ch      = EmailOtpChallenge(
                  id = cid,
                  email = email,
                  codeHash = minted.hash,
                  issuedAt = now,
                  expiresAt = now.plus(ttl),
                  consumedAt = None,
                  attempts = 0,
                )
      _      <- store.flatMap(_.createOtpChallenge(ch)).mapError(Sessions.asThrowable)
      _      <- ZIO
                  .serviceWithZIO[Mailer](_.send(messages.otpCode(email, minted.code, now, ch.expiresAt)))
                  .mapError(Sessions.asThrowable)
    yield ()

  /**
   * The code form. Which address is being verified comes from the pending-OTP cookie, so a visitor who lands here cold
   * (or after it expires) is sent back to /login to start over rather than shown an address-less form.
   */
  private def otpPage(req: Request): URIO[Env, Response] =
    val rt = req.url.queryParams.queryParam("return_to").flatMap(cfg.safeReturnTo)
    ZIO.succeed(
      OtpPending.read(cfg, req) match
        case Some(email) => htmlResponse(pages.otp(email, rt, None))
        case None        => redirect("/login")
    )

  private def verifyOtpAuth(req: Request): URIO[Env, Response] =
    val effect =
      for
        form    <- req.body.asURLEncodedForm
        codeStr  = form.get("code").flatMap(_.stringValue).getOrElse("")
        rt       = form.get("return_to").flatMap(_.stringValue).flatMap(cfg.safeReturnTo)
        email   <- ZIO.fromOption(OtpPending.read(cfg, req)).orElseFail(redirect("/login"))
        resp    <- OtpCode.parse(codeStr) match
                     // A malformed code never reaches the store: nothing to consume, and no attempt to burn.
                     case Left(_)     =>
                       ZIO.succeed(htmlResponse(pages.otp(email, rt, Some(s"Enter the ${OtpCode.length}-digit code from the email."))))
                     case Right(code) => submitOtp(email, code, rt)
      yield resp
    effect.catchAll {
      case r: Response  => ZIO.succeed(r)
      case t: Throwable => crash(Cause.fail(t))
    }

  private def submitOtp(email: Email, code: OtpCode, returnTo: Option[String]): RIO[Env, Response] =
    for
      now      <- Clock.instant
      minted   <- Sessions.mint(cfg, now)
      request   = VerifyOtpAndStartSessionRequest(
                    email = email,
                    presentedCodeHash = OtpCodeHash.hash(email, code, cfg.pepper.value),
                    sessionIdHash = minted.sessionIdHash,
                    csrfHash = minted.csrfHash,
                    sessionExpiresAt = minted.expiresAt,
                  )
      result   <- store.flatMap(_.verifyOtpAndStartSession(request)).either
      response <- result match
                    case Right(user)    =>
                      Sessions
                        .accessCookie(cfg, user, minted.csrfHash, now)
                        .map(access =>
                          redirect(returnTo.getOrElse("/")).addCookies(minted.cookies :+ access :+ OtpPending.clear(cfg))
                        )
                    case Left(otpError) =>
                      // Unlike the magic link, the visitor is sitting in front of the form: say enough to act on (retry
                      // vs. request a new code) without naming which challenge state was found. `Internal` is logged.
                      val logIfInternal = otpError match
                        case VerifyOtpError.Internal(message) => ZIO.logWarning(s"login verifyOtpAuth failed: $message")
                        case _                                => ZIO.unit
                      val message       = otpError match
                        case VerifyOtpError.CodeMismatch    => "That code isn't right. Check the email and try again."
                        case VerifyOtpError.TooManyAttempts => "Too many incorrect attempts. Request a new code."
                        case VerifyOtpError.Expired         => "That code has expired. Request a new one."
                        case VerifyOtpError.AlreadyConsumed => "That code has already been used. Request a new one."
                        case VerifyOtpError.NotFound        => "We don't have a code for that address any more. Request a new one."
                        case VerifyOtpError.Internal(_)     => "Something went wrong. Try again."
                      logIfInternal.as(htmlResponse(pages.otp(email, returnTo, Some(message))))
    yield response

  private def verifyEmailAuth(req: Request): URIO[Env, Response] =
    val effect =
      for
        tokenStr <- ZIO.fromOption(req.url.queryParams.queryParam("token")).orElseFail(redirect("/login?invalid=1"))
        now      <- Clock.instant
        token     = MagicToken.fromBase64Url(tokenStr)
        tHash     = MagicTokenHash.hash(token.value, cfg.pepper.value)
        minted   <- Sessions.mint(cfg, now)
        request   = VerifyAndStartSessionRequest(
                      presentedTokenHash = tHash,
                      sessionIdHash = minted.sessionIdHash,
                      csrfHash = minted.csrfHash,
                      sessionExpiresAt = minted.expiresAt,
                    )
        result   <- store.flatMap(_.verifyAndStartSession(request)).either
        response <- result match
                      case Right(user)       =>
                        val target = req.url.queryParams.queryParam("return_to").flatMap(cfg.safeReturnTo).getOrElse("/")
                        Sessions
                          .accessCookie(cfg, user, minted.csrfHash, now)
                          .map(access => redirect(target).addCookies(minted.cookies :+ access))
                      case Left(verifyError) =>
                        // Don't leak which error: missing / consumed / expired / mismatch all collapse to one "invalid
                        // link" page, but an `Internal` failure is a real error and is still logged.
                        val logIfInternal = verifyError match
                          case VerifyError.Internal(message) => ZIO.logWarning(s"login verifyEmailAuth failed: $message")
                          case _                             => ZIO.unit
                        logIfInternal.as(redirect("/login?invalid=1"))
      yield response
    effect.catchAll {
      case r: Response  => ZIO.succeed(r)
      case t: Throwable => crash(Cause.fail(t))
    }

  private def logoutPage(req: Request): URIO[Env, Response] =
    val effect =
      Sessions.current[U](cfg, req).map {
        case Some((_, user)) =>
          htmlResponse(pages.logoutConfirm(user, readCsrfTokenFromCookie(req, cfg.cookies.csrfName)))
        case None            => redirect("/login")
      }
    effect.catchAllCause(crash)

  private def logoutSubmit(req: Request): URIO[Env, Response] =
    val effect =
      for
        sessionAndUser <- Sessions.current[U](cfg, req)
        result         <- sessionAndUser match
                            case None               => ZIO.succeed(redirect("/login"))
                            case Some((session, _)) =>
                              for
                                csrfStr <- Csrf.readFormField(req).map(_.getOrElse(""))
                                resp    <- if !Csrf.isValid(cfg, csrfStr, session) then ZIO.succeed(forbidden("bad csrf"))
                                           else Sessions.end[U](cfg, session).map(cookies => redirect("/login").addCookies(cookies))
                              yield resp
      yield result
    effect.catchAllCause(crash)

  private def badRequest(msg: String): Response =
    Response.status(Status.BadRequest).copy(body = Body.fromString(msg))

  private def forbidden(msg: String): Response =
    Response.status(Status.Forbidden).copy(body = Body.fromString(msg))

  private def readCsrfTokenFromCookie(req: Request, cookieName: String): CsrfToken =
    CsrfToken.fromBase64Url(Sessions.readCookie(req, cookieName).getOrElse(""))
