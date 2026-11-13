package com.jamesward.zioauthserver

import zio.*
import zio.http.*

/**
 * Changing the sign-in address. Opt-in, like [[PasskeyRoutes]].
 *
 *   - `POST /account/email` (form fields `email`, `_csrf`): needs a session that started within `stepUpAge`
 *     ([[StepUp]]; an older one is sent to sign in again). Mails a link to the NEW address; nothing changes yet.
 *   - `GET /account/email/verify?token=…`: the link. Moves the user to the new address, unless another user has it.
 */
final class AccountRoutes[U: Tag](
    cfg:       AuthServerConfig,
    messages:  Messages,
    stepUpAge: Duration = StepUp.defaultMaxAge,
)(using view: AccountView[U]):

  type Env = AuthStore[U] & AccountStore[U] & Mailer & SecureRandomGen

  val routes: Routes[Env, Response] =
    Routes(
      Method.POST / "account" / "email"           -> handler(start),
      Method.GET / "account" / "email" / "verify" -> handler(verify),
    )

  private def start(req: Request): URIO[Env, Response] =
    val effect =
      for
        current <- Sessions.current[U](cfg, req)
        result  <- current match
                     case None                  => ZIO.succeed(seeOther("/login"))
                     case Some((session, user)) =>
                       for
                         form <- req.body.asURLEncodedForm
                         csrf  = form.get("_csrf").flatMap(_.stringValue).getOrElse("")
                         now  <- Clock.instant
                         resp <- if !Csrf.isValid(cfg, csrf, session) then ZIO.succeed(Response.status(Status.Forbidden))
                                 else if !StepUp.isFresh(session, now, stepUpAge) then
                                   ZIO.succeed(seeOther(StepUp.reauthPath("/")))
                                 else
                                   Email.parse(form.get("email").flatMap(_.stringValue).getOrElse("")) match
                                     case Left(_)      => ZIO.succeed(Response.text("Enter a valid email address.").status(Status.BadRequest))
                                     case Right(email) => sendConfirmation(view.id(user), email, now)
                       yield resp
      yield result
    effect.catchAllCause(c => ZIO.logErrorCause("email change failed", c).as(Response.status(Status.InternalServerError)))

  private def sendConfirmation(userId: UserId, email: Email, now: java.time.Instant): RIO[Env, Response] =
    for
      minted <- MagicTokenOps.mint(cfg)
      id     <- EmailChangeId.mint
      ch      = EmailChangeChallenge(
                  id,
                  userId,
                  email,
                  minted.hash,
                  now,
                  now.plus(java.time.Duration.ofMillis(cfg.challengeTtl.toMillis)),
                  None,
                )
      _      <- ZIO.serviceWithZIO[AccountStore[U]](_.createEmailChange(ch)).mapError(Sessions.asThrowable)
      link    = s"${cfg.baseUrl.encode}/account/email/verify?token=${minted.token.value}"
      _      <- ZIO.serviceWithZIO[Mailer](_.send(messages.emailChange(email, link, now, ch.expiresAt))).mapError(Sessions.asThrowable)
      _      <- ZIO.logInfo(s"email change started for user ${userId.value}")
    yield Response.text(s"We emailed a confirmation link to ${email.value}. Your address changes when you click it.")

  private def verify(req: Request): URIO[Env, Response] =
    req.url.queryParams.queryParam("token") match
      case None        => ZIO.succeed(Response.text("That link is not valid.").status(Status.BadRequest))
      case Some(token) =>
        val hash = MagicTokenHash.hash(MagicToken.fromBase64Url(token).value, cfg.pepper.value)
        Clock.instant.flatMap(now => ZIO.serviceWithZIO[AccountStore[U]](_.confirmEmailChange(hash, now))).either.flatMap {
          case Right(user) =>
            ZIO.logInfo(s"email changed for user ${view.id(user).value}")
              .as(Response.text(s"Your sign-in address is now ${view.email(user).value}."))
          case Left(EmailChangeError.EmailTaken)  =>
            ZIO.succeed(Response.text("That address belongs to another account.").status(Status.Conflict))
          case Left(EmailChangeError.Internal(m)) =>
            ZIO.logWarning(s"email change verify failed: $m").as(Response.status(Status.InternalServerError))
          case Left(_)                            =>
            ZIO.succeed(Response.text("That link is no longer valid.").status(Status.BadRequest))
        }

  private def seeOther(path: String): Response =
    Response.status(Status.SeeOther).addHeader(Header.Location(URL.decode(path).toOption.get))
