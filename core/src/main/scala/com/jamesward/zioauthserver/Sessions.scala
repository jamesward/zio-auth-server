package com.jamesward.zioauthserver

import zio.*
import zio.http.*

import java.time.Instant

/** Browser sessions: the session and csrf cookies, and the short-lived access-JWT cookie. */
object Sessions:

  def current[U: Tag](cfg: AuthServerConfig, req: Request): RIO[AuthStore[U], Option[(Session, U)]] =
    for
      now    <- Clock.instant
      result <- readCookie(req, cfg.cookies.sessionName) match
                  case None        => ZIO.none
                  case Some(value) =>
                    val hash = SessionIdHash.fromBytes(Crypto.hmacSha256(value, cfg.pepper.value))
                    ZIO.serviceWithZIO[AuthStore[U]](_.findSession(hash)).mapError(asThrowable).map {
                      case Some((session, user)) if now.isBefore(session.expiresAt) => Some((session, user))
                      case _                                                     => None
                    }
    yield result

  final case class MintedSession(
      sessionIdHash: SessionIdHash,
      csrfHash:      CsrfTokenHash,
      expiresAt:     Instant,
      cookies:       List[Cookie.Response],
  )

  def mint(cfg: AuthServerConfig, now: Instant): RIO[SecureRandomGen, MintedSession] =
    for
      sid  <- SessionId.mint
      csrf <- CsrfToken.mint
    yield fixed(cfg, now, sid, csrf)

  /**
   * A session from caller-chosen session-id and csrf plaintext. Public only through `zio-auth-server-test`
   * (`testkit.DevSessions.fixed`), so production code can't mint a predictable session.
   */
  private[zioauthserver] def fixed(cfg: AuthServerConfig, now: Instant, sid: SessionId, csrf: CsrfToken): MintedSession =
    val sidHash   = SessionIdHash.fromBytes(Crypto.hmacSha256(sid.value, cfg.pepper.value))
    val csrfHash  = CsrfTokenHash.fromBytes(Crypto.hmacSha256(csrf.value, cfg.pepper.value))
    val expiresAt = now.plus(java.time.Duration.ofMillis(cfg.sessionTtl.toMillis))
    val cookies   = List(
      sessionCookie(cfg.cookies, sid.value, cfg.sessionTtl),
      csrfCookie(cfg.cookies, csrf.value, cfg.sessionTtl),
    )
    MintedSession(sidHash, csrfHash, expiresAt, cookies)

  def end[U: Tag](cfg: AuthServerConfig, session: Session): RIO[AuthStore[U], List[Cookie.Response]] =
    ZIO.serviceWithZIO[AuthStore[U]](_.deleteSession(session.idHash)).mapError(asThrowable).as(
      List(
        clearCookie(cfg.cookies.sessionName, cfg.cookies),
        clearCookie(cfg.cookies.csrfName, cfg.cookies),
        clearCookie(cfg.cookies.accessName, cfg.cookies),
      )
    )

  /**
   * Mints the short-lived access-JWT cookie for a freshly-authenticated user. Called after the session row exists (so
   * the csrf hash is bound); the JWT carries the user's id and scopes plus the csrf binding.
   */
  def accessCookie[U](cfg: AuthServerConfig, user: U, csrfHash: CsrfTokenHash, now: Instant)(using
      view: AccountView[U]
  ): URIO[JwtSigner, Cookie.Response] =
    for
      signer    <- ZIO.service[JwtSigner]
      jti       <- Random.nextUUID.map(_.toString)
      expiresAt  = now.plus(java.time.Duration.ofMillis(cfg.accessTtl.toMillis))
      claims     = SessionClaims.build(cfg.issuer, view.id(user), view.scopes(user), csrfHash, now, expiresAt, jti)
      token     <- signer.sign(claims)
    yield accessTokenCookie(cfg.cookies, token, cfg.accessTtl)

  def readCookie(req: Request, name: String): Option[String] =
    req.headers.get(Header.Cookie).flatMap(_.value.find(_.name == name).map(_.content))

  private[zioauthserver] def asThrowable(e: StoreError): Throwable =
    e match
      case StoreError.Internal(message) => new RuntimeException(message)

  private def accessTokenCookie(cfg: CookieConfig, value: String, ttl: Duration): Cookie.Response =
    Cookie.Response(
      name = cfg.accessName,
      content = value,
      domain = cfg.domain,
      path = Some(Path.root),
      isSecure = cfg.secure,
      isHttpOnly = true,
      maxAge = Some(ttl),
      sameSite = Some(Cookie.SameSite.Lax),
    )

  private def sessionCookie(cfg: CookieConfig, value: String, ttl: Duration): Cookie.Response =
    Cookie.Response(
      name = cfg.sessionName,
      content = value,
      domain = cfg.domain,
      path = Some(Path.root),
      isSecure = cfg.secure,
      isHttpOnly = true,
      maxAge = Some(ttl),
      sameSite = Some(Cookie.SameSite.Lax),
    )

  // Intentionally NOT HttpOnly: a form template reads the token to include it as a hidden field on submit.
  private def csrfCookie(cfg: CookieConfig, value: String, ttl: Duration): Cookie.Response =
    Cookie.Response(
      name = cfg.csrfName,
      content = value,
      domain = cfg.domain,
      path = Some(Path.root),
      isSecure = cfg.secure,
      isHttpOnly = false,
      maxAge = Some(ttl),
      sameSite = Some(Cookie.SameSite.Lax),
    )

  private def clearCookie(name: String, cfg: CookieConfig): Cookie.Response =
    Cookie.Response(
      name = name,
      content = "",
      domain = cfg.domain,
      path = Some(Path.root),
      isSecure = cfg.secure,
      isHttpOnly = true,
      maxAge = Some(Duration.Zero),
      sameSite = Some(Cookie.SameSite.Lax),
    )
