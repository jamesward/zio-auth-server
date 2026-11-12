package com.jamesward.zioauthserver

import zio.*
import zio.http.*

object Csrf:

  /**
   * Double-submit *bound to the session row*: the cookie carries the plain token, the form carries it too, and the form
   * value is compared against the session's csrf hash (HMAC under the server pepper) in constant time. A leaked cookie
   * alone won't validate; the row must still exist.
   */
  def isValid(cfg: AuthServerConfig, presented: String, session: Session): Boolean =
    val hash = Crypto.hmacSha256(presented, cfg.pepper.value)
    java.security.MessageDigest.isEqual(hash, session.csrfHash.bytes)

  def readFormField(req: Request): Task[Option[String]] =
    req.body.asURLEncodedForm.map(_.get("_csrf").flatMap(_.stringValue))

object MagicTokenOps:

  final case class Minted(token: MagicToken, hash: MagicTokenHash)

  def mint(cfg: AuthServerConfig): URIO[SecureRandomGen, Minted] =
    for
      rng      <- ZIO.service[SecureRandomGen]
      tokBytes <- rng.nextBytes(32)
      token     = MagicToken.fromBase64Url(Crypto.encodeB64Url(tokBytes))
    yield Minted(token, MagicTokenHash.hash(token.value, cfg.pepper.value))

/** The 6-digit code that gets emailed, plus the peppered hash the store keeps and compares against. */
object OtpOps:

  final case class Minted(code: OtpCode, hash: OtpCodeHash)

  def mint(cfg: AuthServerConfig, email: Email): URIO[SecureRandomGen, Minted] =
    OtpCode.mint.map(code => Minted(code, OtpCodeHash.hash(email, code, cfg.pepper.value)))

/**
 * Which address the visitor is part-way through signing in with. It has to survive the POST-redirect-GET between "send
 * me a code" and the code form, and the address shouldn't sit in the URL bar, so it rides in a short-lived HttpOnly
 * cookie.
 *
 * The cookie is not a credential: a visitor can point it at any address, but signing in still requires the code mailed
 * there. The stored hash covers the email, and the challenge only allows [[EmailOtpChallenge.maxAttempts]] guesses.
 */
object OtpPending:

  def cookie(cfg: AuthServerConfig, email: Email): Cookie.Response =
    Cookie.Response(
      name = cfg.cookies.otpName,
      content = java.net.URLEncoder.encode(email.value, "UTF-8"),
      domain = cfg.cookies.domain,
      path = Some(Path.root),
      isSecure = cfg.cookies.secure,
      isHttpOnly = true,
      maxAge = Some(cfg.otpTtl),
      sameSite = Some(Cookie.SameSite.Lax),
    )

  def clear(cfg: AuthServerConfig): Cookie.Response =
    Cookie.Response(
      name = cfg.cookies.otpName,
      content = "",
      domain = cfg.cookies.domain,
      path = Some(Path.root),
      isSecure = cfg.cookies.secure,
      isHttpOnly = true,
      maxAge = Some(Duration.Zero),
      sameSite = Some(Cookie.SameSite.Lax),
    )

  def read(cfg: AuthServerConfig, req: Request): Option[Email] =
    req.headers
      .get(Header.Cookie)
      .flatMap(_.value.find(_.name == cfg.cookies.otpName))
      .map(c => java.net.URLDecoder.decode(c.content, "UTF-8"))
      .flatMap(Email.parse(_).toOption)
