package com.jamesward.zioauthserver

import zio.*
import zio.http.URL

opaque type Pepper = String
object Pepper:
  def of(s: String): Pepper               = s
  extension (p: Pepper) def value: String = p
  given CanEqual[Pepper, Pepper]          = CanEqual.derived

final case class CookieConfig(
    sessionName: String,
    csrfName:    String,
    secure:      Boolean,
    /**
     * Short-lived access-JWT cookie (HttpOnly). Carries the verified principal so other first-party servers can derive
     * identity from a signed token instead of reloading the session row. Backed by the session cookie as the revocable
     * refresh.
     */
    accessName:  String = "access",
    /** Cross-subdomain cookie sharing, for example `Some("example.com")` so `www.` sees the cookies `login.` sets. */
    domain:      Option[String] = None,
    /** Which address a visitor is part-way through signing in with via a one-time code (HttpOnly). */
    otpName:     String = "otp",
)

/** Decides which `return_to` values the sign-in flow may redirect to. Anything else falls back to `/`. */
final case class ReturnToPolicy(check: String => Option[String]):
  def apply(s: String): Option[String] = check(s)

object ReturnToPolicy:
  /** Same-origin relative paths only (not protocol-relative `//host`). */
  val relativeOnly: ReturnToPolicy = ReturnToPolicy(s => Option.when(isRelative(s))(s))

  /** Relative paths, or absolute URLs whose scheme, host and port match `origin`. */
  def relativeOrOrigin(origin: URL): ReturnToPolicy =
    ReturnToPolicy { s =>
      if isRelative(s) then Some(s)
      else
        URL.decode(s).toOption.flatMap { u =>
          // `.equals` (not `==`): `Option[Scheme]` has no CanEqual, but Java equality on the Options is fine here.
          if u.scheme.equals(origin.scheme) && u.host.equals(origin.host) && u.port.equals(origin.port) then Some(s)
          else None
        }
    }

  private def isRelative(s: String): Boolean = s.startsWith("/") && !s.startsWith("//")

final case class AuthServerConfig(
    baseUrl:              URL,
    cookies:              CookieConfig,
    pepper:               Pepper,
    returnTo:             ReturnToPolicy = ReturnToPolicy.relativeOnly,
    sessionTtl:           Duration       = 365.days,
    accessTtl:            Duration       = 15.minutes,
    challengeTtl:         Duration       = 15.minutes,
    /** Shorter than the magic link's: a 6-digit code is guessable, so it gets a smaller window. */
    otpTtl:               Duration       = 10.minutes,
    authorizationCodeTtl: Duration       = 60.seconds,
    /**
     * Scopes a client may ask for and get on top of the user's own ([[AccountView.scopes]]). Any other requested scope
     * is dropped from the token, so a client can't ask its way to a role: a dynamically registered client may claim
     * any `scope` (say `role:admin`). Default: none.
     */
    clientScopes:         Set[OAuthScope] = Set.empty,
    /**
     * Clients that get a code without the consent page (your own first-party clients). Dynamic Client Registration
     * and CIMD let anyone create a client, so for them the signed-in user must approve each authorization, or a link
     * to `/oauth/authorize` would hand the attacker's client a code for the user. Default: every client asks.
     */
    skipConsent:          OAuthClient => Boolean = _ => false,
    /**
     * At most `otpCodesPerWindow` one-time codes are sent to one address per `otpWindow`. Each code allows
     * [[EmailOtpChallenge.maxAttempts]] guesses, so without a limit an attacker could keep asking for codes and keep
     * guessing. Over the limit, no code is sent and the newest one stays valid; the page doesn't say so, so it doesn't
     * reveal which addresses have accounts.
     */
    otpCodesPerWindow:    Int      = 5,
    otpWindow:            Duration = 1.hour,
    /**
     * Clients that may introspect any token (a resource server you registered). Every other client gets `active` only
     * for its own tokens: anyone can register a client, so introspection must not tell them about others' tokens.
     */
    introspectAnyToken:   OAuthClient => Boolean = _ => false,
    /**
     * Fetch Client ID Metadata Documents from `http://localhost` and other loopback addresses, for local development
     * and tests. Off in production: a CIMD `client_id` is a URL the server fetches, so it must not reach the server's
     * own or its network's private addresses ([[CimdAddressPolicy]]).
     */
    cimdAllowLoopback:    Boolean = false,
):
  /** The issuer: the base URL without a trailing slash. */
  val issuer: String = baseUrl.encode.stripSuffix("/")

  def safeReturnTo(s: String): Option[String] = returnTo(s)
