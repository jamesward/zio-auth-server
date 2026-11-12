package com.jamesward.zioauthserver

import zio.*
import zio.schema.*

import java.time.Instant

/**
 * Everything the authorization server persists. An application provides one implementation: a database-backed store,
 * or a client of its own API (toolbook's login server keeps its data behind an API).
 *
 * `U` is the application's user type. The store creates users on first sign-in and returns them, so the sign-in pages
 * and the [[AuthorizeGate]] see the application's own user, and [[AccountView]] says what the server needs from it.
 */
trait AuthStore[U]:
  // Email sign-in and browser sessions
  def createChallenge(challenge: EmailLoginChallenge): IO[StoreError, Unit]
  def verifyAndStartSession(request: VerifyAndStartSessionRequest): IO[VerifyError, U]
  def createOtpChallenge(challenge: EmailOtpChallenge): IO[StoreError, Unit]
  def verifyOtpAndStartSession(request: VerifyOtpAndStartSessionRequest): IO[VerifyOtpError, U]
  def findSession(idHash: SessionIdHash): IO[StoreError, Option[(Session, U)]]
  def deleteSession(idHash: SessionIdHash): IO[StoreError, Unit]

  // OAuth clients, codes and tokens
  def createClient(client: OAuthClient): IO[StoreError, Unit]
  def findClient(id: ClientId): IO[StoreError, Option[OAuthClient]]
  def createGrant(grant: AuthorizationGrant): IO[StoreError, Unit]

  /** Consumes the grant for `request.presentedCodeHash` exactly once (see [[AuthorizationGrant.consume]]). */
  def consumeGrant(request: ExchangeCodeRequest): IO[ExchangeError, ConsumedGrant]

  def createAccessToken(token: IssuedAccessToken): IO[StoreError, Unit]
  def findAccessToken(hash: AccessTokenHash): IO[StoreError, Option[IssuedAccessToken]]
  def revokeAccessTokenIfOwned(request: RevokeAccessTokenRequest): IO[StoreError, Unit]

  def createRefreshToken(token: IssuedRefreshToken): IO[StoreError, Unit]
  def findRefreshToken(hash: RefreshTokenHash): IO[StoreError, Option[IssuedRefreshToken]]

  /**
   * Atomically checks the old token (not found, revoked, expired, already rotated) and links it to `newToken`. A token
   * that was already rotated is a replay: revoke its whole chain and fail with [[RotateRefreshTokenError.Replay]].
   */
  def rotateRefreshToken(request: RotateRefreshTokenRequest): IO[RotateRefreshTokenError, Unit]

  /** Revokes the token's whole chain when it belongs to the requesting client; otherwise does nothing. */
  def revokeRefreshTokenIfOwned(request: RevokeRefreshTokenRequest): IO[StoreError, Unit]

/** Sends the sign-in emails. */
trait Mailer:
  def send(message: EmailMessage): IO[StoreError, Unit]

final case class EmailMessage(to: Email, subject: String, text: String)

/** A failure of the store's own machinery (database, network), as opposed to a business outcome. */
enum StoreError derives CanEqual:
  case Internal(message: String)

/** What the server needs from the application's user type. */
trait AccountView[U]:
  def id(user: U): UserId
  def email(user: U): Email

  /**
   * Scopes baked into every token minted for this user, on top of the scopes a client asked for. Toolbook puts its
   * role scopes here so resource servers can check `role:admin`.
   */
  def scopes(user: U): Set[OAuthScope]

final case class VerifyAndStartSessionRequest(
    presentedTokenHash: MagicTokenHash,
    sessionIdHash:      SessionIdHash,
    csrfHash:           CsrfTokenHash,
    sessionExpiresAt:   Instant,
) derives Schema

enum VerifyError derives CanEqual, Schema:
  case NotFound
  case AlreadyConsumed
  case Expired
  case TokenMismatch
  case Internal(message: String)

/**
 * OTP verification is looked up by EMAIL (a 6-digit code isn't a unique key), then the presented code hash is compared
 * against the newest live challenge for that address.
 */
final case class VerifyOtpAndStartSessionRequest(
    email:             Email,
    presentedCodeHash: OtpCodeHash,
    sessionIdHash:     SessionIdHash,
    csrfHash:          CsrfTokenHash,
    sessionExpiresAt:  Instant,
) derives Schema

enum VerifyOtpError derives CanEqual, Schema:
  case NotFound
  case AlreadyConsumed
  case Expired
  case CodeMismatch
  case TooManyAttempts
  case Internal(message: String)

final case class ExchangeCodeRequest(
    presentedCodeHash:    AuthorizationCodeHash,
    presentedClientId:    ClientId,
    presentedRedirectUri: RedirectUri,
    presentedChallenge:   String,
) derives Schema

/** A consumed grant, with the scopes of its user ([[AccountView.scopes]]) at the time of the exchange. */
final case class ConsumedGrant(
    userId:     UserId,
    userScopes: Set[OAuthScope],
    scopes:     Set[OAuthScope],
    resource:   Option[ResourceIndicator],
)

enum ExchangeError derives CanEqual, Schema:
  case GrantNotFound
  case AlreadyConsumed
  case Expired
  case ClientMismatch
  case RedirectUriMismatch
  case PkceMismatch
  case Internal(message: String)

final case class RevokeAccessTokenRequest(
    hash:               AccessTokenHash,
    requestingClientId: ClientId,
) derives Schema

final case class RotateRefreshTokenRequest(
    oldHash:   RefreshTokenHash,
    newToken:  IssuedRefreshToken,
    rotatedAt: Instant,
) derives Schema

final case class RevokeRefreshTokenRequest(
    hash:               RefreshTokenHash,
    requestingClientId: ClientId,
) derives Schema

enum RotateRefreshTokenError derives CanEqual, Schema:
  case NotFound
  case Expired
  case Revoked
  case Replay
  case Internal(message: String)
