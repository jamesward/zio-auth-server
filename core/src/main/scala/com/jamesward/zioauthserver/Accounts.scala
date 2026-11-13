package com.jamesward.zioauthserver

import zio.*
import zio.schema.*

import java.time.Instant
import java.util.UUID

/** Who may sign in with email. Applied by the store when a link or code is verified, and before one is sent. */
enum SignUpPolicy derives CanEqual:
  /** Any address; the first sign-in creates the user (toolbook). */
  case Open

  /** Only existing users. Signing in with an unknown address never creates or joins an account (the factory). */
  case ExistingUsersOnly

  /** Existing users, plus these addresses on their first sign-in. */
  case Allowlist(emails: Set[Email])

object SignUpPolicy:
  extension (p: SignUpPolicy)
    def allowsNew(email: Email): Boolean = p match
      case Open              => true
      case ExistingUsersOnly => false
      case Allowlist(emails) => emails.contains(email)

opaque type EmailChangeId = UUID
object EmailChangeId:
  def fresh(uuid: UUID): EmailChangeId                    = uuid
  val mint: URIO[SecureRandomGen, EmailChangeId]          = ZIO.serviceWithZIO[SecureRandomGen](_.nextUUID)
  extension (i: EmailChangeId) def value: UUID            = i
  given CanEqual[EmailChangeId, EmailChangeId]            = CanEqual.derived
  given Schema[EmailChangeId]                             = Schema[UUID].transform(fresh, _.value)

/** A pending change of a user's address: a link mailed to the new address confirms it. */
final case class EmailChangeChallenge(
    id:         EmailChangeId,
    userId:     UserId,
    newEmail:   Email,
    tokenHash:  MagicTokenHash,
    issuedAt:   Instant,
    expiresAt:  Instant,
    consumedAt: Option[Instant],
)

enum EmailChangeError derives CanEqual:
  case NotFound, AlreadyConsumed, Expired

  /** Another user has the new address. */
  case EmailTaken
  case Internal(message: String)

object EmailChangeError:
  def fromConsume(e: EmailLoginChallenge.ConsumeError): EmailChangeError = e match
    case EmailLoginChallenge.ConsumeError.NotFound        => NotFound
    case EmailLoginChallenge.ConsumeError.AlreadyConsumed => AlreadyConsumed
    case EmailLoginChallenge.ConsumeError.Expired         => Expired
    case EmailLoginChallenge.ConsumeError.TokenMismatch   => NotFound

/**
 * The account operations beyond email sign-in: sessions started by another method (a passkey), and changing the
 * address. A store for a single-owner app (the factory) implements this next to [[AuthStore]].
 */
trait AccountStore[U]:
  def findUser(id: UserId): IO[StoreError, Option[U]]

  /** Starts a session for an existing, active user. `None` when the user is unknown or disabled. */
  def startSession(
      userId:        UserId,
      sessionIdHash: SessionIdHash,
      csrfHash:      CsrfTokenHash,
      expiresAt:     Instant,
  ): IO[StoreError, Option[U]]

  def createEmailChange(challenge: EmailChangeChallenge): IO[StoreError, Unit]

  /** Consumes the challenge for `tokenHash` once and moves its user to the new address, atomically. */
  def confirmEmailChange(tokenHash: MagicTokenHash, now: Instant): IO[EmailChangeError, U]

/** Step-up: identity changes need a session that started recently, so a stolen old session can't make them. */
object StepUp:

  val defaultMaxAge: Duration = 10.minutes

  def isFresh(session: Session, now: Instant, maxAge: Duration = defaultMaxAge): Boolean =
    !session.createdAt.plus(java.time.Duration.ofMillis(maxAge.toMillis)).isBefore(now)

  /** Where to send the browser to sign in again: `/login?reauth=1` skips resuming the current session. */
  def reauthPath(returnTo: String): String =
    s"/login?reauth=1&return_to=${java.net.URLEncoder.encode(returnTo, "UTF-8")}"
