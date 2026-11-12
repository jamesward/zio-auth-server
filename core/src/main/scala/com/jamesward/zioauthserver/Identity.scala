package com.jamesward.zioauthserver

import zio.*
import zio.schema.*

import java.time.Instant
import java.util.UUID

opaque type UserId = UUID
object UserId:
  def fresh(uuid: UUID): UserId         = uuid
  extension (u: UserId) def value: UUID = u
  given CanEqual[UserId, UserId]        = CanEqual.derived
  given Schema[UserId]                  = Schema[UUID].transform(fresh, _.value)

opaque type Email = String
object Email:
  enum InvalidEmail derives CanEqual:
    case Empty, NoAtSign, MultipleAtSigns, EmptyLocalPart, EmptyDomain, ContainsWhitespace

  def parse(raw: String): Either[InvalidEmail, Email] =
    val trimmed = raw.trim.toLowerCase
    if trimmed.isEmpty then Left(InvalidEmail.Empty)
    else if trimmed.exists(_.isWhitespace) then Left(InvalidEmail.ContainsWhitespace)
    else
      // `split("@", -1)` keeps trailing empty strings; without `-1`,
      // `"alice@".split('@')` is `Array("alice")` and we'd misclassify
      // EmptyDomain as NoAtSign.
      val parts = trimmed.split("@", -1)
      if parts.length < 2 then Left(InvalidEmail.NoAtSign)
      else if parts.length > 2 then Left(InvalidEmail.MultipleAtSigns)
      else if parts(0).isEmpty then Left(InvalidEmail.EmptyLocalPart)
      else if parts(1).isEmpty then Left(InvalidEmail.EmptyDomain)
      else Right(trimmed)

  extension (e: Email) def value: String = e
  given CanEqual[Email, Email]           = CanEqual.derived
  given Schema[Email] =
    Schema[String].transformOrFail(
      s => parse(s).left.map(err => s"invalid email: $err"),
      e => Right(e.value),
    )

opaque type MagicToken = String
object MagicToken:
  def fromBase64Url(s: String): MagicToken = s
  extension (t: MagicToken) def value: String = t
  given CanEqual[MagicToken, MagicToken]      = CanEqual.derived
  given Schema[MagicToken]                    = Schema[String].transform(fromBase64Url, _.value)

opaque type MagicTokenHash = Array[Byte]
object MagicTokenHash:
  def fromBytes(bs: Array[Byte]): MagicTokenHash = bs
  def hash(tokenValue: String, pepperValue: String): MagicTokenHash =
    fromBytes(Crypto.hmacSha256(tokenValue, pepperValue))
  extension (h: MagicTokenHash) def bytes: Array[Byte] = h
  // Hashes are 32 raw bytes; the default Array[Byte] schema emits a JSON array
  // of ints (large + slow on the wire), so encode as base64url-no-pad instead.
  // The same applies to every *Hash schema below.
  given Schema[MagicTokenHash] =
    Schema[String].transformOrFail(
      s => Crypto.decodeB64Url(s).map(fromBytes),
      h => Right(Crypto.encodeB64Url(h.bytes)),
    )

opaque type EmailLoginChallengeId = UUID
object EmailLoginChallengeId:
  def fresh(uuid: UUID): EmailLoginChallengeId         = uuid
  val mint: URIO[SecureRandomGen, EmailLoginChallengeId] =
    ZIO.serviceWithZIO[SecureRandomGen](_.nextUUID)
  extension (i: EmailLoginChallengeId) def value: UUID = i
  given CanEqual[EmailLoginChallengeId, EmailLoginChallengeId] = CanEqual.derived
  given Schema[EmailLoginChallengeId]                  = Schema[UUID].transform(fresh, _.value)

// A one-time passcode: exactly six decimal digits, typed by hand into the
// login form. The magic link proves control of the mailbox by being clicked;
// an OTP proves the same thing by being copied out of it. Same challenge
// lifecycle, different delivery — see `EmailOtpChallenge`.
opaque type OtpCode = String
object OtpCode:
  enum InvalidOtpCode derives CanEqual:
    case Empty, NotDigits, WrongLength

  val length: Int = 6

  private val space: Long = 1_000_000L

  def parse(raw: String): Either[InvalidOtpCode, OtpCode] =
    // People paste the code out of the email with the spacing intact
    // ("123 456", "123-456"); strip separators before judging it.
    val cleaned = raw.filterNot(c => c.isWhitespace || c == '-')
    if cleaned.isEmpty then Left(InvalidOtpCode.Empty)
    else if !cleaned.forall(c => c >= '0' && c <= '9') then Left(InvalidOtpCode.NotDigits)
    else if cleaned.length != length then Left(InvalidOtpCode.WrongLength)
    else Right(cleaned)

  // Uniform over all 10^6 codes. Taking `random % 1_000_000` of a 32-bit draw
  // would make the low codes slightly likelier, so we reject draws above the
  // largest multiple of the code space and redraw instead.
  val mint: URIO[SecureRandomGen, OtpCode] =
    val bound = (1L << 32) / space * space
    val draw  =
      ZIO.serviceWithZIO[SecureRandomGen](_.nextBytes(4)).map { bs =>
        bs.foldLeft(0L)((acc, b) => (acc << 8) | (b & 0xffL))
      }
    draw.repeatUntil(_ < bound).map(v => f"${v % space}%06d")

  extension (c: OtpCode) def value: String = c
  given CanEqual[OtpCode, OtpCode]         = CanEqual.derived
  given Schema[OtpCode] =
    Schema[String].transformOrFail(
      s => parse(s).left.map(err => s"invalid otp code: $err"),
      c => Right(c.value),
    )

opaque type OtpCodeHash = Array[Byte]
object OtpCodeHash:
  def fromBytes(bs: Array[Byte]): OtpCodeHash = bs
  // The hash covers the address the code was sent to, not just the code, so a
  // code minted for one mailbox can never be replayed against another — even
  // if two challenges happen to draw the same six digits at the same time.
  def hash(email: Email, code: OtpCode, pepperValue: String): OtpCodeHash =
    // Inside this file both opaque types are transparently their underlying
    // `String`, which shadows their own `value` extension — hence the ascribed
    // locals rather than `email.value` / `code.value`.
    val e: String = email
    val c: String = code
    fromBytes(Crypto.hmacSha256(s"$e:$c", pepperValue))
  extension (h: OtpCodeHash) def bytes: Array[Byte] = h
  given Schema[OtpCodeHash] =
    Schema[String].transformOrFail(
      s => Crypto.decodeB64Url(s).map(fromBytes),
      h => Right(Crypto.encodeB64Url(h.bytes)),
    )

opaque type EmailOtpChallengeId = UUID
object EmailOtpChallengeId:
  def fresh(uuid: UUID): EmailOtpChallengeId         = uuid
  val mint: URIO[SecureRandomGen, EmailOtpChallengeId] =
    ZIO.serviceWithZIO[SecureRandomGen](_.nextUUID)
  extension (i: EmailOtpChallengeId) def value: UUID = i
  given CanEqual[EmailOtpChallengeId, EmailOtpChallengeId] = CanEqual.derived
  given Schema[EmailOtpChallengeId]                  = Schema[UUID].transform(fresh, _.value)

opaque type SessionId = String
object SessionId:
  def fromBase64Url(s: String): SessionId    = s
  val mint: URIO[SecureRandomGen, SessionId] =
    ZIO.serviceWithZIO[SecureRandomGen](_.nextBytes(32)).map(b => Crypto.encodeB64Url(b))
  extension (s: SessionId) def value: String = s
  given CanEqual[SessionId, SessionId]       = CanEqual.derived
  given Schema[SessionId]                    = Schema[String].transform(fromBase64Url, _.value)

opaque type SessionIdHash = Array[Byte]
object SessionIdHash:
  def fromBytes(bs: Array[Byte]): SessionIdHash = bs
  extension (h: SessionIdHash) def bytes: Array[Byte] = h
  given Schema[SessionIdHash] =
    Schema[String].transformOrFail(
      s => Crypto.decodeB64Url(s).map(fromBytes),
      h => Right(Crypto.encodeB64Url(h.bytes)),
    )

opaque type CsrfToken = String
object CsrfToken:
  def fromBase64Url(s: String): CsrfToken     = s
  val mint: URIO[SecureRandomGen, CsrfToken]  =
    ZIO.serviceWithZIO[SecureRandomGen](_.nextBytes(32)).map(b => Crypto.encodeB64Url(b))
  extension (c: CsrfToken) def value: String  = c
  given CanEqual[CsrfToken, CsrfToken]        = CanEqual.derived
  given Schema[CsrfToken]                     = Schema[String].transform(fromBase64Url, _.value)

opaque type CsrfTokenHash = Array[Byte]
object CsrfTokenHash:
  def fromBytes(bs: Array[Byte]): CsrfTokenHash = bs
  extension (h: CsrfTokenHash) def bytes: Array[Byte] = h
  given Schema[CsrfTokenHash] =
    Schema[String].transformOrFail(
      s => Crypto.decodeB64Url(s).map(fromBytes),
      h => Right(Crypto.encodeB64Url(h.bytes)),
    )

enum UserStatus derives CanEqual, Schema:
  case Active, Disabled

object UserStatus:
  def parse(s: String): Either[String, UserStatus] = s match
    case "active"   => Right(Active)
    case "disabled" => Right(Disabled)
    case other      => Left(s"unknown user status: $other")

  extension (us: UserStatus) def asString: String = us match
    case Active   => "active"
    case Disabled => "disabled"

final case class EmailLoginChallenge(
    id:         EmailLoginChallengeId,
    email:      Email,
    tokenHash:  MagicTokenHash,
    issuedAt:   Instant,
    expiresAt:  Instant,
    consumedAt: Option[Instant],
) derives Schema

object EmailLoginChallenge:
  enum ConsumeError derives CanEqual:
    case NotFound
    case AlreadyConsumed
    case Expired
    case TokenMismatch

  def consume(
      challenge:     EmailLoginChallenge,
      presentedHash: MagicTokenHash,
      now:           Instant,
  ): Either[ConsumeError, EmailLoginChallenge] =
    // Constant-time hash compare; `==` would early-exit and leak length.
    if !java.security.MessageDigest.isEqual(
         challenge.tokenHash.bytes,
         presentedHash.bytes,
       )
    then Left(ConsumeError.TokenMismatch)
    else if challenge.consumedAt.isDefined then Left(ConsumeError.AlreadyConsumed)
    else if !now.isBefore(challenge.expiresAt) then Left(ConsumeError.Expired)
    else Right(challenge.copy(consumedAt = Some(now)))

// The OTP counterpart of `EmailLoginChallenge`. Two extra facts the magic
// link doesn't need: the code is short enough to guess, so we count failed
// attempts and lock the challenge once they run out.
final case class EmailOtpChallenge(
    id:         EmailOtpChallengeId,
    email:      Email,
    codeHash:   OtpCodeHash,
    issuedAt:   Instant,
    expiresAt:  Instant,
    consumedAt: Option[Instant],
    attempts:   Int,
) derives Schema

object EmailOtpChallenge:
  // A 6-digit code has a 10^6 space; five tries within the (short) TTL leaves
  // a 1-in-200,000 guessing chance per challenge.
  val maxAttempts: Int = 5

  enum ConsumeError derives CanEqual:
    case NotFound
    case AlreadyConsumed
    case Expired
    case CodeMismatch
    case TooManyAttempts

  def consume(
      challenge:     EmailOtpChallenge,
      presentedHash: OtpCodeHash,
      now:           Instant,
  ): Either[ConsumeError, EmailOtpChallenge] =
    // The attempt budget is checked FIRST: unlike a magic-link token, a code
    // that keeps being guessed must stop being answerable at all, whatever
    // else is true of the challenge. After that the ordering mirrors
    // `EmailLoginChallenge.consume` — fail closed on a bad code before
    // revealing consumed/expired state.
    if challenge.attempts >= maxAttempts then Left(ConsumeError.TooManyAttempts)
    // Constant-time hash compare; `==` would early-exit and leak length.
    else if !java.security.MessageDigest.isEqual(
              challenge.codeHash.bytes,
              presentedHash.bytes,
            )
    then Left(ConsumeError.CodeMismatch)
    else if challenge.consumedAt.isDefined then Left(ConsumeError.AlreadyConsumed)
    else if !now.isBefore(challenge.expiresAt) then Left(ConsumeError.Expired)
    else Right(challenge.copy(consumedAt = Some(now)))

final case class Session(
    idHash:     SessionIdHash,
    userId:     UserId,
    csrfHash:   CsrfTokenHash,
    expiresAt:  Instant,
    lastSeenAt: Instant,
    createdAt:  Instant,
) derives Schema
