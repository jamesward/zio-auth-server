package com.jamesward.zioauthserver

import zio.*

import java.time.Instant
import java.util.UUID

/** A WebAuthn credential id, base64url. */
opaque type PasskeyCredentialId = String
object PasskeyCredentialId:
  def of(base64Url: String): PasskeyCredentialId           = base64Url
  extension (c: PasskeyCredentialId) def value: String     = c
  given CanEqual[PasskeyCredentialId, PasskeyCredentialId] = CanEqual.derived

/**
 * A registered passkey. `userHandle` is what the authenticator stores and returns on a discoverable sign-in (the
 * user id's 16 bytes, base64url); `publicKeyCose` is the COSE public key, base64url.
 */
final case class Passkey(
    credentialId:   PasskeyCredentialId,
    userId:         UserId,
    userHandle:     String,
    publicKeyCose:  String,
    signatureCount: Long,
    name:           String,
    createdAt:      Instant,
    lastUsedAt:     Option[Instant],
)

opaque type PasskeyCeremonyId = UUID
object PasskeyCeremonyId:
  def fresh(uuid: UUID): PasskeyCeremonyId               = uuid
  val mint: URIO[SecureRandomGen, PasskeyCeremonyId]     = ZIO.serviceWithZIO[SecureRandomGen](_.nextUUID)
  extension (i: PasskeyCeremonyId) def value: UUID       = i
  given CanEqual[PasskeyCeremonyId, PasskeyCeremonyId]   = CanEqual.derived

enum PasskeyCeremonyKind derives CanEqual:
  case Registration, Assertion

/**
 * A started registration or sign-in, holding the options the server sent (the challenge) until the browser answers.
 * Used once: [[PasskeyStore.takeCeremony]] removes it.
 */
final case class PasskeyCeremony(
    id:          PasskeyCeremonyId,
    kind:        PasskeyCeremonyKind,
    userId:      Option[UserId],
    requestJson: String,
    expiresAt:   Instant,
)

enum PasskeyError derives CanEqual:
  case DuplicateCredential
  case Internal(message: String)

trait PasskeyStore:
  def passkeys(userId: UserId): IO[StoreError, List[Passkey]]
  def findPasskey(id: PasskeyCredentialId): IO[StoreError, Option[Passkey]]
  def addPasskey(passkey: Passkey): IO[PasskeyError, Unit]
  def recordPasskeyUse(id: PasskeyCredentialId, signatureCount: Long, usedAt: Instant): IO[StoreError, Unit]

  /** Removes the user's passkey; `false` when the user has no passkey with that id. */
  def removePasskey(userId: UserId, id: PasskeyCredentialId): IO[StoreError, Boolean]

  def createCeremony(ceremony: PasskeyCeremony): IO[StoreError, Unit]

  /** Removes and returns the ceremony, atomically, if it hasn't expired at `now`. */
  def takeCeremony(id: PasskeyCeremonyId, now: Instant): IO[StoreError, Option[PasskeyCeremony]]
