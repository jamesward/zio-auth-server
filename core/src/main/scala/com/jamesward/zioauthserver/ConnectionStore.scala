package com.jamesward.zioauthserver

import zio.*

import java.time.Instant

/**
 * A user's link to an upstream OAuth provider (the owner's GitHub account). `subject` is the provider's id for the
 * account; `sealedTokens` are the tokens, encrypted with a [[TokenSealer]], so a database dump doesn't reveal them.
 */
final case class Connection(
    userId:       UserId,
    provider:     String,
    subject:      String,
    sealedTokens: String,
    connectedAt:  Instant,
    updatedAt:    Instant,
)

/** A started connection flow: the `state` parameter (stored as its hash) and the PKCE verifier. */
final case class ConnectionState(
    stateHash:    String,
    userId:       UserId,
    provider:     String,
    codeVerifier: String,
    returnTo:     Option[String],
    expiresAt:    Instant,
)

trait ConnectionStore:
  def createConnectionState(state: ConnectionState): IO[StoreError, Unit]

  /** Removes and returns the state, atomically, if it hasn't expired at `now`. */
  def takeConnectionState(stateHash: String, now: Instant): IO[StoreError, Option[ConnectionState]]

  /** Adds the connection, or replaces the user's existing one for the provider. */
  def saveConnection(connection: Connection): IO[StoreError, Unit]

  def findConnection(userId: UserId, provider: String): IO[StoreError, Option[Connection]]

  /** `false` when there was none. */
  def deleteConnection(userId: UserId, provider: String): IO[StoreError, Boolean]
