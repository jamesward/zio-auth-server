package com.jamesward.zioauthserver.testkit

import com.jamesward.zioauthserver.*
import zio.*

import java.time.Instant

/**
 * An [[AuthStore]] in a `Ref`, for tests and local development. Every operation is one `Ref.modify`, so the
 * consume-once and rotate-once rules hold under concurrent requests, the same as a database store's transactions.
 *
 * `newUser` makes the application's user on first sign-in with an address (when `signUp` allows it), and `withEmail`
 * gives a user a new address. It also implements [[AccountStore]], [[PasskeyStore]] and [[ConnectionStore]].
 */
final class InMemoryAuthStore[U] private (
    state:     Ref[InMemoryAuthStore.State[U]],
    newUser:   (UserId, Email, Instant) => U,
    withEmail: (U, Email) => U,
    signUp:    SignUpPolicy,
)(using view: AccountView[U])
    extends AuthStore[U], AccountStore[U], PasskeyStore, ConnectionStore:
  import InMemoryAuthStore.*

  override def mayStartSignIn(email: Email): IO[StoreError, Boolean] =
    state.get.map(s => s.usersByEmail.contains(email) || signUp.allowsNew(email))

  // Email sign-in and browser sessions

  def createChallenge(challenge: EmailLoginChallenge): IO[StoreError, Unit] =
    state.update(s => s.copy(challenges = s.challenges.updated(key(challenge.tokenHash.bytes), challenge)))

  def verifyAndStartSession(request: VerifyAndStartSessionRequest): IO[VerifyError, U] =
    for
      now  <- Clock.instant
      uuid <- newUserId
      user <- state.modify { s =>
                s.challenges.get(key(request.presentedTokenHash.bytes)) match
                  case None            => (Left(VerifyError.NotFound), s)
                  case Some(challenge) =>
                    EmailLoginChallenge.consume(challenge, request.presentedTokenHash, now) match
                      case Left(e)         => (Left(verifyError(e)), s)
                      case Right(consumed) =>
                        s.userFor(consumed.email, signUp, newUser(UserId.fresh(uuid), consumed.email, now)) match
                          // Unknown, and sign-up closed: as if there were no such link.
                          case None             => (Left(VerifyError.NotFound), s)
                          case Some((user, s1)) =>
                            val s2 = s1.copy(challenges = s1.challenges.updated(key(consumed.tokenHash.bytes), consumed))
                            (Right(user), s2.startSession(request.sessionIdHash, request.csrfHash, request.sessionExpiresAt, view.id(user), now))
              }.absolve
    yield user

  def createOtpChallenge(challenge: EmailOtpChallenge): IO[StoreError, Unit] =
    state.update(s => s.copy(otpChallenges = s.otpChallenges.updated(challenge.id, challenge)))

  def verifyOtpAndStartSession(request: VerifyOtpAndStartSessionRequest): IO[VerifyOtpError, U] =
    for
      now  <- Clock.instant
      uuid <- newUserId
      user <- state.modify { s =>
                s.otpChallenges.values.filter(_.email == request.email).maxByOption(_.issuedAt) match
                  case None            => (Left(VerifyOtpError.NotFound), s)
                  case Some(challenge) =>
                    EmailOtpChallenge.consume(challenge, request.presentedCodeHash, now) match
                      case Left(EmailOtpChallenge.ConsumeError.CodeMismatch) =>
                        // A wrong code counts against the challenge, so `maxAttempts` guesses exhaust it.
                        val counted = challenge.copy(attempts = challenge.attempts + 1)
                        (Left(VerifyOtpError.CodeMismatch), s.copy(otpChallenges = s.otpChallenges.updated(counted.id, counted)))
                      case Left(e)                                           => (Left(verifyOtpError(e)), s)
                      case Right(consumed)                                   =>
                        s.userFor(consumed.email, signUp, newUser(UserId.fresh(uuid), consumed.email, now)) match
                          case None             => (Left(VerifyOtpError.NotFound), s)
                          case Some((user, s1)) =>
                            val s2 = s1.copy(otpChallenges = s1.otpChallenges.updated(consumed.id, consumed))
                            (Right(user), s2.startSession(request.sessionIdHash, request.csrfHash, request.sessionExpiresAt, view.id(user), now))
              }.absolve
    yield user

  def findSession(idHash: SessionIdHash): IO[StoreError, Option[(Session, U)]] =
    state.get.map(s => s.sessions.get(key(idHash.bytes)).flatMap(session => s.usersById.get(session.userId).map((session, _))))

  def deleteSession(idHash: SessionIdHash): IO[StoreError, Unit] =
    state.update(s => s.copy(sessions = s.sessions - key(idHash.bytes)))

  // OAuth clients, codes and tokens

  def createClient(client: OAuthClient): IO[StoreError, Unit] =
    state.update(s => s.copy(clients = s.clients.updated(client.id, client)))

  def findClient(id: ClientId): IO[StoreError, Option[OAuthClient]] =
    state.get.map(_.clients.get(id))

  def createGrant(grant: AuthorizationGrant): IO[StoreError, Unit] =
    state.update(s => s.copy(grants = s.grants.updated(key(grant.codeHash.bytes), grant)))

  def consumeGrant(request: ExchangeCodeRequest): IO[ExchangeError, ConsumedGrant] =
    for
      now      <- Clock.instant
      consumed <- state.modify { s =>
                    s.grants.get(key(request.presentedCodeHash.bytes)) match
                      case None        => (Left(ExchangeError.GrantNotFound), s)
                      case Some(grant) =>
                        AuthorizationGrant.consume(
                          grant,
                          request.presentedClientId,
                          request.presentedRedirectUri,
                          request.presentedChallenge,
                          now,
                        ) match
                          case Left(e)      => (Left(exchangeError(e)), s)
                          case Right(grant) =>
                            s.usersById.get(grant.userId) match
                              case None       => (Left(ExchangeError.Internal("grant's user is missing")), s)
                              case Some(user) =>
                                val result = ConsumedGrant(grant.userId, view.scopes(user), grant.scopes, grant.resource)
                                (Right(result), s.copy(grants = s.grants.updated(key(grant.codeHash.bytes), grant)))
                  }.absolve
    yield consumed

  def createAccessToken(token: IssuedAccessToken): IO[StoreError, Unit] =
    state.update(s => s.copy(accessTokens = s.accessTokens.updated(key(token.hash.bytes), token)))

  def findAccessToken(hash: AccessTokenHash): IO[StoreError, Option[IssuedAccessToken]] =
    state.get.map(_.accessTokens.get(key(hash.bytes)))

  def revokeAccessTokenIfOwned(request: RevokeAccessTokenRequest): IO[StoreError, Unit] =
    Clock.instant.flatMap { now =>
      state.update { s =>
        s.accessTokens.get(key(request.hash.bytes)) match
          case Some(t) if t.clientId == request.requestingClientId && t.revokedAt.isEmpty =>
            s.copy(accessTokens = s.accessTokens.updated(key(t.hash.bytes), t.copy(revokedAt = Some(now))))
          case _                                                                          => s
      }
    }

  def createRefreshToken(token: IssuedRefreshToken): IO[StoreError, Unit] =
    // Like the database store's `on conflict do nothing`: a retried create keeps the first row.
    state.update(s =>
      if s.refreshTokens.contains(key(token.hash.bytes)) then s
      else s.copy(refreshTokens = s.refreshTokens.updated(key(token.hash.bytes), token))
    )

  def findRefreshToken(hash: RefreshTokenHash): IO[StoreError, Option[IssuedRefreshToken]] =
    state.get.map(_.refreshTokens.get(key(hash.bytes)))

  def rotateRefreshToken(request: RotateRefreshTokenRequest): IO[RotateRefreshTokenError, Unit] =
    state.modify { s =>
      s.refreshTokens.get(key(request.oldHash.bytes)) match
        case None                                             => (Left(RotateRefreshTokenError.NotFound), s)
        case Some(old) if old.revokedAt.isDefined             => (Left(RotateRefreshTokenError.Revoked), s)
        case Some(old) if !request.rotatedAt.isBefore(old.expiresAt) => (Left(RotateRefreshTokenError.Expired), s)
        case Some(old) if old.rotatedAt.isDefined             =>
          (Left(RotateRefreshTokenError.Replay), s.revokeChain(old.rootHash, request.rotatedAt))
        case Some(old)                                        =>
          val rotated = old.copy(rotatedAt = Some(request.rotatedAt), rotatedToHash = Some(request.newToken.hash))
          val tokens  = s.refreshTokens
            .updated(key(request.newToken.hash.bytes), request.newToken)
            .updated(key(old.hash.bytes), rotated)
          (Right(()), s.copy(refreshTokens = tokens))
    }.absolve

  def revokeRefreshTokenIfOwned(request: RevokeRefreshTokenRequest): IO[StoreError, Unit] =
    Clock.instant.flatMap { now =>
      state.update { s =>
        s.refreshTokens.get(key(request.hash.bytes)) match
          case Some(t) if t.clientId == request.requestingClientId && t.revokedAt.isEmpty => s.revokeChain(t.rootHash, now)
          // RFC 7009 2.2: a missing, foreign or already revoked token is not an error.
          case _                                                                          => s
      }
    }

  // Accounts

  def findUser(id: UserId): IO[StoreError, Option[U]] = state.get.map(_.usersById.get(id))

  def startSession(
      userId:        UserId,
      sessionIdHash: SessionIdHash,
      csrfHash:      CsrfTokenHash,
      expiresAt:     Instant,
  ): IO[StoreError, Option[U]] =
    Clock.instant.flatMap { now =>
      state.modify { s =>
        s.usersById.get(userId) match
          case None       => (None, s)
          case Some(user) => (Some(user), s.startSession(sessionIdHash, csrfHash, expiresAt, userId, now))
      }
    }

  def createEmailChange(challenge: EmailChangeChallenge): IO[StoreError, Unit] =
    state.update(s => s.copy(emailChanges = s.emailChanges.updated(key(challenge.tokenHash.bytes), challenge)))

  def confirmEmailChange(tokenHash: MagicTokenHash, now: Instant): IO[EmailChangeError, U] =
    state.modify { s =>
      s.emailChanges.get(key(tokenHash.bytes)) match
        case None                                     => (Left(EmailChangeError.NotFound), s)
        case Some(ch) if ch.consumedAt.isDefined      => (Left(EmailChangeError.AlreadyConsumed), s)
        case Some(ch) if !now.isBefore(ch.expiresAt)  => (Left(EmailChangeError.Expired), s)
        case Some(ch)                                 =>
          (s.usersById.get(ch.userId), s.usersByEmail.get(ch.newEmail)) match
            case (None, _)                                     => (Left(EmailChangeError.NotFound), s)
            case (Some(_), Some(other)) if other != ch.userId  => (Left(EmailChangeError.EmailTaken), s)
            case (Some(user), _)                               =>
              val moved = withEmail(user, ch.newEmail)
              (
                Right(moved),
                s.copy(
                  usersById = s.usersById.updated(ch.userId, moved),
                  usersByEmail = (s.usersByEmail - view.email(user)).updated(ch.newEmail, ch.userId),
                  emailChanges = s.emailChanges.updated(key(tokenHash.bytes), ch.copy(consumedAt = Some(now))),
                ),
              )
    }.absolve

  // Passkeys

  def passkeys(userId: UserId): IO[StoreError, List[Passkey]] =
    state.get.map(_.passkeys.values.filter(_.userId == userId).toList.sortBy(_.createdAt))

  def findPasskey(id: PasskeyCredentialId): IO[StoreError, Option[Passkey]] = state.get.map(_.passkeys.get(id.value))

  def addPasskey(passkey: Passkey): IO[PasskeyError, Unit] =
    state.modify { s =>
      if s.passkeys.contains(passkey.credentialId.value) then (Left(PasskeyError.DuplicateCredential), s)
      else (Right(()), s.copy(passkeys = s.passkeys.updated(passkey.credentialId.value, passkey)))
    }.absolve

  def recordPasskeyUse(id: PasskeyCredentialId, signatureCount: Long, usedAt: Instant): IO[StoreError, Unit] =
    state.update(s =>
      s.copy(passkeys = s.passkeys.updatedWith(id.value)(_.map(_.copy(signatureCount = signatureCount, lastUsedAt = Some(usedAt)))))
    )

  def removePasskey(userId: UserId, id: PasskeyCredentialId): IO[StoreError, Boolean] =
    state.modify { s =>
      s.passkeys.get(id.value) match
        case Some(p) if p.userId == userId => (true, s.copy(passkeys = s.passkeys - id.value))
        case _                             => (false, s)
    }

  def createCeremony(ceremony: PasskeyCeremony): IO[StoreError, Unit] =
    state.update(s => s.copy(ceremonies = s.ceremonies.updated(ceremony.id, ceremony)))

  def takeCeremony(id: PasskeyCeremonyId, now: Instant): IO[StoreError, Option[PasskeyCeremony]] =
    state.modify(s => (s.ceremonies.get(id).filter(c => now.isBefore(c.expiresAt)), s.copy(ceremonies = s.ceremonies - id)))

  // Connections

  def createConnectionState(st: ConnectionState): IO[StoreError, Unit] =
    state.update(s => s.copy(connectionStates = s.connectionStates.updated(st.stateHash, st)))

  def takeConnectionState(stateHash: String, now: Instant): IO[StoreError, Option[ConnectionState]] =
    state.modify(s =>
      (s.connectionStates.get(stateHash).filter(c => now.isBefore(c.expiresAt)), s.copy(connectionStates = s.connectionStates - stateHash))
    )

  def saveConnection(connection: Connection): IO[StoreError, Unit] =
    state.update(s => s.copy(connections = s.connections.updated((connection.userId, connection.provider), connection)))

  def findConnection(userId: UserId, provider: String): IO[StoreError, Option[Connection]] =
    state.get.map(_.connections.get((userId, provider)))

  def deleteConnection(userId: UserId, provider: String): IO[StoreError, Boolean] =
    state.modify(s => (s.connections.contains((userId, provider)), s.copy(connections = s.connections - ((userId, provider)))))

  /** The users signed up so far. */
  def users: UIO[List[U]] = state.get.map(_.usersById.values.toList)

  /** Adds or replaces a user, for seeding a test or a dev run. */
  def putUser(user: U): UIO[Unit] =
    state.update(s =>
      s.copy(
        usersById = s.usersById.updated(view.id(user), user),
        usersByEmail = s.usersByEmail.updated(view.email(user), view.id(user)),
      )
    )

  /** Adds a session row directly, for a dev login with a fixed session ([[DevSessions.fixed]]). */
  def putSession(session: Session): UIO[Unit] =
    state.update(s => s.copy(sessions = s.sessions.updated(key(session.idHash.bytes), session)))

object InMemoryAuthStore:

  def make[U](
      newUser:   (UserId, Email, Instant) => U,
      withEmail: (U, Email) => U,
      signUp:    SignUpPolicy = SignUpPolicy.Open,
  )(using AccountView[U]): UIO[InMemoryAuthStore[U]] =
    Ref.make(State.empty[U]).map(new InMemoryAuthStore(_, newUser, withEmail, signUp))

  type Stores[U] = AuthStore[U] & AccountStore[U] & PasskeyStore & ConnectionStore

  /** Provides every store trait, and the [[InMemoryAuthStore]] itself so a test can seed and inspect it. */
  def layer[U: Tag](
      newUser:   (UserId, Email, Instant) => U,
      withEmail: (U, Email) => U,
      signUp:    SignUpPolicy = SignUpPolicy.Open,
  )(using AccountView[U]): ULayer[Stores[U] & InMemoryAuthStore[U]] =
    ZLayer.fromZIOEnvironment(
      make(newUser, withEmail, signUp).map(s =>
        ZEnvironment[AuthStore[U], AccountStore[U], PasskeyStore, ConnectionStore, InMemoryAuthStore[U]](s, s, s, s, s)
      )
    )

  // Not `Random`: under zio-test every test's TestRandom starts from the same seed, so tests sharing a store would
  // mint the same user id.
  private val newUserId: UIO[java.util.UUID] = ZIO.succeed(java.util.UUID.randomUUID())

  // Hashes are byte arrays, which compare by reference; a Chunk compares by content.
  private type Key = Chunk[Byte]
  private def key(bytes: Array[Byte]): Key = Chunk.fromArray(bytes)

  private final case class State[U](
      usersById:     Map[UserId, U],
      usersByEmail:  Map[Email, UserId],
      challenges:    Map[Key, EmailLoginChallenge],
      otpChallenges: Map[EmailOtpChallengeId, EmailOtpChallenge],
      sessions:      Map[Key, Session],
      clients:       Map[ClientId, OAuthClient],
      grants:        Map[Key, AuthorizationGrant],
      accessTokens:  Map[Key, IssuedAccessToken],
      refreshTokens: Map[Key, IssuedRefreshToken],
      emailChanges:  Map[Key, EmailChangeChallenge],
      passkeys:      Map[String, Passkey],
      ceremonies:    Map[PasskeyCeremonyId, PasskeyCeremony],
      connectionStates: Map[String, ConnectionState],
      connections:   Map[(UserId, String), Connection],
  ):
    /** The user with this address, or `created` added as a new one if `signUp` allows it. */
    def userFor(email: Email, signUp: SignUpPolicy, created: => U)(using view: AccountView[U]): Option[(U, State[U])] =
      usersByEmail.get(email).flatMap(usersById.get) match
        case Some(user)                     => Some((user, this))
        case None if signUp.allowsNew(email) =>
          val user = created
          Some(
            (
              user,
              copy(
                usersById = usersById.updated(view.id(user), user),
                usersByEmail = usersByEmail.updated(email, view.id(user)),
              ),
            )
          )
        case None                           => None

    def startSession(
        idHash:    SessionIdHash,
        csrfHash:  CsrfTokenHash,
        expiresAt: Instant,
        userId:    UserId,
        now:       Instant,
    ): State[U] =
      val session = Session(idHash, userId, csrfHash, expiresAt, lastSeenAt = now, createdAt = now)
      copy(sessions = sessions.updated(key(idHash.bytes), session))

    def revokeChain(root: RefreshTokenHash, now: Instant): State[U] =
      val rootKey = key(root.bytes)
      copy(refreshTokens = refreshTokens.map { (k, t) =>
        if key(t.rootHash.bytes) == rootKey && t.revokedAt.isEmpty then k -> t.copy(revokedAt = Some(now)) else k -> t
      })

  private object State:
    def empty[U]: State[U] =
      State(
        Map.empty, Map.empty, Map.empty, Map.empty, Map.empty, Map.empty, Map.empty, Map.empty, Map.empty, Map.empty, Map.empty,
        Map.empty, Map.empty, Map.empty,
      )

  private def verifyError(e: EmailLoginChallenge.ConsumeError): VerifyError = e match
    case EmailLoginChallenge.ConsumeError.NotFound        => VerifyError.NotFound
    case EmailLoginChallenge.ConsumeError.AlreadyConsumed => VerifyError.AlreadyConsumed
    case EmailLoginChallenge.ConsumeError.Expired         => VerifyError.Expired
    case EmailLoginChallenge.ConsumeError.TokenMismatch   => VerifyError.TokenMismatch

  private def verifyOtpError(e: EmailOtpChallenge.ConsumeError): VerifyOtpError = e match
    case EmailOtpChallenge.ConsumeError.NotFound        => VerifyOtpError.NotFound
    case EmailOtpChallenge.ConsumeError.AlreadyConsumed => VerifyOtpError.AlreadyConsumed
    case EmailOtpChallenge.ConsumeError.Expired         => VerifyOtpError.Expired
    case EmailOtpChallenge.ConsumeError.CodeMismatch    => VerifyOtpError.CodeMismatch
    case EmailOtpChallenge.ConsumeError.TooManyAttempts => VerifyOtpError.TooManyAttempts

  private def exchangeError(e: AuthorizationGrant.ConsumeError): ExchangeError = e match
    case AuthorizationGrant.ConsumeError.AlreadyConsumed     => ExchangeError.AlreadyConsumed
    case AuthorizationGrant.ConsumeError.Expired             => ExchangeError.Expired
    case AuthorizationGrant.ConsumeError.ClientMismatch      => ExchangeError.ClientMismatch
    case AuthorizationGrant.ConsumeError.RedirectUriMismatch => ExchangeError.RedirectUriMismatch
    case AuthorizationGrant.ConsumeError.PkceMismatch        => ExchangeError.PkceMismatch
    case AuthorizationGrant.ConsumeError.PkceVerifierInvalid => ExchangeError.PkceMismatch
