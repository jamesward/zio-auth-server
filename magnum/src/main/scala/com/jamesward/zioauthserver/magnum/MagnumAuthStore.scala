package com.jamesward.zioauthserver.magnum

import com.augustnagro.magnum.*
import com.jamesward.zioauthserver.*
import zio.*

import java.time.Instant
import java.util.UUID
import javax.sql.DataSource

/** The user of a [[MagnumAuthStore]]: the `users` row. */
final case class AuthUser(id: UserId, email: Email, status: UserStatus, createdAt: Instant)

object AuthUser:
  /** No scopes beyond what clients ask for. An app with roles provides its own `AccountView[AuthUser]`. */
  given AccountView[AuthUser] with
    def id(user: AuthUser): UserId               = user.id
    def email(user: AuthUser): Email             = user.email
    def scopes(user: AuthUser): Set[OAuthScope] = Set.empty

/**
 * Every store trait on Postgres, in the schema [[AuthSchema]] migrates (default `auth`). Each call is one JDBC
 * transaction on a blocking thread (plain magnum, nothing kept in a FiberRef). Single-use rows are locked
 * (`select … for update`) or removed (`delete … returning`) in that transaction, so a link, code, grant, ceremony or
 * state is used once and a refresh token rotates once, however many requests race.
 *
 * Disabled users (`status = 'disabled'`) can't sign in, and their sessions aren't found.
 */
final class MagnumAuthStore(dataSource: DataSource, schema: String, signUp: SignUpPolicy)
    extends AuthStore[AuthUser], AccountStore[AuthUser], PasskeyStore, ConnectionStore:
  import MagnumAuthStore.*

  private val xa = Transactor(dataSource, SqlLogger.NoOp)

  private def table(name: String): SqlLiteral = SqlLiteral(s"$schema.$name")
  private val users           = table("users")
  private val challenges      = table("email_login_challenges")
  private val otpChallenges   = table("email_otp_challenges")
  private val sessions        = table("sessions")
  private val clients         = table("oauth_clients")
  private val grants          = table("authorization_grants")
  private val accessTokens    = table("access_tokens")
  private val refreshTokens   = table("refresh_tokens")
  private val emailChanges    = table("email_changes")
  private val passkeyTable    = table("passkeys")
  private val ceremonies      = table("passkey_ceremonies")
  private val connStates      = table("connection_states")
  private val connectionTable = table("connections")

  private def tx[A](f: DbTx ?=> A): IO[StoreError, A] =
    ZIO.attemptBlocking(xa.transact(f)).mapError(t => StoreError.Internal(message(t)))

  /** A transaction whose business failures are values, so the work before them (a counted attempt) still commits. */
  private def txEither[E, A](internal: String => E)(f: DbTx ?=> Either[E, A]): IO[E, A] =
    ZIO.attemptBlocking(xa.transact(f)).mapError(t => internal(message(t))).absolve

  // ── users ────────────────────────────────────────────────────────────────

  private val userCols = SqlLiteral("id, email, status, created_at")

  private def userById(id: UUID)(using DbCon): Option[AuthUser] =
    sql"select $userCols from $users where id = $id".query[UserRow].run().headOption.map(_.toDomain)

  private def userByEmail(email: Email)(using DbCon): Option[AuthUser] =
    sql"select $userCols from $users where email = ${email.value}".query[UserRow].run().headOption.map(_.toDomain)

  /** The active user with this address, or a new one if the policy allows; `None` otherwise. */
  private def signInUser(email: Email, now: Instant)(using DbCon): Option[AuthUser] =
    userByEmail(email) match
      case Some(u) => Option.when(u.status == UserStatus.Active)(u)
      case None if signUp.allowsNew(email) =>
        val id = UUID.randomUUID()
        // A concurrent first sign-in with the same address may win the insert; then read its row.
        sql"""insert into $users (id, email, status, created_at, updated_at)
              values ($id, ${email.value}, 'active', $now, $now) on conflict (email) do nothing""".update.run()
        userByEmail(email).filter(_.status == UserStatus.Active)
      case None => None

  private def insertSession(idHash: SessionIdHash, userId: UserId, csrf: CsrfTokenHash, expiresAt: Instant, now: Instant)(using DbCon): Unit =
    sql"""insert into $sessions (id_hash, user_id, csrf_hash, expires_at, last_seen_at, created_at)
          values (${idHash.bytes}, ${userId.value}, ${csrf.bytes}, $expiresAt, $now, $now)""".update.run(): Unit

  override def mayStartSignIn(email: Email): IO[StoreError, Boolean] =
    tx(userByEmail(email) match
      case Some(u) => u.status == UserStatus.Active
      case None    => signUp.allowsNew(email))

  def findUser(id: UserId): IO[StoreError, Option[AuthUser]] = tx(userById(id.value))

  // ── email sign-in and sessions ───────────────────────────────────────────

  def createChallenge(c: EmailLoginChallenge): IO[StoreError, Unit] =
    tx(sql"""insert into $challenges (id, email, token_hash, issued_at, expires_at, consumed_at)
             values (${c.id.value}, ${c.email.value}, ${c.tokenHash.bytes}, ${c.issuedAt}, ${c.expiresAt}, ${c.consumedAt})""".update.run()).unit

  def verifyAndStartSession(r: VerifyAndStartSessionRequest): IO[VerifyError, AuthUser] =
    Clock.instant.flatMap { now =>
      txEither(VerifyError.Internal(_)) {
        sql"""select id, email, token_hash, issued_at, expires_at, consumed_at from $challenges
              where token_hash = ${r.presentedTokenHash.bytes} for update""".query[ChallengeRow].run().headOption match
          case None      => Left(VerifyError.NotFound)
          case Some(row) =>
            EmailLoginChallenge.consume(row.toDomain, r.presentedTokenHash, now) match
              case Left(e)         => Left(verifyError(e))
              case Right(consumed) =>
                signInUser(consumed.email, now) match
                  // Unknown and sign-up closed (or disabled): as if there were no such link, and it stays unused.
                  case None       => Left(VerifyError.NotFound)
                  case Some(user) =>
                    sql"update $challenges set consumed_at = $now where id = ${row.id}".update.run()
                    insertSession(r.sessionIdHash, user.id, r.csrfHash, r.sessionExpiresAt, now)
                    Right(user)
      }
    }

  def createOtpChallenge(c: EmailOtpChallenge): IO[StoreError, Unit] =
    tx(sql"""insert into $otpChallenges (id, email, code_hash, issued_at, expires_at, consumed_at, attempts)
             values (${c.id.value}, ${c.email.value}, ${c.codeHash.bytes}, ${c.issuedAt}, ${c.expiresAt}, ${c.consumedAt}, ${c.attempts})""".update.run()).unit

  def verifyOtpAndStartSession(r: VerifyOtpAndStartSessionRequest): IO[VerifyOtpError, AuthUser] =
    Clock.instant.flatMap { now =>
      txEither(VerifyOtpError.Internal(_)) {
        sql"""select id, email, code_hash, issued_at, expires_at, consumed_at, attempts from $otpChallenges
              where email = ${r.email.value} order by issued_at desc limit 1 for update""".query[OtpRow].run().headOption match
          case None      => Left(VerifyOtpError.NotFound)
          case Some(row) =>
            EmailOtpChallenge.consume(row.toDomain, r.presentedCodeHash, now) match
              case Left(EmailOtpChallenge.ConsumeError.CodeMismatch) =>
                // Counted, and committed with the failure: five wrong codes exhaust the challenge.
                sql"update $otpChallenges set attempts = attempts + 1 where id = ${row.id}".update.run()
                Left(VerifyOtpError.CodeMismatch)
              case Left(e)                                           => Left(verifyOtpError(e))
              case Right(consumed)                                   =>
                signInUser(consumed.email, now) match
                  case None       => Left(VerifyOtpError.NotFound)
                  case Some(user) =>
                    sql"update $otpChallenges set consumed_at = $now where id = ${row.id}".update.run()
                    insertSession(r.sessionIdHash, user.id, r.csrfHash, r.sessionExpiresAt, now)
                    Right(user)
      }
    }

  def findSession(idHash: SessionIdHash): IO[StoreError, Option[(Session, AuthUser)]] =
    tx(
      sql"""select s.id_hash, s.user_id, s.csrf_hash, s.expires_at, s.last_seen_at, s.created_at,
                   u.id, u.email, u.status, u.created_at
            from $sessions s join $users u on u.id = s.user_id
            where s.id_hash = ${idHash.bytes} and u.status = 'active'""".query[(SessionRow, UserRow)].run().headOption
        .map((s, u) => (s.toDomain, u.toDomain))
    )

  def deleteSession(idHash: SessionIdHash): IO[StoreError, Unit] =
    tx(sql"delete from $sessions where id_hash = ${idHash.bytes}".update.run()).unit

  def startSession(userId: UserId, idHash: SessionIdHash, csrf: CsrfTokenHash, expiresAt: Instant): IO[StoreError, Option[AuthUser]] =
    Clock.instant.flatMap(now =>
      tx(userById(userId.value).filter(_.status == UserStatus.Active).map { user =>
        insertSession(idHash, user.id, csrf, expiresAt, now)
        user
      })
    )

  // ── email change ─────────────────────────────────────────────────────────

  def createEmailChange(c: EmailChangeChallenge): IO[StoreError, Unit] =
    tx(sql"""insert into $emailChanges (id, user_id, new_email, token_hash, issued_at, expires_at, consumed_at)
             values (${c.id.value}, ${c.userId.value}, ${c.newEmail.value}, ${c.tokenHash.bytes}, ${c.issuedAt}, ${c.expiresAt}, ${c.consumedAt})""".update.run()).unit

  def confirmEmailChange(tokenHash: MagicTokenHash, now: Instant): IO[EmailChangeError, AuthUser] =
    txEither(EmailChangeError.Internal(_)) {
      sql"""select id, user_id, new_email, consumed_at, expires_at from $emailChanges
            where token_hash = ${tokenHash.bytes} for update""".query[(UUID, UUID, String, Option[Instant], Instant)].run().headOption match
        case None                                       => Left(EmailChangeError.NotFound)
        case Some((_, _, _, Some(_), _))                => Left(EmailChangeError.AlreadyConsumed)
        case Some((_, _, _, None, exp)) if !now.isBefore(exp) => Left(EmailChangeError.Expired)
        case Some((id, userId, newEmail, None, _))      =>
          val email = must(Email.parse(newEmail), "email")
          userByEmail(email) match
            case Some(other) if !other.id.value.equals(userId) => Left(EmailChangeError.EmailTaken)
            case _                                        =>
              userById(userId) match
                case None       => Left(EmailChangeError.NotFound)
                case Some(user) =>
                  sql"update $users set email = ${email.value}, updated_at = $now where id = $userId".update.run()
                  sql"update $emailChanges set consumed_at = $now where id = $id".update.run()
                  Right(user.copy(email = email))
    }.catchSome {
      // Another user took the address between the check and the update.
      case EmailChangeError.Internal(m) if m.contains(UniqueViolation) => ZIO.fail(EmailChangeError.EmailTaken)
    }

  // ── OAuth clients, grants, tokens ────────────────────────────────────────

  def createClient(c: OAuthClient): IO[StoreError, Unit] =
    tx(sql"""insert into $clients (id, kind, profile, name, secret_hash, grants, scopes, registration, registered_at, created_at, redirect_uris)
             values (${c.id.value}, ${c.kind.asString}, ${c.profile.asString}, ${c.name}, ${c.secretHash.map(_.bytes)},
                     ${c.grants.map(_.asString).toList.sorted.mkString(" ")}, ${OAuthScopeSet.render(c.scopes)},
                     ${c.registration.asString}, ${c.registeredAt}, ${c.createdAt}, ${c.redirectUris.map(_.value).toList.sorted.mkString("\n")})
             on conflict (id) do nothing""".update.run()).unit

  def findClient(id: ClientId): IO[StoreError, Option[OAuthClient]] =
    tx(sql"""select id, kind, profile, name, secret_hash, grants, scopes, registration, registered_at, created_at, redirect_uris
             from $clients where id = ${id.value}""".query[ClientRow].run().headOption.map(_.toDomain))

  def createGrant(g: AuthorizationGrant): IO[StoreError, Unit] =
    tx(sql"""insert into $grants (code_hash, client_id, user_id, redirect_uri, scopes, resource, code_challenge, challenge_method, issued_at, expires_at, consumed_at)
             values (${g.codeHash.bytes}, ${g.clientId.value}, ${g.userId.value}, ${g.redirectUri.value}, ${OAuthScopeSet.render(g.scopes)},
                     ${g.resource.map(_.value)}, ${g.codeChallenge.value}, ${g.challengeMethod.asString}, ${g.issuedAt}, ${g.expiresAt}, ${g.consumedAt})""".update.run()).unit

  def consumeGrant(r: ExchangeCodeRequest): IO[ExchangeError, ConsumedGrant] =
    Clock.instant.flatMap { now =>
      txEither(ExchangeError.Internal(_)) {
        sql"""select code_hash, client_id, user_id, redirect_uri, scopes, resource, code_challenge, challenge_method, issued_at, expires_at, consumed_at
              from $grants where code_hash = ${r.presentedCodeHash.bytes} for update""".query[GrantRow].run().headOption match
          case None      => Left(ExchangeError.GrantNotFound)
          case Some(row) =>
            val grant = row.toDomain
            AuthorizationGrant.consume(grant, r.presentedClientId, r.presentedRedirectUri, r.presentedChallenge, now) match
              case Left(e)  => Left(exchangeError(e))
              case Right(_) =>
                userById(grant.userId.value).filter(_.status == UserStatus.Active) match
                  case None       => Left(ExchangeError.GrantNotFound)
                  case Some(user) =>
                    sql"update $grants set consumed_at = $now where code_hash = ${r.presentedCodeHash.bytes}".update.run()
                    Right(ConsumedGrant(grant.userId, summon[AccountView[AuthUser]].scopes(user), grant.scopes, grant.resource))
      }
    }

  def createAccessToken(t: IssuedAccessToken): IO[StoreError, Unit] =
    tx(sql"""insert into $accessTokens (hash, client_id, subject_kind, user_id, scopes, resource, issued_at, expires_at, revoked_at)
             values (${t.hash.bytes}, ${t.clientId.value}, ${t.subjectKind.asString}, ${t.userId.map(_.value)}, ${OAuthScopeSet.render(t.scopes)},
                     ${t.resource.map(_.value)}, ${t.issuedAt}, ${t.expiresAt}, ${t.revokedAt})""".update.run()).unit

  def findAccessToken(hash: AccessTokenHash): IO[StoreError, Option[IssuedAccessToken]] =
    tx(sql"""select hash, client_id, subject_kind, user_id, scopes, resource, issued_at, expires_at, revoked_at
             from $accessTokens where hash = ${hash.bytes}""".query[AccessRow].run().headOption.map(_.toDomain))

  def revokeAccessTokenIfOwned(r: RevokeAccessTokenRequest): IO[StoreError, Unit] =
    Clock.instant.flatMap(now =>
      tx(sql"""update $accessTokens set revoked_at = $now
               where hash = ${r.hash.bytes} and client_id = ${r.requestingClientId.value} and revoked_at is null""".update.run()).unit
    )

  private val refreshCols =
    SqlLiteral("hash, root_hash, parent_hash, client_id, user_id, scopes, resource, issued_at, expires_at, revoked_at, rotated_at, rotated_to_hash")

  private def insertRefresh(t: IssuedRefreshToken, onConflictNothing: Boolean)(using DbCon): Unit =
    val conflict = SqlLiteral(if onConflictNothing then "on conflict (hash) do nothing" else "")
    sql"""insert into $refreshTokens ($refreshCols)
          values (${t.hash.bytes}, ${t.rootHash.bytes}, ${t.parentHash.map(_.bytes)}, ${t.clientId.value}, ${t.userId.map(_.value)},
                  ${OAuthScopeSet.render(t.scopes)}, ${t.resource.map(_.value)}, ${t.issuedAt}, ${t.expiresAt}, ${t.revokedAt},
                  ${t.rotatedAt}, ${t.rotatedToHash.map(_.bytes)}) $conflict""".update.run(): Unit

  def createRefreshToken(t: IssuedRefreshToken): IO[StoreError, Unit] = tx(insertRefresh(t, onConflictNothing = true))

  def findRefreshToken(hash: RefreshTokenHash): IO[StoreError, Option[IssuedRefreshToken]] =
    tx(sql"select $refreshCols from $refreshTokens where hash = ${hash.bytes}".query[RefreshRow].run().headOption.map(_.toDomain))

  private def revokeChain(root: Array[Byte], now: Instant)(using DbCon): Unit =
    sql"update $refreshTokens set revoked_at = $now where root_hash = $root and revoked_at is null".update.run(): Unit

  def rotateRefreshToken(r: RotateRefreshTokenRequest): IO[RotateRefreshTokenError, Unit] =
    txEither(RotateRefreshTokenError.Internal(_)) {
      sql"select $refreshCols from $refreshTokens where hash = ${r.oldHash.bytes} for update".query[RefreshRow].run().headOption match
        case None                                                => Left(RotateRefreshTokenError.NotFound)
        case Some(old) if old.revokedAt.isDefined                => Left(RotateRefreshTokenError.Revoked)
        case Some(old) if !r.rotatedAt.isBefore(old.expiresAt)   => Left(RotateRefreshTokenError.Expired)
        case Some(old) if old.rotatedAt.isDefined                =>
          // A replay: committed with the failure, so the whole chain stays revoked.
          revokeChain(old.rootHash, r.rotatedAt)
          Left(RotateRefreshTokenError.Replay)
        case Some(_)                                             =>
          insertRefresh(r.newToken, onConflictNothing = false)
          sql"""update $refreshTokens set rotated_at = ${r.rotatedAt}, rotated_to_hash = ${r.newToken.hash.bytes}
                where hash = ${r.oldHash.bytes}""".update.run()
          Right(())
    }

  def revokeRefreshTokenIfOwned(r: RevokeRefreshTokenRequest): IO[StoreError, Unit] =
    Clock.instant.flatMap(now =>
      tx(
        sql"select $refreshCols from $refreshTokens where hash = ${r.hash.bytes} for update".query[RefreshRow].run().headOption match
          case Some(t) if t.clientId == r.requestingClientId.value && t.revokedAt.isEmpty => revokeChain(t.rootHash, now)
          // RFC 7009 2.2: a missing, foreign or already revoked token is not an error.
          case _                                                                         => ()
      )
    )

  // ── passkeys ─────────────────────────────────────────────────────────────

  private val passkeyCols =
    SqlLiteral("credential_id, user_id, user_handle, public_key_cose, signature_count, name, created_at, last_used_at")

  def passkeys(userId: UserId): IO[StoreError, List[Passkey]] =
    tx(sql"select $passkeyCols from $passkeyTable where user_id = ${userId.value} order by created_at"
      .query[PasskeyRow].run().map(_.toDomain).toList)

  def findPasskey(id: PasskeyCredentialId): IO[StoreError, Option[Passkey]] =
    tx(sql"select $passkeyCols from $passkeyTable where credential_id = ${id.value}".query[PasskeyRow].run().headOption.map(_.toDomain))

  def addPasskey(p: Passkey): IO[PasskeyError, Unit] =
    tx(sql"""insert into $passkeyTable ($passkeyCols)
             values (${p.credentialId.value}, ${p.userId.value}, ${p.userHandle}, ${p.publicKeyCose}, ${p.signatureCount},
                     ${p.name}, ${p.createdAt}, ${p.lastUsedAt})""".update.run()).unit.mapError {
      case StoreError.Internal(m) if m.contains(UniqueViolation) => PasskeyError.DuplicateCredential
      case StoreError.Internal(m)                                => PasskeyError.Internal(m)
    }

  def recordPasskeyUse(id: PasskeyCredentialId, signatureCount: Long, usedAt: Instant): IO[StoreError, Unit] =
    tx(sql"""update $passkeyTable set signature_count = $signatureCount, last_used_at = $usedAt
             where credential_id = ${id.value}""".update.run()).unit

  def removePasskey(userId: UserId, id: PasskeyCredentialId): IO[StoreError, Boolean] =
    tx(sql"delete from $passkeyTable where credential_id = ${id.value} and user_id = ${userId.value}".update.run() > 0)

  def createCeremony(c: PasskeyCeremony): IO[StoreError, Unit] =
    tx(sql"""insert into $ceremonies (id, kind, user_id, request_json, expires_at)
             values (${c.id.value}, ${c.kind.toString}, ${c.userId.map(_.value)}, ${c.requestJson}, ${c.expiresAt})""".update.run()).unit

  def takeCeremony(id: PasskeyCeremonyId, now: Instant): IO[StoreError, Option[PasskeyCeremony]] =
    tx(sql"delete from $ceremonies where id = ${id.value} returning id, kind, user_id, request_json, expires_at"
      .returning[(UUID, String, Option[UUID], String, Instant)].run().headOption.collect {
        case (i, kind, user, json, exp) if now.isBefore(exp) =>
          PasskeyCeremony(PasskeyCeremonyId.fresh(i), PasskeyCeremonyKind.valueOf(kind), user.map(UserId.fresh), json, exp)
      })

  // ── connections ──────────────────────────────────────────────────────────

  def createConnectionState(s: ConnectionState): IO[StoreError, Unit] =
    tx(sql"""insert into $connStates (state_hash, user_id, provider, code_verifier, return_to, expires_at)
             values (${s.stateHash}, ${s.userId.value}, ${s.provider}, ${s.codeVerifier}, ${s.returnTo}, ${s.expiresAt})""".update.run()).unit

  def takeConnectionState(stateHash: String, now: Instant): IO[StoreError, Option[ConnectionState]] =
    tx(sql"""delete from $connStates where state_hash = $stateHash
             returning state_hash, user_id, provider, code_verifier, return_to, expires_at"""
      .returning[(String, UUID, String, String, Option[String], Instant)].run().headOption.collect {
        case (h, u, p, v, r, exp) if now.isBefore(exp) => ConnectionState(h, UserId.fresh(u), p, v, r, exp)
      })

  def saveConnection(c: Connection): IO[StoreError, Unit] =
    tx(sql"""insert into $connectionTable (user_id, provider, subject, sealed_tokens, connected_at, updated_at)
             values (${c.userId.value}, ${c.provider}, ${c.subject}, ${c.sealedTokens}, ${c.connectedAt}, ${c.updatedAt})
             on conflict (user_id, provider) do update set subject = excluded.subject, sealed_tokens = excluded.sealed_tokens,
               connected_at = excluded.connected_at, updated_at = excluded.updated_at""".update.run()).unit

  def findConnection(userId: UserId, provider: String): IO[StoreError, Option[Connection]] =
    tx(sql"""select user_id, provider, subject, sealed_tokens, connected_at, updated_at from $connectionTable
             where user_id = ${userId.value} and provider = $provider"""
      .query[(UUID, String, String, String, Instant, Instant)].run().headOption.map((u, p, s, t, c, up) =>
        Connection(UserId.fresh(u), p, s, t, c, up)
      ))

  def deleteConnection(userId: UserId, provider: String): IO[StoreError, Boolean] =
    tx(sql"delete from $connectionTable where user_id = ${userId.value} and provider = $provider".update.run() > 0)

object MagnumAuthStore:

  /** The store on `schema` (migrate it first with [[AuthSchema.migrate]]). */
  def apply(dataSource: DataSource, signUp: SignUpPolicy, schema: String = AuthSchema.DefaultSchema): Either[String, MagnumAuthStore] =
    AuthSchema.validSchema(schema).map(s => new MagnumAuthStore(dataSource, s, signUp))

  type Stores = AuthStore[AuthUser] & AccountStore[AuthUser] & PasskeyStore & ConnectionStore

  /** Every store trait from one store, for a `DataSource` in the environment. */
  def layer(signUp: SignUpPolicy, schema: String = AuthSchema.DefaultSchema): ZLayer[DataSource, Throwable, Stores] =
    ZLayer.fromZIOEnvironment(
      for
        ds    <- ZIO.service[DataSource]
        store <- ZIO.fromEither(apply(ds, signUp, schema)).mapError(new IllegalArgumentException(_))
      yield ZEnvironment[AuthStore[AuthUser], AccountStore[AuthUser], PasskeyStore, ConnectionStore](store, store, store, store)
    )

  private val UniqueViolation = "SQLState 23505"

  /** The failure's messages down the cause chain, with any SQLState, for the error value. */
  private def message(t: Throwable): String =
    Iterator.iterate(t)(_.getCause).takeWhile(_ != null).take(5).map {
      case e: java.sql.SQLException => s"${e.getMessage} (SQLState ${e.getSQLState})"
      case e                        => Option(e.getMessage).getOrElse(e.getClass.getName)
    }.mkString(": ")

  private def must[E, A](result: Either[E, A], what: String): A =
    result.fold(e => throw new IllegalStateException(s"stored $what doesn't parse: $e"), identity)

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

  // Rows, read by position: each query selects the columns in field order.

  private final case class UserRow(id: UUID, email: String, status: String, createdAt: Instant) derives DbCodec:
    def toDomain: AuthUser =
      AuthUser(UserId.fresh(id), must(Email.parse(email), "email"), must(UserStatus.parse(status), "status"), createdAt)

  private final case class ChallengeRow(
      id: UUID, email: String, tokenHash: Array[Byte], issuedAt: Instant, expiresAt: Instant, consumedAt: Option[Instant],
  ) derives DbCodec:
    def toDomain: EmailLoginChallenge =
      EmailLoginChallenge(EmailLoginChallengeId.fresh(id), must(Email.parse(email), "email"), MagnumAuthStore.magicHash(tokenHash),
        issuedAt, expiresAt, consumedAt)

  private final case class OtpRow(
      id: UUID, email: String, codeHash: Array[Byte], issuedAt: Instant, expiresAt: Instant, consumedAt: Option[Instant], attempts: Int,
  ) derives DbCodec:
    def toDomain: EmailOtpChallenge =
      EmailOtpChallenge(EmailOtpChallengeId.fresh(id), must(Email.parse(email), "email"), OtpCodeHash.fromBytes(codeHash),
        issuedAt, expiresAt, consumedAt, attempts)

  private final case class SessionRow(
      idHash: Array[Byte], userId: UUID, csrfHash: Array[Byte], expiresAt: Instant, lastSeenAt: Instant, createdAt: Instant,
  ) derives DbCodec:
    def toDomain: Session =
      Session(SessionIdHash.fromBytes(idHash), UserId.fresh(userId), CsrfTokenHash.fromBytes(csrfHash), expiresAt, lastSeenAt, createdAt)

  private final case class ClientRow(
      id: String, kind: String, profile: String, name: String, secretHash: Option[Array[Byte]], grants: String, scopes: String,
      registration: String, registeredAt: Instant, createdAt: Instant, redirectUris: String,
  ) derives DbCodec:
    def toDomain: OAuthClient =
      OAuthClient(
        ClientId.of(id), must(ClientKind.parse(kind), "client kind"), must(ClientProfile.parse(profile), "client profile"), name,
        secretHash.map(ClientSecretHash.fromBytes), words(grants).map(g => must(GrantType.parse(g), "grant type")).toSet,
        OAuthScopeSet.parse(scopes), must(ClientRegistration.parse(registration), "registration"), registeredAt, createdAt,
        redirectUris.split('\n').filter(_.nonEmpty).map(u => must(RedirectUri.parse(u), "redirect uri")).toSet,
      )

  private final case class GrantRow(
      codeHash: Array[Byte], clientId: String, userId: UUID, redirectUri: String, scopes: String, resource: Option[String],
      codeChallenge: String, challengeMethod: String, issuedAt: Instant, expiresAt: Instant, consumedAt: Option[Instant],
  ) derives DbCodec:
    def toDomain: AuthorizationGrant =
      AuthorizationGrant(
        AuthorizationCodeHash.fromBytes(codeHash), ClientId.of(clientId), UserId.fresh(userId),
        must(RedirectUri.parse(redirectUri), "redirect uri"), OAuthScopeSet.parse(scopes), resource.map(resourceOf),
        CodeChallenge.of(codeChallenge), must(ChallengeMethod.parse(challengeMethod), "challenge method"), issuedAt, expiresAt,
        consumedAt,
      )

  private final case class AccessRow(
      hash: Array[Byte], clientId: String, subjectKind: String, userId: Option[UUID], scopes: String, resource: Option[String],
      issuedAt: Instant, expiresAt: Instant, revokedAt: Option[Instant],
  ) derives DbCodec:
    def toDomain: IssuedAccessToken =
      IssuedAccessToken(
        AccessTokenHash.fromBytes(hash), ClientId.of(clientId), must(SubjectKind.parse(subjectKind), "subject kind"),
        userId.map(UserId.fresh), OAuthScopeSet.parse(scopes), resource.map(resourceOf), issuedAt, expiresAt, revokedAt,
      )

  private final case class RefreshRow(
      hash: Array[Byte], rootHash: Array[Byte], parentHash: Option[Array[Byte]], clientId: String, userId: Option[UUID],
      scopes: String, resource: Option[String], issuedAt: Instant, expiresAt: Instant, revokedAt: Option[Instant],
      rotatedAt: Option[Instant], rotatedToHash: Option[Array[Byte]],
  ) derives DbCodec:
    def toDomain: IssuedRefreshToken =
      IssuedRefreshToken(
        RefreshTokenHash.fromBytes(hash), RefreshTokenHash.fromBytes(rootHash), parentHash.map(RefreshTokenHash.fromBytes),
        ClientId.of(clientId), userId.map(UserId.fresh), OAuthScopeSet.parse(scopes), resource.map(resourceOf), issuedAt,
        expiresAt, revokedAt, rotatedAt, rotatedToHash.map(RefreshTokenHash.fromBytes),
      )

  private final case class PasskeyRow(
      credentialId: String, userId: UUID, userHandle: String, publicKeyCose: String, signatureCount: Long, name: String,
      createdAt: Instant, lastUsedAt: Option[Instant],
  ) derives DbCodec:
    def toDomain: Passkey =
      Passkey(PasskeyCredentialId.of(credentialId), UserId.fresh(userId), userHandle, publicKeyCose, signatureCount, name,
        createdAt, lastUsedAt)

  private def magicHash(bytes: Array[Byte]): MagicTokenHash = MagicTokenHash.fromBytes(bytes)

  private def words(s: String): List[String] = s.split(' ').filter(_.nonEmpty).toList

  private def resourceOf(s: String): ResourceIndicator = must(ResourceIndicator.parse(s), "resource")
