package com.jamesward.zioauthserver.testkit

import com.jamesward.zioauthserver.*
// `zio.*` would import the package `zio.test`, which clashes with zio-test's `test`.
import zio.{test as _, *}
import zio.test.*

import java.time.Instant

/**
 * The behavior every store implementation must have: single-use links, codes, grants, ceremonies and states; atomic
 * refresh-token rotation with replay revoking the chain; revocation only by the owning client; the sign-up policy;
 * email changes; passkeys and connections. Run it from the implementation's tests:
 *
 * {{{
 * object MyStoreSpec extends ZIOSpecDefault:
 *   def spec = AuthStoreContract.spec[DataSource, AuthUser]("MyStore", policy => MyStore.layer(policy))
 *     .provideShared(postgres)
 * }}}
 *
 * `make` builds a store with the given [[SignUpPolicy]]. A database store may share its data between the stores it
 * makes: every test uses its own random addresses and ids.
 */
object AuthStoreContract:

  type Stores[U] = AuthStore[U] & AccountStore[U] & PasskeyStore & ConnectionStore

  private val pepper = "contract-pepper"

  def spec[R, U: Tag](name: String, make: SignUpPolicy => ZLayer[R, Throwable, Stores[U]])(using
      view: AccountView[U]
  ): Spec[R, Throwable] =
    val ops = Ops[U]()
    import ops.*

    def open(test: ZIO[Stores[U], Any, TestResult]): ZIO[R, Throwable, TestResult] =
      test.mapError(asThrowable).provideSomeLayer[R](make(SignUpPolicy.Open))

    suite(s"$name: AuthStore contract")(
      suite("email sign-in")(
        test("a magic link signs up a new address once, then signs in the same user") {
          open(
            for
              email <- freshEmail
              u1    <- signIn(email)
              u2    <- signIn(email)
            yield assertTrue(view.email(u1) == email, view.id(u1) == view.id(u2))
          )
        },
        test("a magic link works once, and not after it expires") {
          open(
            for
              email   <- freshEmail
              now     <- Clock.instant
              link    <- createLink(email, now.plusSeconds(600))
              first   <- verifyLink(link).either
              second  <- verifyLink(link).either
              old     <- createLink(email, now.minusSeconds(1))
              expired <- verifyLink(old).either
              unknown <- verifyLink(MagicTokenHash.fromBytes(randomBytes())).either
            yield assertTrue(
              first.isRight,
              second == Left(VerifyError.AlreadyConsumed),
              expired == Left(VerifyError.Expired),
              unknown == Left(VerifyError.NotFound),
            )
          )
        },
        test("a wrong one-time code counts, and the fifth wrong one locks the code") {
          open(
            for
              email   <- freshEmail
              now     <- Clock.instant
              right    = OtpCodeHash.hash(email, OtpCode.parse("123456").toOption.get, pepper)
              wrong    = OtpCodeHash.hash(email, OtpCode.parse("654321").toOption.get, pepper)
              id      <- ZIO.succeed(EmailOtpChallengeId.fresh(java.util.UUID.randomUUID()))
              _       <- store(_.createOtpChallenge(EmailOtpChallenge(id, email, right, now, now.plusSeconds(600), None, 0)))
              misses  <- ZIO.foreach(1 to EmailOtpChallenge.maxAttempts)(_ => verifyCode(email, wrong).either)
              locked  <- verifyCode(email, right).either
            yield assertTrue(
              misses.forall(_ == Left(VerifyOtpError.CodeMismatch)),
              locked == Left(VerifyOtpError.TooManyAttempts),
            )
          )
        },
        test("the right one-time code signs in once") {
          open(
            for
              email  <- freshEmail
              now    <- Clock.instant
              right   = OtpCodeHash.hash(email, OtpCode.parse("246810").toOption.get, pepper)
              id      = EmailOtpChallengeId.fresh(java.util.UUID.randomUUID())
              _      <- store(_.createOtpChallenge(EmailOtpChallenge(id, email, right, now, now.plusSeconds(600), None, 0)))
              first  <- verifyCode(email, right).either
              second <- verifyCode(email, right).either
            yield assertTrue(first.map(view.email) == Right(email), second == Left(VerifyOtpError.AlreadyConsumed))
          )
        },
        test("sessions are found until deleted") {
          open(
            for
              email   <- freshEmail
              (u, sh) <- signInWithSession(email)
              found   <- store(_.findSession(sh))
              _       <- store(_.deleteSession(sh))
              gone    <- store(_.findSession(sh))
            yield assertTrue(found.map(p => view.id(p._2)) == Some(view.id(u)), gone.isEmpty)
          )
        },
      ),
      suite("sign-up policy")(
        test("ExistingUsersOnly never creates an account, and doesn't offer to send a link") {
          for
            email   <- freshEmail
            result  <- (for
                         may    <- store(_.mayStartSignIn(email))
                         now    <- Clock.instant
                         link   <- createLink(email, now.plusSeconds(600))
                         signed <- verifyLink(link).either
                       yield (may, signed)).provideSomeLayer[R](make(SignUpPolicy.ExistingUsersOnly))
          yield assertTrue(!result._1, result._2 == Left(VerifyError.NotFound))
        },
        test("Allowlist admits the listed address, then treats it as an existing user") {
          for
            allowed  <- freshEmail
            stranger <- freshEmail
            result   <- (for
                          mayAllowed  <- store(_.mayStartSignIn(allowed))
                          mayStranger <- store(_.mayStartSignIn(stranger))
                          user        <- signIn(allowed)
                          now         <- Clock.instant
                          link        <- createLink(stranger, now.plusSeconds(600))
                          refused     <- verifyLink(link).either
                        yield (mayAllowed, mayStranger, view.email(user), refused))
                          .provideSomeLayer[R](make(SignUpPolicy.Allowlist(Set(allowed))))
            existing <- store(_.mayStartSignIn(allowed)).provideSomeLayer[R](make(SignUpPolicy.ExistingUsersOnly))
          yield assertTrue(
            result._1,
            !result._2,
            result._3 == allowed,
            result._4 == Left(VerifyError.NotFound),
          ) && (if existing then assertTrue(existing) else assertCompletes) // a fresh in-memory store forgets the user
        },
      ),
      suite("authorization codes")(
        test("a grant is consumed once, and failed checks don't consume it") {
          open(
            for
              user         <- freshEmail.flatMap(signIn)
              client       <- freshClient
              grant        <- createGrant(client, view.id(user))
              wrongClient  <- consume(grant, clientId = Some(ClientId.of("someone-else"))).either
              wrongPkce    <- consume(grant, challenge = "not-the-challenge").either
              first        <- consume(grant).either
              second       <- consume(grant).either
            yield assertTrue(
              wrongClient == Left(ExchangeError.ClientMismatch),
              wrongPkce == Left(ExchangeError.PkceMismatch),
              first.map(_.userId) == Right(view.id(user)),
              first.map(_.userScopes) == Right(view.scopes(user)),
              second == Left(ExchangeError.AlreadyConsumed),
            )
          )
        },
        test("of 20 concurrent exchanges of one code, exactly one succeeds") {
          open(
            for
              user    <- freshEmail.flatMap(signIn)
              client  <- freshClient
              grant   <- createGrant(client, view.id(user))
              results <- ZIO.foreachPar(1 to 20)(_ => consume(grant).either)
            yield assertTrue(results.count(_.isRight) == 1)
          )
        },
      ),
      suite("tokens")(
        test("only the owning client revokes an access token") {
          open(
            for
              user    <- freshEmail.flatMap(signIn)
              client  <- freshClient
              now     <- Clock.instant
              token    = IssuedAccessToken(AccessTokenHash.fromBytes(randomBytes()), client.id, SubjectKind.User, Some(view.id(user)),
                           Set(OAuthScope.of("mcp")), None, now, now.plusSeconds(3600), None)
              _       <- store(_.createAccessToken(token))
              _       <- store(_.revokeAccessTokenIfOwned(RevokeAccessTokenRequest(token.hash, ClientId.of("someone-else"))))
              still   <- store(_.findAccessToken(token.hash))
              _       <- store(_.revokeAccessTokenIfOwned(RevokeAccessTokenRequest(token.hash, client.id)))
              revoked <- store(_.findAccessToken(token.hash))
            yield assertTrue(still.exists(_.isActive(now)), revoked.exists(!_.isActive(now)))
          )
        },
        test("a refresh token rotates once; replaying it revokes the whole chain") {
          open(
            for
              user   <- freshEmail.flatMap(signIn)
              client <- freshClient
              now    <- Clock.instant
              root    = refreshToken(client, view.id(user), now, None)
              _      <- store(_.createRefreshToken(root))
              next    = refreshToken(client, view.id(user), now, Some(root))
              first  <- rotate(RotateRefreshTokenRequest(root.hash, next, now)).either
              other   = refreshToken(client, view.id(user), now, Some(root))
              replay <- rotate(RotateRefreshTokenRequest(root.hash, other, now)).either
              nextNow <- store(_.findRefreshToken(next.hash))
            yield assertTrue(
              first.isRight,
              replay == Left(RotateRefreshTokenError.Replay),
              nextNow.exists(_.revokedAt.isDefined),
            )
          )
        },
        test("of 10 concurrent rotations of one refresh token, exactly one succeeds") {
          open(
            for
              user    <- freshEmail.flatMap(signIn)
              client  <- freshClient
              now     <- Clock.instant
              root     = refreshToken(client, view.id(user), now, None)
              _       <- store(_.createRefreshToken(root))
              results <- ZIO.foreachPar(1 to 10)(_ =>
                           rotate(RotateRefreshTokenRequest(root.hash, refreshToken(client, view.id(user), now, Some(root)), now)).either
                         )
            yield assertTrue(results.count(_.isRight) == 1)
          )
        },
        test("revoking a refresh token revokes its chain, only for the owning client") {
          open(
            for
              user    <- freshEmail.flatMap(signIn)
              client  <- freshClient
              now     <- Clock.instant
              root     = refreshToken(client, view.id(user), now, None)
              _       <- store(_.createRefreshToken(root))
              next     = refreshToken(client, view.id(user), now, Some(root))
              _       <- rotate(RotateRefreshTokenRequest(root.hash, next, now))
              _       <- store(_.revokeRefreshTokenIfOwned(RevokeRefreshTokenRequest(next.hash, ClientId.of("someone-else"))))
              still   <- store(_.findRefreshToken(next.hash))
              _       <- store(_.revokeRefreshTokenIfOwned(RevokeRefreshTokenRequest(next.hash, client.id)))
              revoked <- store(_.findRefreshToken(next.hash))
            yield assertTrue(still.exists(_.revokedAt.isEmpty), revoked.exists(_.revokedAt.isDefined))
          )
        },
      ),
      suite("accounts")(
        test("a session starts for an existing user, not for an unknown one") {
          open(
            for
              user    <- freshEmail.flatMap(signIn)
              now     <- Clock.instant
              sh       = SessionIdHash.fromBytes(randomBytes())
              started <- account(_.startSession(view.id(user), sh, CsrfTokenHash.fromBytes(randomBytes()), now.plusSeconds(3600)))
              found   <- store(_.findSession(sh))
              nobody  <- account(_.startSession(UserId.fresh(java.util.UUID.randomUUID()), SessionIdHash.fromBytes(randomBytes()),
                           CsrfTokenHash.fromBytes(randomBytes()), now.plusSeconds(3600)))
            yield assertTrue(started.map(view.id) == Some(view.id(user)), found.isDefined, nobody.isEmpty)
          )
        },
        test("an email change moves the user once, and not onto another user's address") {
          open(
            for
              user     <- freshEmail.flatMap(signIn)
              taken    <- freshEmail.flatMap(signIn)
              newEmail <- freshEmail
              now      <- Clock.instant
              ok        = MagicTokenHash.fromBytes(randomBytes())
              _        <- account(_.createEmailChange(EmailChangeChallenge(EmailChangeId.fresh(java.util.UUID.randomUUID()),
                            view.id(user), newEmail, ok, now, now.plusSeconds(600), None)))
              moved    <- account(_.confirmEmailChange(ok, now)).either
              again    <- account(_.confirmEmailChange(ok, now)).either
              clash     = MagicTokenHash.fromBytes(randomBytes())
              _        <- account(_.createEmailChange(EmailChangeChallenge(EmailChangeId.fresh(java.util.UUID.randomUUID()),
                            view.id(user), view.email(taken), clash, now, now.plusSeconds(600), None)))
              refused  <- account(_.confirmEmailChange(clash, now)).either
              reloaded <- account(_.findUser(view.id(user)))
            yield assertTrue(
              moved.map(view.email) == Right(newEmail),
              again == Left(EmailChangeError.AlreadyConsumed),
              refused == Left(EmailChangeError.EmailTaken),
              reloaded.map(view.email) == Some(newEmail),
            )
          )
        },
      ),
      suite("passkeys")(
        test("passkeys are added once, listed, used, and removed only by their user") {
          open(
            for
              user    <- freshEmail.flatMap(signIn)
              other   <- freshEmail.flatMap(signIn)
              now     <- Clock.instant
              pk       = passkey(view.id(user), now)
              _       <- passkeyStore(_.addPasskey(pk))
              dup     <- passkeyStore(_.addPasskey(pk)).either
              listed  <- passkeyStore(_.passkeys(view.id(user)))
              _       <- passkeyStore(_.recordPasskeyUse(pk.credentialId, 7, now))
              used    <- passkeyStore(_.findPasskey(pk.credentialId))
              byOther <- passkeyStore(_.removePasskey(view.id(other), pk.credentialId))
              byOwner <- passkeyStore(_.removePasskey(view.id(user), pk.credentialId))
              gone    <- passkeyStore(_.findPasskey(pk.credentialId))
            yield assertTrue(
              dup == Left(PasskeyError.DuplicateCredential),
              listed.map(_.credentialId) == List(pk.credentialId),
              used.map(_.signatureCount) == Some(7L),
              used.flatMap(_.lastUsedAt).isDefined,
              !byOther,
              byOwner,
              gone.isEmpty,
            )
          )
        },
        test("a ceremony is taken once, and not after it expires") {
          open(
            for
              now     <- Clock.instant
              live     = PasskeyCeremony(PasskeyCeremonyId.fresh(java.util.UUID.randomUUID()), PasskeyCeremonyKind.Assertion, None, "{}", now.plusSeconds(300))
              old      = PasskeyCeremony(PasskeyCeremonyId.fresh(java.util.UUID.randomUUID()), PasskeyCeremonyKind.Assertion, None, "{}", now.minusSeconds(1))
              _       <- passkeyStore(_.createCeremony(live))
              _       <- passkeyStore(_.createCeremony(old))
              first   <- passkeyStore(_.takeCeremony(live.id, now))
              second  <- passkeyStore(_.takeCeremony(live.id, now))
              expired <- passkeyStore(_.takeCeremony(old.id, now))
            yield assertTrue(first.map(_.id) == Some(live.id), second.isEmpty, expired.isEmpty)
          )
        },
      ),
      suite("connections")(
        test("a connection state is taken once, and not after it expires") {
          open(
            for
              user    <- freshEmail.flatMap(signIn)
              now     <- Clock.instant
              live     = ConnectionState(randomText(), view.id(user), "github", "verifier", Some("/"), now.plusSeconds(300))
              old      = ConnectionState(randomText(), view.id(user), "github", "verifier", None, now.minusSeconds(1))
              _       <- connections(_.createConnectionState(live))
              _       <- connections(_.createConnectionState(old))
              first   <- connections(_.takeConnectionState(live.stateHash, now))
              second  <- connections(_.takeConnectionState(live.stateHash, now))
              expired <- connections(_.takeConnectionState(old.stateHash, now))
            yield assertTrue(first.map(_.stateHash) == Some(live.stateHash), first.map(_.codeVerifier) == Some(live.codeVerifier), second.isEmpty, expired.isEmpty)
          )
        },
        test("a connection is saved, replaced, found and deleted per user and provider") {
          open(
            for
              user    <- freshEmail.flatMap(signIn)
              now     <- Clock.instant
              c1       = Connection(view.id(user), "github", "42", "v1.first", now, now)
              _       <- connections(_.saveConnection(c1))
              c2       = c1.copy(sealedTokens = "v1.second", updatedAt = now.plusSeconds(1))
              _       <- connections(_.saveConnection(c2))
              found   <- connections(_.findConnection(view.id(user), "github"))
              other   <- connections(_.findConnection(view.id(user), "gitlab"))
              deleted <- connections(_.deleteConnection(view.id(user), "github"))
              again   <- connections(_.deleteConnection(view.id(user), "github"))
            yield assertTrue(found.map(_.sealedTokens) == Some("v1.second"), other.isEmpty, deleted, !again)
          )
        },
      ),
    ) @@ TestAspect.withLiveClock @@ TestAspect.withLiveRandom

  private final class Ops[U: Tag](using view: AccountView[U]):
    def store[A](f: AuthStore[U] => IO[Any, A]): ZIO[AuthStore[U], Throwable, A] =
      ZIO.serviceWithZIO[AuthStore[U]](f).mapError(asThrowable)
    def rotate(request: RotateRefreshTokenRequest): ZIO[AuthStore[U], RotateRefreshTokenError, Unit] =
      ZIO.serviceWithZIO[AuthStore[U]](_.rotateRefreshToken(request))
    def account[A, E](f: AccountStore[U] => IO[E, A]): ZIO[AccountStore[U], E, A] = ZIO.serviceWithZIO[AccountStore[U]](f)
    def passkeyStore[A, E](f: PasskeyStore => IO[E, A]): ZIO[PasskeyStore, E, A]  = ZIO.serviceWithZIO[PasskeyStore](f)
    def connections[A](f: ConnectionStore => IO[StoreError, A]): ZIO[ConnectionStore, Throwable, A] =
      ZIO.serviceWithZIO[ConnectionStore](f).mapError(asThrowable)

    val freshEmail: UIO[Email] = ZIO.succeed(Email.parse(s"${java.util.UUID.randomUUID()}@example.com").toOption.get)

    def createLink(email: Email, expiresAt: Instant): ZIO[AuthStore[U], Throwable, MagicTokenHash] =
      for
        now  <- Clock.instant
        hash  = MagicTokenHash.fromBytes(randomBytes())
        _    <- store(_.createChallenge(
                  EmailLoginChallenge(EmailLoginChallengeId.fresh(java.util.UUID.randomUUID()), email, hash, now, expiresAt, None)
                ))
      yield hash

    def verifyLink(hash: MagicTokenHash): ZIO[AuthStore[U], VerifyError, U] =
      Clock.instant.flatMap(now =>
        ZIO.serviceWithZIO[AuthStore[U]](_.verifyAndStartSession(VerifyAndStartSessionRequest(
          hash, SessionIdHash.fromBytes(randomBytes()), CsrfTokenHash.fromBytes(randomBytes()), now.plusSeconds(3600)
        )))
      )

    def verifyCode(email: Email, hash: OtpCodeHash): ZIO[AuthStore[U], VerifyOtpError, U] =
      Clock.instant.flatMap(now =>
        ZIO.serviceWithZIO[AuthStore[U]](_.verifyOtpAndStartSession(VerifyOtpAndStartSessionRequest(
          email, hash, SessionIdHash.fromBytes(randomBytes()), CsrfTokenHash.fromBytes(randomBytes()), now.plusSeconds(3600)
        )))
      )

    def signIn(email: Email): ZIO[AuthStore[U], Throwable, U] = signInWithSession(email).map(_._1)

    def signInWithSession(email: Email): ZIO[AuthStore[U], Throwable, (U, SessionIdHash)] =
      for
        now  <- Clock.instant
        link <- createLink(email, now.plusSeconds(600))
        sh    = SessionIdHash.fromBytes(randomBytes())
        user <- ZIO.serviceWithZIO[AuthStore[U]](_.verifyAndStartSession(VerifyAndStartSessionRequest(
                  link, sh, CsrfTokenHash.fromBytes(randomBytes()), now.plusSeconds(3600)
                ))).mapError(e => new AssertionError(s"sign-in failed: $e"))
      yield (user, sh)

    val freshClient: ZIO[AuthStore[U], Throwable, OAuthClient] =
      for
        now    <- Clock.instant
        client  = OAuthClient(
                    ClientId.of(s"client-${java.util.UUID.randomUUID()}"), ClientKind.Public, ClientProfile.Mcp, "Contract client",
                    None, Set(GrantType.AuthorizationCode, GrantType.RefreshToken), Set(OAuthScope.of("mcp")),
                    ClientRegistration.Dynamic, now, now, Set(RedirectUri.parse("http://127.0.0.1:9999/cb").toOption.get),
                  )
        _      <- store(_.createClient(client))
      yield client

    private val challengeValue = "CONTRACT-CHALLENGE"

    def createGrant(client: OAuthClient, userId: UserId): ZIO[AuthStore[U], Throwable, AuthorizationGrant] =
      for
        now  <- Clock.instant
        grant = AuthorizationGrant(
                  AuthorizationCodeHash.fromBytes(randomBytes()), client.id, userId, client.redirectUris.head,
                  Set(OAuthScope.of("mcp")), None, CodeChallenge.of(challengeValue), ChallengeMethod.S256, now,
                  now.plusSeconds(60), None,
                )
        _    <- store(_.createGrant(grant))
      yield grant

    def consume(
        grant:     AuthorizationGrant,
        clientId:  Option[ClientId] = None,
        challenge: String = challengeValue,
    ): ZIO[AuthStore[U], ExchangeError, ConsumedGrant] =
      ZIO.serviceWithZIO[AuthStore[U]](_.consumeGrant(ExchangeCodeRequest(
        grant.codeHash, clientId.getOrElse(grant.clientId), grant.redirectUri, challenge
      )))

    def refreshToken(client: OAuthClient, userId: UserId, now: Instant, parent: Option[IssuedRefreshToken]): IssuedRefreshToken =
      val hash = RefreshTokenHash.fromBytes(randomBytes())
      IssuedRefreshToken(
        hash, parent.fold(hash)(_.rootHash), parent.map(_.hash), client.id, Some(userId), Set(OAuthScope.of("mcp")), None,
        now, now.plusSeconds(3600), None, None, None,
      )

    def passkey(userId: UserId, now: Instant): Passkey =
      Passkey(PasskeyCredentialId.of(randomText()), userId, randomText(), randomText(), 0, "Test key", now, None)

  private def randomBytes(): Array[Byte] =
    val b = Array.ofDim[Byte](32)
    java.util.concurrent.ThreadLocalRandom.current().nextBytes(b)
    b

  private def randomText(): String = Crypto.encodeB64Url(randomBytes())

  private def asThrowable(e: Any): Throwable = e match
    case t: Throwable => t
    case other        => new AssertionError(s"store failed: $other")
