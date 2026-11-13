package com.jamesward.zioauthserver

import zio.*
import zio.http.*
import zio.json.*

import java.time.Instant

/** An upstream OAuth 2 provider, as an OAuth client of it (the authorization code flow with PKCE). */
final case class OAuthProvider(
    name:         String,
    authorizeUrl: String,
    tokenUrl:     String,
    clientId:     String,
    clientSecret: String,
    redirectUri:  String,
    scopes:       List[String] = Nil,
)

/** The provider's tokens, as stored (sealed) in a [[Connection]]. */
final case class ProviderTokens(
    accessToken:           String,
    refreshToken:          Option[String],
    expiresAt:             Option[Instant],
    refreshTokenExpiresAt: Option[Instant],
    scope:                 Option[String],
) derives JsonCodec

enum ConnectError derives CanEqual:
  /** No connection, or its refresh token lapsed: the user has to connect again. */
  case NotConnected

  /** The state is unknown, used or expired. */
  case InvalidState

  /** The provider account isn't one this app accepts (the factory accepts only the owner's GitHub user). */
  case SubjectNotAllowed(subject: String)

  /** The provider refused or failed (an error response, a network failure). */
  case Provider(message: String)
  case Internal(message: String)

/**
 * Links a user to an upstream account and keeps its tokens fresh. `subjectOf` asks the provider who the tokens belong
 * to (GitHub: the user id from `/user`); `allowSubject` decides whether that account may be connected. Tokens are
 * stored sealed with `sealer`, bound to the user and provider.
 */
final class OAuthConnector(
    provider:     OAuthProvider,
    sealer:       TokenSealer,
    subjectOf:    String => ZIO[Client, Throwable, String],
    allowSubject: String => Boolean,
    stateTtl:     Duration = 10.minutes,
    revoke:       Option[ProviderTokens => ZIO[Client, Throwable, Unit]] = None,
):
  import OAuthConnector.*

  /** The URL to send the user's browser to. */
  def start(userId: UserId, returnTo: Option[String]): ZIO[ConnectionStore & SecureRandomGen, ConnectError, URL] =
    for
      rng      <- ZIO.service[SecureRandomGen]
      state    <- rng.nextBytes(32).map(Crypto.encodeB64Url)
      verifier <- rng.nextBytes(32).map(Crypto.encodeB64Url)
      now      <- Clock.instant
      _        <- ZIO
                    .serviceWithZIO[ConnectionStore](
                      _.createConnectionState(
                        ConnectionState(
                          hashState(state),
                          userId,
                          provider.name,
                          verifier,
                          returnTo,
                          now.plus(java.time.Duration.ofMillis(stateTtl.toMillis)),
                        )
                      )
                    )
                    .mapError(internal)
      params    = QueryParams(
                    "response_type"         -> "code",
                    "client_id"             -> provider.clientId,
                    "redirect_uri"          -> provider.redirectUri,
                    "state"                 -> state,
                    "code_challenge"        -> Crypto.encodeB64Url(Crypto.sha256(verifier)),
                    "code_challenge_method" -> "S256",
                  ) ++ (if provider.scopes.isEmpty then QueryParams.empty else QueryParams("scope" -> provider.scopes.mkString(" ")))
      base     <- ZIO.fromEither(URL.decode(provider.authorizeUrl)).orElseFail(ConnectError.Internal("bad authorizeUrl"))
    yield base.addQueryParams(params)

  /** Finishes the flow at the redirect URI: exchanges the code, checks the account, stores the connection. */
  def callback(code: String, state: String): ZIO[ConnectionStore & Client, ConnectError, (Connection, Option[String])] =
    for
      now     <- Clock.instant
      taken   <- ZIO.serviceWithZIO[ConnectionStore](_.takeConnectionState(hashState(state), now)).mapError(internal)
      pending <- ZIO.fromOption(taken.filter(_.provider == provider.name)).orElseFail(ConnectError.InvalidState)
      tokens  <- tokenRequest(
                   "grant_type"    -> "authorization_code",
                   "code"          -> code,
                   "redirect_uri"  -> provider.redirectUri,
                   "code_verifier" -> pending.codeVerifier,
                 )
      subject <- subjectOf(tokens.accessToken).mapError(t => ConnectError.Provider(s"account lookup failed: ${t.getMessage}"))
      _       <- ZIO.unless(allowSubject(subject))(ZIO.fail(ConnectError.SubjectNotAllowed(subject)))
      prior   <- ZIO.serviceWithZIO[ConnectionStore](_.findConnection(pending.userId, provider.name)).mapError(internal)
      conn     = Connection(
                   pending.userId,
                   provider.name,
                   subject,
                   seal(pending.userId, tokens),
                   prior.fold(now)(_.connectedAt),
                   now,
                 )
      _       <- ZIO.serviceWithZIO[ConnectionStore](_.saveConnection(conn)).mapError(internal)
      _       <- ZIO.logInfo(s"${provider.name} connected for user ${pending.userId.value} (account $subject)")
    yield (conn, pending.returnTo)

  /** A current access token, refreshed (and the rotated tokens stored) when it is within a minute of expiring. */
  def accessToken(userId: UserId): ZIO[ConnectionStore & Client, ConnectError, String] =
    for
      now    <- Clock.instant
      conn   <- ZIO.serviceWithZIO[ConnectionStore](_.findConnection(userId, provider.name)).mapError(internal).someOrFail(ConnectError.NotConnected)
      tokens <- ZIO.fromEither(open(conn)).mapError(ConnectError.Internal(_))
      fresh  <- if tokens.expiresAt.forall(_.isAfter(now.plusSeconds(60))) then ZIO.succeed(tokens)
                else refresh(conn, tokens, now)
    yield fresh.accessToken

  /** Removes the connection, after asking the provider to revoke the tokens when `revoke` is set (best effort). */
  def disconnect(userId: UserId): ZIO[ConnectionStore & Client, ConnectError, Boolean] =
    for
      conn    <- ZIO.serviceWithZIO[ConnectionStore](_.findConnection(userId, provider.name)).mapError(internal)
      _       <- ZIO.foreachDiscard(conn.zip(revoke)) { (c, rev) =>
                   ZIO.fromEither(open(c)).flatMap(t => rev(t).either.flatMap {
                     case Left(t)  => ZIO.logWarning(s"${provider.name} token revocation failed: ${t.getMessage}")
                     case Right(_) => ZIO.unit
                   }).catchAll(m => ZIO.logWarning(s"${provider.name} tokens unreadable on disconnect: $m"))
                 }
      removed <- ZIO.serviceWithZIO[ConnectionStore](_.deleteConnection(userId, provider.name)).mapError(internal)
    yield removed

  private def refresh(conn: Connection, tokens: ProviderTokens, now: Instant): ZIO[ConnectionStore & Client, ConnectError, ProviderTokens] =
    for
      rt     <- ZIO.fromOption(tokens.refreshToken.filter(_ => tokens.refreshTokenExpiresAt.forall(_.isAfter(now))))
                  .orElseFail(ConnectError.NotConnected)
      next   <- tokenRequest("grant_type" -> "refresh_token", "refresh_token" -> rt).mapError {
                  // An `invalid_grant` means the refresh token is gone (revoked, lapsed, already rotated).
                  case ConnectError.Provider(m) if m.contains("invalid_grant") || m.contains("bad_refresh_token") =>
                    ConnectError.NotConnected
                  case other                                                                                        => other
                }
      kept    = next.copy(refreshToken = next.refreshToken.orElse(tokens.refreshToken))
      _      <- ZIO.serviceWithZIO[ConnectionStore](_.saveConnection(conn.copy(sealedTokens = seal(conn.userId, kept), updatedAt = now)))
                  .mapError(internal)
    yield kept

  private def tokenRequest(fields: (String, String)*): ZIO[Client, ConnectError, ProviderTokens] =
    val form = Form(
      (fields ++ Seq("client_id" -> provider.clientId, "client_secret" -> provider.clientSecret))
        .map((k, v) => FormField.simpleField(k, v))*
    )
    val effect =
      for
        url  <- ZIO.fromEither(URL.decode(provider.tokenUrl)).mapError(_ => new Exception("bad tokenUrl"))
        resp <- ZIO.serviceWithZIO[Client](
                  _.batched(Request.post(url, Body.fromURLEncodedForm(form)).addHeader(Header.Accept(MediaType.application.json)))
                )
        body <- resp.body.asString
        now  <- Clock.instant
      yield (resp.status, body, now)
    effect
      .mapError(t => ConnectError.Provider(s"token request failed: ${t.getMessage}"))
      .flatMap { (status, body, now) =>
        // GitHub answers errors with 200 and an `error` field.
        body.fromJson[TokenResponse] match
          case Right(t) if status.isSuccess && t.error.isEmpty && t.access_token.nonEmpty =>
            ZIO.succeed(t.toTokens(now))
          case Right(t)                                                                  =>
            ZIO.fail(ConnectError.Provider(s"${status.code} ${t.error.getOrElse("no access_token")}"))
          case Left(_)                                                                   =>
            ZIO.fail(ConnectError.Provider(s"${status.code} unreadable token response"))
      }

  private def associated(userId: UserId): String = s"${userId.value}:${provider.name}"

  private def seal(userId: UserId, tokens: ProviderTokens): String = sealer.seal(tokens.toJson, associated(userId))

  private def open(conn: Connection): Either[String, ProviderTokens] =
    sealer.open(conn.sealedTokens, associated(conn.userId)).flatMap(_.fromJson[ProviderTokens])

object OAuthConnector:

  private def internal(e: StoreError): ConnectError = e match
    case StoreError.Internal(m) => ConnectError.Internal(m)

  /** The stored form of a state: it's a bearer value until used, so only its hash is kept. */
  def hashState(state: String): String = Crypto.encodeB64Url(Crypto.sha256(state))

  private final case class TokenResponse(
      access_token:             Option[String] = None,
      refresh_token:            Option[String] = None,
      expires_in:               Option[Long] = None,
      refresh_token_expires_in: Option[Long] = None,
      scope:                    Option[String] = None,
      error:                    Option[String] = None,
  ) derives JsonDecoder:
    def toTokens(now: Instant): ProviderTokens =
      ProviderTokens(
        accessToken = access_token.getOrElse(""),
        refreshToken = refresh_token,
        expiresAt = expires_in.map(now.plusSeconds),
        refreshTokenExpiresAt = refresh_token_expires_in.map(now.plusSeconds),
        scope = scope,
      )

/** GitHub as a provider: a GitHub App's (or OAuth App's) user authorization, the account id from `/user`. */
object GitHub:

  def provider(clientId: String, clientSecret: String, redirectUri: String, name: String = "github"): OAuthProvider =
    OAuthProvider(
      name = name,
      authorizeUrl = "https://github.com/login/oauth/authorize",
      tokenUrl = "https://github.com/login/oauth/access_token",
      clientId = clientId,
      clientSecret = clientSecret,
      redirectUri = redirectUri,
    )

  private final case class GitHubUser(id: Long) derives JsonDecoder

  /** The numeric GitHub user id, which, unlike the login, never changes. */
  def userId(apiBase: String = "https://api.github.com")(accessToken: String): ZIO[Client, Throwable, String] =
    for
      url  <- ZIO.fromEither(URL.decode(s"${apiBase.stripSuffix("/")}/user"))
      resp <- ZIO.serviceWithZIO[Client](
                _.batched(
                  Request
                    .get(url)
                    .addHeader(Header.Authorization.Bearer(accessToken))
                    .addHeader(Header.Accept(MediaType.application.json))
                    .addHeader("User-Agent", "zio-auth-server")
                )
              )
      body <- resp.body.asString
      _    <- ZIO.unless(resp.status.isSuccess)(ZIO.fail(new Exception(s"GitHub /user answered ${resp.status.code}")))
      user <- ZIO.fromEither(body.fromJson[GitHubUser]).mapError(e => new Exception(s"GitHub /user: $e"))
    yield user.id.toString

  /** Revokes the user's grant for the app (`DELETE /applications/{client_id}/grant`). */
  def revokeGrant(clientId: String, clientSecret: String, apiBase: String = "https://api.github.com")(
      tokens: ProviderTokens
  ): ZIO[Client, Throwable, Unit] =
    for
      url  <- ZIO.fromEither(URL.decode(s"${apiBase.stripSuffix("/")}/applications/$clientId/grant"))
      resp <- ZIO.serviceWithZIO[Client](
                _.batched(
                  Request(method = Method.DELETE, url = url, body = Body.fromString(s"""{"access_token":${tokens.accessToken.toJson}}"""))
                    .addHeader(Header.Authorization.Basic(clientId, clientSecret))
                    .addHeader(Header.Accept(MediaType.application.json))
                    .addHeader("User-Agent", "zio-auth-server")
                )
              )
      _    <- ZIO.unless(resp.status.isSuccess)(ZIO.fail(new Exception(s"GitHub grant revocation answered ${resp.status.code}")))
    yield ()

/**
 * The provider's redirect URI: `GET /connect/<provider>/callback`. On success it redirects to the flow's `returnTo`
 * (when [[AuthServerConfig.safeReturnTo]] allows it) or answers a short page.
 */
final class ConnectionRoutes(cfg: AuthServerConfig, connector: OAuthConnector, providerName: String):

  val routes: Routes[ConnectionStore & Client, Response] =
    Routes(Method.GET / "connect" / providerName / "callback" -> handler(callback))

  private def callback(req: Request): URIO[ConnectionStore & Client, Response] =
    val q = req.url.queryParams
    (q.queryParam("code"), q.queryParam("state")) match
      case (Some(code), Some(state)) =>
        connector.callback(code, state).either.flatMap {
          case Right((_, returnTo)) =>
            ZIO.succeed(returnTo.flatMap(cfg.safeReturnTo) match
              case Some(target) => Response.status(Status.SeeOther).addHeader(Header.Location(URL.decode(target).toOption.get))
              case None         => Response.text(s"$providerName connected. You can close this window."))
          case Left(e)              =>
            ZIO.logWarning(s"$providerName connection failed: $e").as(Response.text(message(e)).status(Status.BadRequest))
        }
      case _                         =>
        // The provider sends `error` when the user declined.
        ZIO.succeed(Response.text(s"$providerName connection not completed: ${q.queryParam("error").getOrElse("missing code")}").status(Status.BadRequest))

  private def message(e: ConnectError): String = e match
    case ConnectError.InvalidState         => "This connection link expired or was already used. Start again."
    case ConnectError.SubjectNotAllowed(_) => s"That $providerName account can't be connected here."
    case ConnectError.NotConnected         => "Not connected."
    case ConnectError.Provider(_)          => s"$providerName refused the connection. Start again."
    case ConnectError.Internal(_)          => "Something went wrong. Start again."
