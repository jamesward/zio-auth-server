package com.jamesward.zioauthserver

import zio.*
import zio.http.*
import zio.json.*

import java.time.Instant

/**
 * The OAuth 2.1 authorization server: RFC 8414 metadata, JWKS, authorization code with PKCE, refresh-token rotation
 * with replay detection, RFC 7662 introspection, RFC 7009 revocation, RFC 7591 dynamic client registration and Client
 * ID Metadata Documents.
 */
final class OAuthRoutes[R, U: Tag](cfg: AuthServerConfig, gate: AuthorizeGate[R, U], pages: Pages[U])(using AccountView[U]):

  /** `Client` dereferences CIMD (Client ID Metadata Document) client_ids. */
  type Env = AuthStore[U] & SecureRandomGen & JwtSigner & Client & R

  val routes: Routes[Env, Response] =
    Routes(
      Method.GET / ".well-known" / "oauth-authorization-server" -> handler(metadata),
      Method.GET / "oauth" / "jwks"                             -> handler(jwks),
      Method.GET / "oauth" / "authorize"                        -> handler(authorize),
      Method.POST / "oauth" / "authorize"                       -> handler(authorizeDecision),
      Method.POST / "oauth" / "token"                           -> handler(tokenEndpoint),
      Method.POST / "oauth" / "introspect"                      -> handler(introspect),
      Method.POST / "oauth" / "revoke"                          -> handler(revoke),
      Method.POST / "oauth" / "register"                        -> handler(register),
    )

  private val store: URIO[AuthStore[U], AuthStore[U]] = ZIO.service[AuthStore[U]]

  private def metadata(req: Request): UIO[Response] =
    ZIO.succeed(
      Response
        .json(OAuthServerMetadata.forIssuer(cfg.issuer).toJson)
        .addHeader(Header.CacheControl.NoStore)
    )

  private def jwks(req: Request): URIO[JwtSigner, Response] =
    ZIO.serviceWithZIO[JwtSigner](_.publicJwkSet).map { jwkSet =>
      Response
        .json(jwkSet.toString)
        .addHeader(Header.CacheControl.MaxAge(3600))
    }

  private enum PreRedirectError(val message: String):
    case MissingClientId             extends PreRedirectError("missing client_id")
    case MissingRedirectUri          extends PreRedirectError("missing redirect_uri")
    case BadRedirectUri(why: String) extends PreRedirectError(s"invalid redirect_uri: $why")
    case UnknownClient               extends PreRedirectError("unknown client_id")
    case RedirectUriNotRegistered    extends PreRedirectError("redirect_uri not registered for this client")

  private enum AuthError(val code: String, val description: String):
    case InvalidRequest(d: String) extends AuthError("invalid_request", d)
    case UnsupportedResponseType   extends AuthError("unsupported_response_type", "only response_type=code is supported")
    case InvalidScope(d: String)   extends AuthError("invalid_scope", d)
    case AccessDenied              extends AuthError("access_denied", "the user denied the request")
    case ServerError(d: String)    extends AuthError("server_error", d)

  private def authorize(req: Request): URIO[Env, Response] =
    parseRedirectUri(req.url.queryParams) match
      case Left(err) => ZIO.succeed(badRequest(err.message))
      case Right(_)  =>
        authorizeKnownOAuthClient(req, req.url.queryParams, approved = false).merge.catchAllCause(c =>
          ZIO.logErrorCause("authorize crashed", c).as(Response.status(Status.InternalServerError))
        )

  private def parseRedirectUri(q: QueryParams): Either[PreRedirectError, (ClientId, RedirectUri)] =
    for
      cid   <- q.queryParam("client_id").toRight(PreRedirectError.MissingClientId)
      ruRaw <- q.queryParam("redirect_uri").toRight(PreRedirectError.MissingRedirectUri)
      ru    <- RedirectUri.parse(ruRaw).left.map(e => PreRedirectError.BadRedirectUri(e.toString))
    yield (ClientId.of(cid), ru)

  /**
   * The consent page's answer. The original authorize query comes back in `request`; it is validated again exactly as
   * on the GET, and the form's csrf token must match the session.
   */
  private def authorizeDecision(req: Request): URIO[Env, Response] =
    val effect =
      for
        form     <- req.body.asURLEncodedForm.orElseFail(badRequest("bad form"))
        field     = (n: String) => form.get(n).flatMap(_.stringValue).getOrElse("")
        q         = QueryParams.decode(field("request"))
        current  <- Sessions.current[U](cfg, req).orElseFail(Response.status(Status.InternalServerError))
        session  <- ZIO.fromOption(current.map(_._1)).orElseFail(Response.status(Status.Forbidden))
        _        <- ZIO.unless(Csrf.isValid(cfg, field("_csrf"), session))(ZIO.fail(Response.status(Status.Forbidden)))
        // The gate and the login bounce see the request as the GET it stands for.
        asGet     = req.copy(method = Method.GET, url = req.url.copy(queryParams = q))
        response <- field("decision") match
                      case "approve" => authorizeKnownOAuthClient(asGet, q, approved = true)
                      case "deny"    =>
                        parseRedirectUri(q) match
                          case Left(err)     => ZIO.succeed(badRequest(err.message))
                          case Right((cid, ru)) =>
                            resolveClient(cid).orElseFail(Response.status(Status.InternalServerError)).map {
                              case Some(c) if ru.matchesRegistered(c.redirectUris) =>
                                redirectWithError(ru, AuthError.AccessDenied, q.queryParam("state"))
                              case _                                                => badRequest("unknown client or redirect_uri")
                            }
                      case _         => ZIO.succeed(badRequest("decision must be approve or deny"))
      yield response
    effect.merge.catchAllCause(c => ZIO.logErrorCause("authorize decision crashed", c).as(Response.status(Status.InternalServerError)))

  private def authorizeKnownOAuthClient(req: Request, q: QueryParams, approved: Boolean): ZIO[Env, Response, Response] =
    val internalErr = (_: Any) => Response.status(Status.InternalServerError)
    for
      cid       <- ZIO
                     .fromOption(q.queryParam("client_id").map(ClientId.of))
                     .orElseFail(badRequest(PreRedirectError.MissingClientId.message))
      ru        <- ZIO
                     .fromOption(q.queryParam("redirect_uri").flatMap(RedirectUri.parse(_).toOption))
                     .orElseFail(badRequest(PreRedirectError.MissingRedirectUri.message))
      clientOpt <- resolveClient(cid)
                     .tapErrorCause(c => ZIO.logErrorCause("authorize: resolveClient failed", c))
                     .mapError(internalErr)
      client    <- ZIO.fromOption(clientOpt).orElseFail(badRequest(PreRedirectError.UnknownClient.message))
      _         <- ZIO.unless(ru.matchesRegistered(client.redirectUris))(
                     ZIO.fail(badRequest(PreRedirectError.RedirectUriNotRegistered.message))
                   )
      result    <- validateAndIssue(client, ru, q, req, approved)
    yield result

  // --- Client resolution: pre-registered / DCR client, or CIMD dereference ---

  private final case class CimdDoc(
      client_id:     String,
      redirect_uris: List[String],
      grant_types:   Option[List[String]] = None,
      scope:         Option[String] = None,
      client_name:   Option[String] = None,
  ) derives JsonDecoder

  /**
   * Resolves a `client_id` to an [[OAuthClient]]. A URL-shaped id (HTTPS, or loopback HTTP for development) is a
   * Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document): fetch the document, require its
   * `client_id` to equal the URL, and build a public client from it. Its scopes come from the document's `scope` field,
   * as with DCR, so a CIMD client is no more privileged than a DCR one. Any other id is looked up in the store. CIMD
   * failures are logged and degrade to `None`, which the caller reports as an unknown client.
   */
  private def resolveClient(cid: ClientId): ZIO[Env, StoreError, Option[OAuthClient]] =
    // A URL-shaped client_id is a CIMD client, never a persisted/DCR one, so it never goes through findClient.
    if cimdEligible(cid.value) then resolveCimdClient(cid)
    else
      store.flatMap(_.findClient(cid)).flatMap {
        case found @ Some(c) =>
          ZIO.logInfo(s"OAuth client resolved via ${c.registration} registration (persisted): client_id=${c.id.value}").as(found)
        case None            => ZIO.none
      }

  // A URL-shaped client_id is a CIMD client; which URLs are actually fetched is CimdAddressPolicy's call.
  private def cimdEligible(url: String): Boolean =
    url.startsWith("https://") || url.startsWith("http://")

  private def resolveCimdClient(cid: ClientId): URIO[Client & AuthStore[U], Option[OAuthClient]] =
    val url   = cid.value
    val fetch =
      for
        now           <- Clock.instant
        _             <- CimdAddressPolicy
                           .check(url, cfg.cimdAllowLoopback)
                           .mapError(r => new RuntimeException(s"CIMD url refused: ${r.message}"))
        reqUrl        <- ZIO.fromEither(URL.decode(url)).mapError(e => new RuntimeException(s"invalid CIMD url: $e"))
        resp          <- ZIO.serviceWithZIO[Client](_.batched(Request.get(reqUrl)))
        _             <- ZIO.fail(new RuntimeException(s"CIMD fetch returned ${resp.status.code}")).when(!resp.status.isSuccess)
        body          <- resp.body.asString
        doc           <- ZIO.fromEither(body.fromJson[CimdDoc]).mapError(e => new RuntimeException(s"bad CIMD JSON: $e"))
        _             <- ZIO
                           .fail(new RuntimeException(s"CIMD client_id '${doc.client_id}' does not match its URL '$url'"))
                           .when(doc.client_id != url)
        uris           = doc.redirect_uris.flatMap(RedirectUri.parse(_).toOption).toSet
        _             <- ZIO.fail(new RuntimeException("CIMD document has no valid redirect_uris")).when(uris.isEmpty)
        declaredGrants = doc.grant_types
                           .map(_.flatMap(GrantType.parse(_).toOption).toSet)
                           .getOrElse(Set(GrantType.AuthorizationCode))
                           .intersect(Set(GrantType.AuthorizationCode, GrantType.RefreshToken))
        grants         = if declaredGrants.contains(GrantType.AuthorizationCode) then declaredGrants
                         else Set(GrantType.AuthorizationCode)
        scopes         = doc.scope.map(OAuthScopeSet.parse).getOrElse(Set.empty)
        client         = OAuthClient(
                           id = cid,
                           kind = ClientKind.Public,
                           profile = ClientProfile.Mcp,
                           name = doc.client_name.getOrElse("CIMD Client"),
                           secretHash = None,
                           grants = grants,
                           scopes = scopes,
                           registration = ClientRegistration.Dynamic,
                           registeredAt = now,
                           createdAt = now,
                           redirectUris = uris,
                         )
        // Persist an idempotent anchor so a store's references from grants and refresh tokens to clients are
        // satisfied. The stored client is ONLY an anchor: authorization always re-dereferences the document (URL
        // client_ids never go through findClient), so its freshly-fetched metadata decides every request.
        _             <- store.flatMap(_.createClient(client)).mapError(Sessions.asThrowable)
        _             <- ZIO.logInfo(s"OAuth client resolved via CIMD (dereferenced Client ID Metadata Document): client_id=$url")
      yield client
    fetch.mapBoth(identity, Some(_)).catchAllCause(c =>
      ZIO.logWarningCause(s"CIMD dereference failed for client_id '$url'", c).as(None)
    )

  private def validateAndIssue(
      client: OAuthClient,
      ru:       RedirectUri,
      q:        QueryParams,
      req:      Request,
      approved: Boolean,
  ): ZIO[Env, Response, Response] =
    val internalErr = (_: Any) => Response.status(Status.InternalServerError)
    val state       = q.queryParam("state")
    val redirectErr = (e: AuthError) => redirectWithError(ru, e, state)
    for
      _            <- ZIO.unless(q.queryParam("response_type").contains("code"))(
                        ZIO.fail(redirectErr(AuthError.UnsupportedResponseType))
                      )
      challengeRaw <- ZIO
                        .fromOption(q.queryParam("code_challenge"))
                        .orElseFail(redirectErr(AuthError.InvalidRequest("missing code_challenge")))
      methodRaw     = q.queryParam("code_challenge_method").getOrElse("S256")
      method       <- ZIO
                        .fromEither(ChallengeMethod.parse(methodRaw))
                        .mapError(e => redirectErr(AuthError.InvalidRequest(s"bad code_challenge_method: $e")))
      requested     = q.queryParam("scope").map(OAuthScopeSet.parse).getOrElse(Set.empty)
      _            <- ZIO.unless(requested.subsetOf(client.scopes))(
                        ZIO.fail(redirectErr(AuthError.InvalidScope("requested scope not allowed for client")))
                      )
      // Only scopes the server lets clients have: a client that registered `role:admin` doesn't get it. The user's own
      // scopes are added at the exchange.
      scopeReq      = requested.filter(cfg.clientScopes)
      resource     <- q.queryParam("resource") match
                        case None    => ZIO.succeed(Option.empty[ResourceIndicator])
                        case Some(s) =>
                          ZIO
                            .fromEither(ResourceIndicator.parse(s))
                            .mapBoth(e => redirectErr(AuthError.InvalidRequest(s"bad resource: $e")), Some(_))
      sessAndUser  <- Sessions
                        .current[U](cfg, req)
                        .tapErrorCause(c => ZIO.logErrorCause("validateAndIssue: Sessions.current failed", c))
                        .mapError(internalErr)
      response     <- sessAndUser match
                        case None            => ZIO.succeed(redirectToLogin(req))
                        case Some((_, user)) =>
                          gateOrIssue(
                            AuthorizeContext(user, client, scopeReq, resource, q.queryParam("resource"), req),
                            ru,
                            challengeRaw,
                            method,
                            state,
                            consented = approved || cfg.skipConsent(client),
                            consentPage = consentPage(user, client, ru, scopeReq, q, req),
                          )
                            .tapErrorCause(c => ZIO.logErrorCause("validateAndIssue: gateOrIssue failed", c))
                            .mapError(internalErr)
    yield response

  private def gateOrIssue(
      ctx:          AuthorizeContext[U],
      ru:           RedirectUri,
      challengeRaw: String,
      method:       ChallengeMethod,
      state:        Option[String],
      consented:    Boolean,
      consentPage:  => Response,
  ): RIO[Env, Response] =
    gate.check(ctx).flatMap {
      case GateDecision.Allow if !consented => ZIO.succeed(consentPage)
      case GateDecision.Allow             =>
        issueGrantAndRedirect(ctx.client, ctx.user, ru, ctx.scopes, ctx.resource, CodeChallenge.of(challengeRaw), method, state)
      case GateDecision.Respond(response) => ZIO.succeed(response)
    }

  /** The consent page: not framable, not cached, and with the session's csrf token in its form. */
  private def consentPage(user: U, client: OAuthClient, ru: RedirectUri, scopes: Set[OAuthScope], q: QueryParams, req: Request): Response =
    Sessions.readCookie(req, cfg.cookies.csrfName) match
      // Not a login bounce: `/login` would resume the session and send the browser straight back here, forever.
      case None       =>
        Response.text("Your sign-in is missing its CSRF cookie. Sign out, sign in again, and retry.").status(Status.Forbidden)
      case Some(csrf) =>
        val host = scala.util.Try(java.net.URI.create(ru.value)).toOption.flatMap(u => Option(u.getHost)).getOrElse(ru.value)
        Response
          .html(pages.consent(user, ConsentRequest(client.name, client.id, host, scopes, q.encode.stripPrefix("?")), CsrfToken.fromBase64Url(csrf)))
          .addHeader(Header.CacheControl.NoStore)
          .addHeader("X-Frame-Options", "DENY")
          .addHeader("Content-Security-Policy", "frame-ancestors 'none'")

  private def issueGrantAndRedirect(
      client:    OAuthClient,
      user:      U,
      ru:        RedirectUri,
      scope:     Set[OAuthScope],
      resource:  Option[ResourceIndicator],
      challenge: CodeChallenge,
      method:    ChallengeMethod,
      state:     Option[String],
  ): RIO[Env, Response] =
    for
      now     <- Clock.instant
      code    <- AuthorizationCode.mint
      codeHash = AuthorizationCodeHash.fromBytes(Crypto.hmacSha256(code.value, cfg.pepper.value))
      grant    = AuthorizationGrant(
                   codeHash = codeHash,
                   clientId = client.id,
                   userId = summon[AccountView[U]].id(user),
                   redirectUri = ru,
                   scopes = scope,
                   resource = resource,
                   codeChallenge = challenge,
                   challengeMethod = method,
                   issuedAt = now,
                   expiresAt = now.plus(java.time.Duration.ofMillis(cfg.authorizationCodeTtl.toMillis)),
                   consumedAt = None,
                 )
      _       <- store.flatMap(_.createGrant(grant)).mapError(Sessions.asThrowable)
      target   = appendCodeAndState(ru.value, code, state)
    yield Response
      .status(Status.SeeOther)
      .addHeader(Header.Location(URL.decode(target).toOption.get))

  private def appendCodeAndState(uri: String, code: AuthorizationCode, state: Option[String]): String =
    val sep  = if uri.contains('?') then "&" else "?"
    val base = s"$uri${sep}code=${java.net.URLEncoder.encode(code.value, "UTF-8")}"
    state match
      case Some(s) => s"$base&state=${java.net.URLEncoder.encode(s, "UTF-8")}"
      case None    => base

  private def redirectWithError(ru: RedirectUri, err: AuthError, state: Option[String]): Response =
    val sep  = if ru.value.contains('?') then "&" else "?"
    val base = s"${ru.value}${sep}error=${err.code}" +
      s"&error_description=${java.net.URLEncoder.encode(err.description, "UTF-8")}"
    val full = state match
      case Some(s) => s"$base&state=${java.net.URLEncoder.encode(s, "UTF-8")}"
      case None    => base
    Response
      .status(Status.SeeOther)
      .addHeader(Header.Location(URL.decode(full).toOption.get))

  private def redirectToLogin(req: Request): Response =
    val pathQ  = req.url.path.encode + req.url.queryParams.encode
    val target = s"/login?return_to=${java.net.URLEncoder.encode(pathQ, "UTF-8")}"
    Response
      .status(Status.SeeOther)
      .addHeader(Header.Location(URL.decode(target).toOption.get))

  private final case class TokenResponse(
      access_token:  String,
      token_type:    String,
      expires_in:    Long,
      scope:         String,
      refresh_token: Option[String] = None,
  ) derives JsonEncoder

  private final case class TokenError(error: String, error_description: String) derives JsonEncoder

  private def tokenFailure(status: Status, code: String, msg: String): IO[Response, Nothing] =
    ZIO.fail(
      Response
        .json(TokenError(code, msg).toJson)
        .status(status)
        .addHeader(Header.CacheControl.NoStore)
    )

  private def tokenEndpoint(req: Request): URIO[Env, Response] =
    val effect =
      for
        form        <- req.body.asURLEncodedForm
        grantTypeStr = form.get("grant_type").flatMap(_.stringValue).getOrElse("")
        result      <- grantTypeStr match
                         case "authorization_code" => authorizationCodeGrant(req, form)
                         case "refresh_token"      => refreshTokenGrant(req, form)
                         case other                =>
                           tokenFailure(Status.BadRequest, "unsupported_grant_type", s"unsupported grant_type: $other")
      yield result
    effect.catchAll {
      case r: Response  => ZIO.succeed(r)
      case t: Throwable =>
        ZIO.logErrorCause("token endpoint crashed", Cause.fail(t)) *>
          tokenFailure(Status.InternalServerError, "server_error", "internal error").flip
    }

  private def authorizationCodeGrant(req: Request, form: Form): ZIO[Env, Response, Response] =
    val codeStr     = form.get("code").flatMap(_.stringValue).getOrElse("")
    val cidStr      = form.get("client_id").flatMap(_.stringValue).getOrElse("")
    val ruStr       = form.get("redirect_uri").flatMap(_.stringValue).getOrElse("")
    val verifierStr = form.get("code_verifier").flatMap(_.stringValue).getOrElse("")

    if codeStr.isEmpty || cidStr.isEmpty || ruStr.isEmpty || verifierStr.isEmpty then
      tokenFailure(Status.BadRequest, "invalid_request", "missing code/client_id/redirect_uri/code_verifier")
    else
      RedirectUri.parse(ruStr) match
        case Left(_)   => tokenFailure(Status.BadRequest, "invalid_request", "bad redirect_uri")
        case Right(ru) =>
          CodeVerifier.parse(verifierStr) match
            case Left(_)         => tokenFailure(Status.BadRequest, "invalid_grant", "bad code_verifier")
            case Right(verifier) =>
              exchangeCodeFlow(
                code = AuthorizationCode.fromBase64Url(codeStr),
                clientId = ClientId.of(cidStr),
                ru = ru,
                verifier = verifier,
                req = req,
              )

  private def accessTokenClaims(
      subject:   UserId,
      scopes:    Set[OAuthScope],
      clientId:  ClientId,
      resource:  Option[ResourceIndicator],
      now:       Instant,
      expiresAt: Instant,
      jti:       String,
  ): com.nimbusds.jwt.JWTClaimsSet =
    val b = new com.nimbusds.jwt.JWTClaimsSet.Builder()
      .issuer(cfg.issuer)
      .subject(subject.value.toString)
      .issueTime(java.util.Date.from(now))
      .notBeforeTime(java.util.Date.from(now))
      .expirationTime(java.util.Date.from(expiresAt))
      .jwtID(jti)
      .claim("scope", OAuthScopeSet.render(scopes))
      .claim("client_id", clientId.value)
    resource.foreach(r => b.audience(r.value))
    b.build()

  private def exchangeCodeFlow(
      code:     AuthorizationCode,
      clientId: ClientId,
      ru:       RedirectUri,
      verifier: CodeVerifier,
      req:      Request,
  ): ZIO[Env, Response, Response] =
    def internalErr = tokenFailure(Status.InternalServerError, "server_error", "internal error")
    for
      now      <- Clock.instant
      clientOpt <- resolveClient(clientId).catchAllCause(c =>
                     ZIO.logErrorCause("token endpoint: resolveClient failed (auth-code grant)", c) *> internalErr
                   )
      client   <- clientOpt.fold(tokenFailure(Status.BadRequest, "invalid_client", "client not found"))(ZIO.succeed(_))
      _        <- clientAuthCheck(req, client)
      presented = Crypto.encodeB64Url(Crypto.sha256(verifier.value))
      codeHash  = AuthorizationCodeHash.fromBytes(Crypto.hmacSha256(code.value, cfg.pepper.value))
      jti      <- Random.nextUUID.map(_.toString)
      ttl       = client.profile.accessTokenTtl
      expiresAt = now.plus(java.time.Duration.ofMillis(ttl.toMillis))
      result   <- store.flatMap(
                    _.consumeGrant(
                      ExchangeCodeRequest(
                        presentedCodeHash = codeHash,
                        presentedClientId = clientId,
                        presentedRedirectUri = ru,
                        presentedChallenge = presented,
                      )
                    )
                  ).either
      consumed <- result match
                    case Right(r) => ZIO.succeed(r)
                    case Left(e)  => translateExchangeError(e)

      // The user's own scopes (toolbook's role closure) go alongside the requested scopes, so the JWT carries enough
      // for resource-server `requireScopes(role:X)` checks.
      effectiveScopes = consumed.scopes.filter(cfg.clientScopes) ++ consumed.userScopes

      claims = accessTokenClaims(consumed.userId, effectiveScopes, client.id, consumed.resource, now, expiresAt, jti)
      tokStr <- ZIO.serviceWithZIO[JwtSigner](_.sign(claims))

      // The window between consumeGrant and createAccessToken is microseconds. If createAccessToken fails after the
      // grant was consumed, the grant is already single-use, so the client just re-authorizes and gets a fresh code.
      tokHash = AccessTokenHash.fromBytes(Crypto.hmacSha256(tokStr, cfg.pepper.value))
      issued  = IssuedAccessToken(
                  hash = tokHash,
                  clientId = client.id,
                  subjectKind = SubjectKind.User,
                  userId = Some(consumed.userId),
                  scopes = effectiveScopes,
                  resource = consumed.resource,
                  issuedAt = now,
                  expiresAt = expiresAt,
                  revokedAt = None,
                )
      _      <- store.flatMap(_.createAccessToken(issued)).catchAllCause(c =>
                  ZIO.logErrorCause("token endpoint: createAccessToken failed (auth-code grant)", c) *> internalErr
                )

      // A refresh token alongside the access token for any client that supports it: it is what keeps desktop MCP
      // clients signed in across days without re-authorizing.
      maybeRt <- ZIO.when(client.grants.contains(GrantType.RefreshToken))(
                   mintRootRefreshToken(client, consumed.userId, effectiveScopes, consumed.resource, now)
                     .catchAllCause(c =>
                       ZIO.logErrorCause("token endpoint: mintRootRefreshToken failed (auth-code grant)", c) *> internalErr
                     )
                 )

      body = TokenResponse(
               access_token = tokStr,
               token_type = "Bearer",
               expires_in = ttl.toSeconds,
               scope = OAuthScopeSet.render(effectiveScopes),
               refresh_token = maybeRt.map(_._1.value),
             )
    yield Response
      .json(body.toJson)
      .addHeader(Header.CacheControl.NoStore)

  /** Mints a fresh root-of-chain refresh token and persists it; returns the plaintext (only seen here) and the row. */
  private def mintRootRefreshToken(
      client:   OAuthClient,
      userId:   UserId,
      scopes:   Set[OAuthScope],
      resource: Option[ResourceIndicator],
      now:      Instant,
  ): RIO[Env, (RefreshToken, IssuedRefreshToken)] =
    for
      raw   <- RefreshToken.mint
      hash   = RefreshTokenHash.hash(raw.value, cfg.pepper.value)
      ttl    = client.profile.refreshTokenTtl
      issued = IssuedRefreshToken(
                 hash = hash,
                 rootHash = hash, // self == root
                 parentHash = None,
                 clientId = client.id,
                 userId = Some(userId),
                 scopes = scopes,
                 resource = resource,
                 issuedAt = now,
                 expiresAt = now.plus(java.time.Duration.ofMillis(ttl.toMillis)),
                 revokedAt = None,
                 rotatedAt = None,
                 rotatedToHash = None,
               )
      _     <- store.flatMap(_.createRefreshToken(issued)).mapError(Sessions.asThrowable)
    yield (raw, issued)

  private def translateExchangeError(e: ExchangeError): IO[Response, Nothing] =
    val msg = e match
      case ExchangeError.GrantNotFound       => "unknown code"
      case ExchangeError.AlreadyConsumed     => "code already consumed"
      case ExchangeError.Expired             => "code expired"
      case ExchangeError.ClientMismatch      => "client_id does not match grant"
      case ExchangeError.RedirectUriMismatch => "redirect_uri does not match grant"
      case ExchangeError.PkceMismatch        => "PKCE verifier does not match challenge"
      // A store failure: don't leak the server-side message, collapse to a generic invalid_grant.
      case ExchangeError.Internal(_)         => "code rejected"
    tokenFailure(Status.BadRequest, "invalid_grant", msg)

  /**
   * RFC 6749 §6: the client presents `refresh_token` and gets a new access token and a rotated refresh token. On a
   * rotation conflict (replay, expiry, missing) the store revokes the chain and the client gets invalid_grant; it can
   * then drop its stored refresh token and start the authorization-code flow again.
   */
  private def refreshTokenGrant(req: Request, form: Form): ZIO[Env, Response, Response] =
    def internalErr = tokenFailure(Status.InternalServerError, "server_error", "internal error")

    val rtRaw  = form.get("refresh_token").flatMap(_.stringValue).getOrElse("")
    val cidStr = form.get("client_id").flatMap(_.stringValue).getOrElse("")
    val scope  = form.get("scope").flatMap(_.stringValue).map(OAuthScopeSet.parse)

    if rtRaw.isEmpty then tokenFailure(Status.BadRequest, "invalid_request", "missing refresh_token")
    else
      val presentedHash = RefreshTokenHash.hash(rtRaw, cfg.pepper.value)
      for
        now      <- Clock.instant
        rtRowOpt <- store.flatMap(_.findRefreshToken(presentedHash)).catchAllCause(c =>
                      ZIO.logErrorCause("token endpoint: findRefreshToken failed (refresh grant)", c) *> internalErr
                    )
        rtRow    <- rtRowOpt.fold(tokenFailure(Status.BadRequest, "invalid_grant", "unknown refresh_token"))(ZIO.succeed(_))

        // Authenticate the client. Two valid presentations: a confidential client with HTTP Basic carrying its id and
        // secret, or a public client with the client_id form field and no secret, which must match the refresh
        // token's client_id (else cross-client refresh-token theft).
        clientOpt <- resolveClient(rtRow.clientId).catchAllCause(c =>
                       ZIO.logErrorCause("token endpoint: resolveClient failed (refresh grant)", c) *> internalErr
                     )
        client    <- clientOpt.fold(internalErr)(ZIO.succeed(_))
        _         <- clientAuthCheck(req, client)
        _         <- ZIO.when(cidStr.nonEmpty && cidStr != rtRow.clientId.value)(
                       tokenFailure(Status.BadRequest, "invalid_grant", "refresh_token does not belong to this client")
                     )

        // No user id means a client_credentials-issued refresh token, which isn't minted today.
        userId <- rtRow.userId.fold(
                    tokenFailure(Status.BadRequest, "invalid_grant", "refresh_token has no associated user")
                  )(ZIO.succeed(_))

        // The user as of now: a deleted or disabled user's chain is revoked and the refresh fails.
        userOpt <- store.flatMap(_.findActiveUser(userId)).catchAllCause(c =>
                     ZIO.logErrorCause("token endpoint: findActiveUser failed (refresh grant)", c) *> internalErr
                   )
        user    <- userOpt match
                     case Some(u) => ZIO.succeed(u)
                     case None    =>
                       ZIO.logWarning(s"token endpoint: refresh for a user who may no longer get tokens: ${userId.value}") *>
                         store
                           .flatMap(_.revokeRefreshTokenIfOwned(RevokeRefreshTokenRequest(rtRow.hash, client.id)))
                           .catchAllCause(c => ZIO.logErrorCause("token endpoint: revoking an inactive user's chain failed", c)) *>
                         tokenFailure(Status.BadRequest, "invalid_grant", "refresh_token revoked")

        // RFC 6749 §6: the requested scope MUST be a subset of the original. Default to the original scope set. The
        // stored scopes hold the user's scopes of the time; the new token gets the user's current ones instead, plus
        // the requested scopes clients may have. So a role taken away is gone at the next refresh, and a token from
        // before `clientScopes` (one that asked for `role:admin`) loses what it asked for.
        requested  <- scope match
                        case None    => ZIO.succeed(rtRow.scopes)
                        case Some(s) =>
                          if s.subsetOf(rtRow.scopes) then ZIO.succeed(s)
                          else tokenFailure(Status.BadRequest, "invalid_scope", "requested scope exceeds original")
        userScopes  = summon[AccountView[U]].scopes(user)
        nextScopes  = requested.filter(cfg.clientScopes) ++ scope.fold(userScopes)(s => userScopes.filter(s.contains))

        ttl       = client.profile.accessTokenTtl
        expiresAt = now.plus(java.time.Duration.ofMillis(ttl.toMillis))
        atJti    <- Random.nextUUID.map(_.toString)
        atStr    <- ZIO.serviceWithZIO[JwtSigner](
                      _.sign(accessTokenClaims(userId, nextScopes, client.id, rtRow.resource, now, expiresAt, atJti))
                    )
        atHash    = AccessTokenHash.fromBytes(Crypto.hmacSha256(atStr, cfg.pepper.value))

        // The successor refresh token, linked to the same chain root.
        rtNextRaw  <- RefreshToken.mint
        rtNextHash  = RefreshTokenHash.hash(rtNextRaw.value, cfg.pepper.value)
        rtTtl       = client.profile.refreshTokenTtl
        // Sliding window: every refresh resets the expiry to `now + refreshTokenTtl`, so an actively-used client stays
        // signed in. This doesn't widen the stolen-token window meaningfully: rotation with replay detection revokes the
        // entire chain the moment the legitimate client refreshes a token an attacker already used.
        rtExpiresAt = now.plus(java.time.Duration.ofMillis(rtTtl.toMillis))
        rtNew       = IssuedRefreshToken(
                        hash = rtNextHash,
                        rootHash = rtRow.rootHash,
                        parentHash = Some(rtRow.hash),
                        clientId = client.id,
                        userId = Some(userId),
                        scopes = nextScopes,
                        resource = rtRow.resource,
                        issuedAt = now,
                        expiresAt = rtExpiresAt,
                        revokedAt = None,
                        rotatedAt = None,
                        rotatedToHash = None,
                      )

        rotateResult <- store
                          .flatMap(_.rotateRefreshToken(RotateRefreshTokenRequest(rtRow.hash, rtNew, now)))
                          .either
        _            <- rotateResult match
                          case Right(_) => ZIO.unit
                          case Left(e)  => translateRotateError(e)

        atIssued = IssuedAccessToken(
                     hash = atHash,
                     clientId = client.id,
                     subjectKind = SubjectKind.User,
                     userId = Some(userId),
                     scopes = nextScopes,
                     resource = rtRow.resource,
                     issuedAt = now,
                     expiresAt = expiresAt,
                     revokedAt = None,
                   )
        _       <- store.flatMap(_.createAccessToken(atIssued)).catchAllCause(c =>
                     ZIO.logErrorCause("token endpoint: createAccessToken failed (refresh grant)", c) *> internalErr
                   )

        body = TokenResponse(
                 access_token = atStr,
                 token_type = "Bearer",
                 expires_in = ttl.toSeconds,
                 scope = OAuthScopeSet.render(nextScopes),
                 refresh_token = Some(rtNextRaw.value),
               )
      yield Response
        .json(body.toJson)
        .addHeader(Header.CacheControl.NoStore)

  private def translateRotateError(e: RotateRefreshTokenError): IO[Response, Nothing] =
    val msg = e match
      case RotateRefreshTokenError.NotFound    => "unknown refresh_token"
      case RotateRefreshTokenError.Expired     => "refresh_token expired"
      case RotateRefreshTokenError.Revoked     => "refresh_token revoked"
      // The chain has already been revoked by the store. A generic message, so an attacker can't tell a first replay
      // from a post-revoke state.
      case RotateRefreshTokenError.Replay      => "refresh_token revoked"
      // A store failure: don't leak the server-side message.
      case RotateRefreshTokenError.Internal(_) => "refresh_token rejected"
    val log = e match
      case RotateRefreshTokenError.Internal(m) => ZIO.logError(s"token endpoint: rotateRefreshToken failed (refresh grant): $m")
      case other                               => ZIO.logWarning(s"token endpoint: rotateRefreshToken rejected (refresh grant): $other")
    log *> tokenFailure(Status.BadRequest, "invalid_grant", msg)

  private def clientAuthCheck(req: Request, client: OAuthClient): IO[Response, Unit] =
    client.kind match
      case ClientKind.Public       => ZIO.unit
      case ClientKind.Confidential =>
        val basic = req.headers.get(Header.Authorization).collect { case b: Header.Authorization.Basic => b }
        basic match
          case None    => tokenFailure(Status.Unauthorized, "invalid_client", "confidential client requires HTTP Basic")
          case Some(b) =>
            val presentedId     = ClientId.of(b.username)
            val presentedSecret = ClientSecret.of(b.password.value.asString)
            client.secretHash match
              case None         => tokenFailure(Status.Unauthorized, "invalid_client", "client has no registered secret")
              case Some(stored) =>
                val presentedHash = ClientSecretHash.fromBytes(Crypto.hmacSha256(presentedSecret.value, cfg.pepper.value))
                tokenFailure(Status.Unauthorized, "invalid_client", "bad client credentials")
                  .unless(
                    presentedId == client.id &&
                      java.security.MessageDigest.isEqual(presentedHash.bytes, stored.bytes)
                  )
                  .unit

  private val inactiveResponse: Response =
    Response
      .json("""{"active":false}""")
      .addHeader(Header.CacheControl.NoStore)

  private def activeResponse(tok: IssuedAccessToken): Response =
    import zio.json.ast.Json
    val sub                               = tok.subjectKind match
      case SubjectKind.User   => tok.userId.fold("")(_.value.toString)
      case SubjectKind.Client => tok.clientId.value
    val baseFields: Chunk[(String, Json)] = Chunk(
      "active"     -> Json.Bool(true),
      "client_id"  -> Json.Str(tok.clientId.value),
      "sub"        -> Json.Str(sub),
      "scope"      -> Json.Str(OAuthScopeSet.render(tok.scopes)),
      "iss"        -> Json.Str(cfg.issuer),
      "iat"        -> Json.Num(tok.issuedAt.getEpochSecond),
      "exp"        -> Json.Num(tok.expiresAt.getEpochSecond),
      "token_type" -> Json.Str("Bearer"),
    )
    val withAud: Chunk[(String, Json)]    = tok.resource match
      case None    => baseFields
      case Some(r) => baseFields ++ Chunk("aud" -> Json.Arr(Chunk(Json.Str(r.value))))
    Response
      .json(Json.Obj(withAud).toJson)
      .addHeader(Header.CacheControl.NoStore)

  private def introspect(req: Request): URIO[Env, Response] =
    val effect =
      for
        form      <- req.body.asURLEncodedForm
        tokenStr   = form.get("token").flatMap(_.stringValue).getOrElse("")
        cliEither <- authenticateClient(req, form).either
        response  <- cliEither match
                       case Left(_)       => ZIO.succeed(inactiveResponse)
                       case Right(client) =>
                         if tokenStr.isEmpty then ZIO.succeed(inactiveResponse)
                         else introspectActive(tokenStr, client)
      yield response
    effect.catchAllCause(c => ZIO.logErrorCause("introspect crashed", c).as(inactiveResponse))

  /** A token is reported active only to the client it was issued to, or to one in `introspectAnyToken`. */
  private def introspectActive(tokenStr: String, client: OAuthClient): RIO[Env, Response] =
    val tHash = AccessTokenHash.fromBytes(Crypto.hmacSha256(tokenStr, cfg.pepper.value))
    for
      tokOpt <- store.flatMap(_.findAccessToken(tHash)).mapError(Sessions.asThrowable)
      now    <- Clock.instant
    yield tokOpt match
      case Some(tok) if tok.isActive(now) && (tok.clientId == client.id || cfg.introspectAnyToken(client)) => activeResponse(tok)
      case _                                                                                                => inactiveResponse

  private val revokeOk: Response = Response.ok

  private def revoke(req: Request): URIO[Env, Response] =
    val effect =
      for
        form      <- req.body.asURLEncodedForm
        tokenStr   = form.get("token").flatMap(_.stringValue).getOrElse("")
        cliEither <- authenticateClient(req, form).either
        response  <- cliEither match
                       case Left(authErr) => ZIO.succeed(authErr)
                       case Right(client) =>
                         if tokenStr.isEmpty then ZIO.succeed(revokeOk)
                         else revokeIfOwned(tokenStr, client)
      yield response
    effect.catchAllCause(c => ZIO.logErrorCause("revoke crashed", c).as(Response.status(Status.InternalServerError)))

  private def revokeIfOwned(tokenStr: String, client: OAuthClient): RIO[Env, Response] =
    // Try the access token first (the common case), then the refresh token. `token_type_hint` is ignored: trying both
    // is cheap and lets a misclassified hint still work.
    val atHash = AccessTokenHash.fromBytes(Crypto.hmacSha256(tokenStr, cfg.pepper.value))
    val rtHash = RefreshTokenHash.hash(tokenStr, cfg.pepper.value)
    (for
      s <- store
      _ <- s.revokeAccessTokenIfOwned(RevokeAccessTokenRequest(atHash, client.id))
      _ <- s.revokeRefreshTokenIfOwned(RevokeRefreshTokenRequest(rtHash, client.id))
    yield revokeOk).mapError(Sessions.asThrowable)

  private final case class RegistrationRequest(
      redirect_uris:              List[String],
      client_name:                Option[String] = None,
      grant_types:                Option[List[String]] = None,
      response_types:             Option[List[String]] = None,
      token_endpoint_auth_method: Option[String] = None,
      scope:                      Option[String] = None,
  ) derives JsonDecoder

  private final case class RegistrationError(error: String, error_description: String) derives JsonEncoder

  private final case class ParsedRegistration(
      redirectUris:    Set[RedirectUri],
      grants:          Set[GrantType],
      scopes:          Set[OAuthScope],
      tokenAuthMethod: String,
      clientName:      Option[String],
  )

  private def regErrorResponse(status: Status, code: String, msg: String): Response =
    Response
      .json(RegistrationError(code, msg).toJson)
      .status(status)
      .addHeader(Header.CacheControl.NoStore)

  private def register(req: Request): URIO[Env, Response] =
    val effect =
      for
        bodyStr   <- req.body.asString.orElseFail(regErrorResponse(Status.BadRequest, "invalid_client_metadata", "could not read body"))
        parsed    <- ZIO
                       .fromEither(bodyStr.fromJson[RegistrationRequest])
                       .mapError(e => regErrorResponse(Status.BadRequest, "invalid_client_metadata", s"bad JSON: $e"))
        validated <- ZIO.fromEither(validateRegistration(parsed))
        now       <- Clock.instant
        cid       <- ClientId.mint
        kind       = validated.tokenAuthMethod match
                       case "none"                => ClientKind.Public
                       case "client_secret_basic" => ClientKind.Confidential
                       case _                     => ClientKind.Public
        plaintext <- kind match
                       case ClientKind.Public       => ZIO.succeed(Option.empty[String])
                       case ClientKind.Confidential => ClientSecret.mint.map(s => Some(s.value))
        secretHash = plaintext.map(p => ClientSecretHash.fromBytes(Crypto.hmacSha256(p, cfg.pepper.value)))
        client     = OAuthClient(
                       id = cid,
                       kind = kind,
                       profile = ClientProfile.Mcp,
                       name = validated.clientName.getOrElse("Unnamed Client"),
                       secretHash = secretHash,
                       grants = validated.grants,
                       scopes = validated.scopes,
                       registration = ClientRegistration.Dynamic,
                       registeredAt = now,
                       createdAt = now,
                       redirectUris = validated.redirectUris,
                     )
        _         <- store
                       .flatMap(_.createClient(client))
                       .tapErrorCause(c => ZIO.logErrorCause(s"register: createClient failed (client_id=${cid.value})", c))
                       .mapError(_ => regErrorResponse(Status.InternalServerError, "server_error", "create failed"))
        body       = registrationResponseJson(client, plaintext, validated, now)
      yield Response
        .json(body.toJson)
        .status(Status.Created)
        .addHeader(Header.CacheControl.NoStore)

    effect.merge.catchAllCause(c =>
      ZIO.logErrorCause("register crashed", c).as(regErrorResponse(Status.InternalServerError, "server_error", "internal error"))
    )

  private def validateRegistration(req: RegistrationRequest): Either[Response, ParsedRegistration] =
    def fail(code: String, msg: String) = regErrorResponse(Status.BadRequest, code, msg)

    for
      _               <- if req.redirect_uris.isEmpty then Left(fail("invalid_redirect_uri", "at least one redirect_uri required"))
                         else Right(())
      uris            <- req.redirect_uris.foldRight(Right(Set.empty): Either[Response, Set[RedirectUri]]) { (raw, acc) =>
                           for
                             set <- acc
                             ru  <- RedirectUri.parse(raw).left.map(e => fail("invalid_redirect_uri", s"$raw: $e"))
                           yield set + ru
                         }
      grantsList       = req.grant_types.getOrElse(List("authorization_code"))
      requestedGrants <- grantsList.foldRight(Right(Set.empty): Either[Response, Set[GrantType]]) { (raw, acc) =>
                           for
                             set <- acc
                             gt  <- GrantType.parse(raw).left.map(e => fail("invalid_client_metadata", s"grant_type: $e"))
                           yield set + gt
                         }
      // RFC 7591 §3.2.1 lets the AS replace requested metadata with values it can honor: grants are narrowed to
      // {authorization_code, refresh_token}.
      grants           = requestedGrants intersect Set(GrantType.AuthorizationCode, GrantType.RefreshToken)
      _               <- if grants.contains(GrantType.AuthorizationCode) then Right(())
                         else Left(fail("invalid_client_metadata", "grant_types must include authorization_code"))
      responseTypes    = req.response_types.getOrElse(List("code"))
      _               <- if responseTypes.toSet == Set("code") then Right(())
                         else Left(fail("invalid_client_metadata", "only response_type=code supported"))
      tokenAuth        = req.token_endpoint_auth_method.getOrElse("none")
      _               <- if Set("none", "client_secret_basic").contains(tokenAuth) then Right(())
                         else
                           Left(fail("invalid_client_metadata", "token_endpoint_auth_method must be 'none' or 'client_secret_basic'"))
      scopes           = req.scope.map(OAuthScopeSet.parse).getOrElse(Set.empty)
    yield ParsedRegistration(
      redirectUris = uris,
      grants = grants,
      scopes = scopes,
      tokenAuthMethod = tokenAuth,
      clientName = req.client_name,
    )

  private def registrationResponseJson(
      client:          OAuthClient,
      plaintextSecret: Option[String],
      validated:       ParsedRegistration,
      now:             Instant,
  ): zio.json.ast.Json =
    import zio.json.ast.Json
    val base: Chunk[(String, Json)] = Chunk(
      "client_id"                  -> Json.Str(client.id.value),
      "client_id_issued_at"        -> Json.Num(now.getEpochSecond),
      "redirect_uris"              -> Json.Arr(Chunk.fromIterable(client.redirectUris.iterator.map(u => Json.Str(u.value)).toList)),
      "grant_types"                -> Json.Arr(Chunk.fromIterable(client.grants.iterator.map(g => Json.Str(g.asString)).toList)),
      "response_types"             -> Json.Arr(Chunk(Json.Str("code"))),
      "token_endpoint_auth_method" -> Json.Str(validated.tokenAuthMethod),
      "scope"                      -> Json.Str(OAuthScopeSet.render(client.scopes)),
      "client_name"                -> Json.Str(client.name),
    )
    val withSecret                  = plaintextSecret match
      case None    => base
      case Some(s) => base ++ Chunk("client_secret" -> Json.Str(s), "client_secret_expires_at" -> Json.Num(0))
    Json.Obj(withSecret)

  private def authenticateClient(req: Request, form: Form): ZIO[Env, Response, OAuthClient] =
    val basic                                               = req.headers.get(Header.Authorization).collect { case b: Header.Authorization.Basic => b }
    val candidate: Option[(ClientId, Option[ClientSecret])] = basic match
      case Some(b) => Some((ClientId.of(b.username), Some(ClientSecret.of(b.password.value.asString))))
      case None    => form.get("client_id").flatMap(_.stringValue).map(cid => (ClientId.of(cid), None))

    def invalidClient = tokenFailure(Status.Unauthorized, "invalid_client", "bad client credentials")
    def internalErr   = ZIO.fail(Response.status(Status.InternalServerError))

    candidate match
      case None                     => invalidClient
      case Some((cid, maybeSecret)) =>
        for
          // `resolveClient` (CIMD-aware), not `findClient` directly: URL-shaped CIMD client_ids are dereferenced.
          opt    <- resolveClient(cid).catchAllCause(c => ZIO.logErrorCause("client auth: resolveClient failed", c) *> internalErr)
          client <- opt.fold(invalidClient)(ZIO.succeed(_))
          _      <- (client.kind, maybeSecret) match
                      case (ClientKind.Public, _)               => ZIO.unit
                      case (ClientKind.Confidential, None)      => invalidClient
                      case (ClientKind.Confidential, Some(sec)) =>
                        client.secretHash match
                          case None         => invalidClient
                          case Some(stored) =>
                            val ph = ClientSecretHash.fromBytes(Crypto.hmacSha256(sec.value, cfg.pepper.value))
                            invalidClient.unless(java.security.MessageDigest.isEqual(ph.bytes, stored.bytes)).unit
        yield client

  private def badRequest(msg: String): Response =
    Response.status(Status.BadRequest).copy(body = Body.fromString(msg))

object OAuthRoutes:
  /** With the default consent page ([[Pages.defaultConsent]]). */
  def apply[R, U: Tag](cfg: AuthServerConfig, gate: AuthorizeGate[R, U])(using AccountView[U]): OAuthRoutes[R, U] =
    new OAuthRoutes(cfg, gate, Pages.default[U])

  def apply[R, U: Tag](cfg: AuthServerConfig, gate: AuthorizeGate[R, U], pages: Pages[U])(using AccountView[U]): OAuthRoutes[R, U] =
    new OAuthRoutes(cfg, gate, pages)
