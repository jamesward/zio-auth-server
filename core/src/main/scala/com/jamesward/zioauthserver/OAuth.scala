package com.jamesward.zioauthserver

import zio.*
import zio.schema.*

import java.net.URI
import java.time.Instant
import java.util.UUID

opaque type ClientId = String
object ClientId:
  def of(s: String): ClientId                  = s
  val mint: URIO[SecureRandomGen, ClientId]    =
    ZIO.serviceWithZIO[SecureRandomGen](_.nextBytes(16)).map(b => Crypto.encodeB64Url(b))
  extension (c: ClientId) def value: String    = c
  given CanEqual[ClientId, ClientId]           = CanEqual.derived
  given Schema[ClientId]                       = Schema[String].transform(of, _.value)

opaque type ClientSecret = String
object ClientSecret:
  def of(s: String): ClientSecret                  = s
  val mint: URIO[SecureRandomGen, ClientSecret]    =
    ZIO.serviceWithZIO[SecureRandomGen](_.nextBytes(32)).map(b => Crypto.encodeB64Url(b))
  extension (s: ClientSecret) def value: String    = s
  given CanEqual[ClientSecret, ClientSecret]       = CanEqual.derived
  given Schema[ClientSecret]                        = Schema[String].transform(of, _.value)

opaque type ClientSecretHash = Array[Byte]
object ClientSecretHash:
  def fromBytes(b: Array[Byte]): ClientSecretHash         = b
  extension (h: ClientSecretHash) def bytes: Array[Byte]  = h
  given CanEqual[ClientSecretHash, ClientSecretHash]      = CanEqual.derived
  given Schema[ClientSecretHash] =
    Schema[String].transformOrFail(
      s => Crypto.decodeB64Url(s).map(fromBytes),
      h => Right(Crypto.encodeB64Url(h.bytes)),
    )

enum ClientKind derives CanEqual, Schema:
  case Public, Confidential

object ClientKind:
  def parse(s: String): Either[String, ClientKind] = s match
    case "public"       => Right(ClientKind.Public)
    case "confidential" => Right(ClientKind.Confidential)
    case other          => Left(s"unknown client kind: $other")

  extension (k: ClientKind)
    def asString: String = k match
      case ClientKind.Public       => "public"
      case ClientKind.Confidential => "confidential"

enum ClientProfile derives CanEqual, Schema:
  case Standard, Mcp

object ClientProfile:
  def parse(s: String): Either[String, ClientProfile] = s match
    case "standard" => Right(ClientProfile.Standard)
    case "mcp"      => Right(ClientProfile.Mcp)
    case other      => Left(s"unknown client profile: $other")

  extension (p: ClientProfile)
    def asString: String = p match
      case ClientProfile.Standard => "standard"
      case ClientProfile.Mcp      => "mcp"

    def accessTokenTtl: zio.Duration = p match
      case ClientProfile.Mcp      => zio.Duration.fromJava(java.time.Duration.ofDays(1))
      case ClientProfile.Standard => zio.Duration.fromJava(java.time.Duration.ofHours(1))

    // Refresh tokens are long-lived but server-side: they're stored as
    // HMAC hashes and can be revoked individually (logout), in bulk by
    // client_id (revoke a misbehaving client), or in chains (replay
    // detection). The Mcp profile uses the same TTL OAuth offline-access
    // tokens commonly do; the Standard profile is shorter because web
    // sessions usually re-auth on a tighter cycle.
    def refreshTokenTtl: zio.Duration = p match
      case ClientProfile.Mcp      => zio.Duration.fromJava(java.time.Duration.ofDays(90))
      case ClientProfile.Standard => zio.Duration.fromJava(java.time.Duration.ofDays(30))

enum ClientRegistration derives CanEqual, Schema:
  case Static, Dynamic

object ClientRegistration:
  def parse(s: String): Either[String, ClientRegistration] = s match
    case "static"  => Right(ClientRegistration.Static)
    case "dynamic" => Right(ClientRegistration.Dynamic)
    case other     => Left(s"unknown client registration: $other")

  extension (r: ClientRegistration)
    def asString: String = r match
      case ClientRegistration.Static  => "static"
      case ClientRegistration.Dynamic => "dynamic"

enum GrantType derives CanEqual, Schema:
  case AuthorizationCode, ClientCredentials, RefreshToken

object GrantType:
  def parse(s: String): Either[String, GrantType] = s match
    case "authorization_code" => Right(GrantType.AuthorizationCode)
    case "client_credentials" => Right(GrantType.ClientCredentials)
    case "refresh_token"      => Right(GrantType.RefreshToken)
    case other                => Left(s"unknown grant_type: $other")

  extension (g: GrantType)
    def asString: String = g match
      case GrantType.AuthorizationCode => "authorization_code"
      case GrantType.ClientCredentials => "client_credentials"
      case GrantType.RefreshToken      => "refresh_token"

opaque type RedirectUri = String
object RedirectUri:
  enum InvalidRedirectUri derives CanEqual:
    case Empty, Malformed, NotAbsolute, MissingScheme

  def parse(s: String): Either[InvalidRedirectUri, RedirectUri] =
    val t = s.trim
    if t.isEmpty then Left(InvalidRedirectUri.Empty)
    else
      try
        val uri = URI.create(t)
        if !uri.isAbsolute     then Left(InvalidRedirectUri.NotAbsolute)
        else if uri.getScheme == null then Left(InvalidRedirectUri.MissingScheme)
        else                              Right(t)
      catch case _: IllegalArgumentException => Left(InvalidRedirectUri.Malformed)

  private val loopbackHosts = Set("localhost", "127.0.0.1", "::1", "[::1]")
  private def asUri(r: RedirectUri): Option[URI] =
    try Some(URI.create(r)) catch case _: IllegalArgumentException => None

  extension (r: RedirectUri)
    def value: String = r
    /**
     * True if this (request) redirect_uri matches one of the client's `registered`
     * URIs. Exact match, OR — per RFC 8252 §7.3/§8.3 — a loopback match: when BOTH
     * the registered and the requested host are loopback, they match on scheme +
     * path with the loopback host form treated as equivalent (localhost ≡ 127.0.0.1
     * ≡ ::1) and the PORT ignored. This accommodates native/CLI clients that
     * register one loopback form (e.g. `http://localhost:6274/oauth/callback`) but
     * request another (`http://127.0.0.1:6274/...`) and/or an ephemeral port.
     * Non-loopback URIs must match exactly (including host + port).
     */
    def matchesRegistered(registered: Set[RedirectUri]): Boolean =
      registered.exists { reg =>
        reg == r || ((asUri(reg), asUri(r)) match
          case (Some(a), Some(b)) =>
            val ha = Option(a.getHost).getOrElse("")
            val hb = Option(b.getHost).getOrElse("")
            loopbackHosts.contains(ha) && loopbackHosts.contains(hb) &&
              a.getScheme == b.getScheme &&
              Option(a.getPath).getOrElse("") == Option(b.getPath).getOrElse("")
          case _ => false)
      }

  given CanEqual[RedirectUri, RedirectUri]         = CanEqual.derived
  given Schema[RedirectUri] =
    Schema[String].transformOrFail(
      s => parse(s).left.map(err => s"invalid redirect_uri: $err"),
      r => Right(r.value),
    )

opaque type OAuthScope = String
object OAuthScope:
  def of(s: String): OAuthScope                = s
  extension (sc: OAuthScope) def value: String = sc
  given CanEqual[OAuthScope, OAuthScope]            = CanEqual.derived
  given Schema[OAuthScope]                          = Schema[String].transform(of, _.value)

object OAuthScopeSet:
  def parse(s: String): Set[OAuthScope] =
    s.split("\\s+").iterator.filter(_.nonEmpty).map(OAuthScope.of).toSet

  def render(s: Set[OAuthScope]): String =
    s.iterator.map(_.value).toSeq.sorted.mkString(" ")

opaque type ResourceIndicator = String
object ResourceIndicator:
  enum InvalidResource derives CanEqual:
    case Empty, NotAbsolute, Malformed

  // Parse-don't-validate: a `ResourceIndicator` is always canonicalized to its
  // ORIGIN (`scheme://host[:port]`), with any path/query/fragment stripped and
  // scheme+host lowercased. The audience our resource servers enforce is
  // host-wide: zio-http-mcp mounts every toolbook under `mountedAtParam("slug")`,
  // and for param mounts it derives the expected audience from the host root
  // (not the per-`<slug>` path) — see McpServer.authResourcePath. An MCP client
  // that requests `resource=https://host/<slug>` (deriving it from the mount URL
  // rather than the PRM `resource` field) would otherwise get a token whose
  // `aud` includes the path and be rejected with an audience mismatch. Folding
  // to the origin here makes the issued `aud` match what the resource server
  // checks, and makes a path-bearing audience unrepresentable downstream.
  def parse(s: String): Either[InvalidResource, ResourceIndicator] =
    val t = s.trim
    if t.isEmpty then Left(InvalidResource.Empty)
    else
      try
        val uri = URI.create(t)
        if !uri.isAbsolute then Left(InvalidResource.NotAbsolute)
        else
          // Need an authority (host) to form an origin. Opaque/host-less
          // absolute URIs (e.g. `urn:...`) can't be a host-wide MCP audience.
          Option(uri.getHost) match
            case None       => Left(InvalidResource.Malformed)
            case Some(host) =>
              val scheme = uri.getScheme.toLowerCase
              val port   = uri.getPort // -1 when unspecified
              val origin =
                if port < 0 then s"$scheme://${host.toLowerCase}"
                else s"$scheme://${host.toLowerCase}:$port"
              Right(origin)
      catch case _: IllegalArgumentException => Left(InvalidResource.Malformed)

  extension (r: ResourceIndicator) def value: String = r
  given CanEqual[ResourceIndicator, ResourceIndicator] = CanEqual.derived
  given Schema[ResourceIndicator] =
    Schema[String].transformOrFail(
      s => parse(s).left.map(err => s"invalid resource: $err"),
      r => Right(r.value),
    )

opaque type CodeChallenge = String
object CodeChallenge:
  def of(s: String): CodeChallenge          = s
  extension (c: CodeChallenge) def value: String = c
  given CanEqual[CodeChallenge, CodeChallenge]   = CanEqual.derived
  given Schema[CodeChallenge]                    = Schema[String].transform(of, _.value)

opaque type CodeVerifier = String
object CodeVerifier:
  enum InvalidVerifier derives CanEqual:
    case TooShort, TooLong, BadChars

  private val Allowed = "^[A-Za-z0-9\\-._~]+$".r

  def parse(s: String): Either[InvalidVerifier, CodeVerifier] =
    if s.length < 43          then Left(InvalidVerifier.TooShort)
    else if s.length > 128    then Left(InvalidVerifier.TooLong)
    else if !Allowed.matches(s) then Left(InvalidVerifier.BadChars)
    else                          Right(s)

  extension (v: CodeVerifier) def value: String = v
  given CanEqual[CodeVerifier, CodeVerifier]    = CanEqual.derived
  given Schema[CodeVerifier] =
    Schema[String].transformOrFail(
      s => parse(s).left.map(err => s"invalid code_verifier: $err"),
      v => Right(v.value),
    )

final case class OAuthClient(
    id:           ClientId,
    kind:         ClientKind,
    profile:      ClientProfile,
    name:         String,
    secretHash:   Option[ClientSecretHash],
    grants:       Set[GrantType],
    scopes:       Set[OAuthScope],
    registration: ClientRegistration,
    registeredAt: Instant,
    createdAt:    Instant,
    redirectUris: Set[RedirectUri],
) derives Schema

opaque type AuthorizationCode = String
object AuthorizationCode:
  def fromBase64Url(s: String): AuthorizationCode        = s
  val mint: URIO[SecureRandomGen, AuthorizationCode]     =
    ZIO.serviceWithZIO[SecureRandomGen](_.nextBytes(32)).map(b => Crypto.encodeB64Url(b))
  extension (c: AuthorizationCode) def value: String     = c
  given CanEqual[AuthorizationCode, AuthorizationCode]   = CanEqual.derived
  given Schema[AuthorizationCode]                        = Schema[String].transform(fromBase64Url, _.value)

opaque type AuthorizationCodeHash = Array[Byte]
object AuthorizationCodeHash:
  def fromBytes(b: Array[Byte]): AuthorizationCodeHash       = b
  extension (h: AuthorizationCodeHash) def bytes: Array[Byte] = h
  given CanEqual[AuthorizationCodeHash, AuthorizationCodeHash] = CanEqual.derived
  given Schema[AuthorizationCodeHash] =
    Schema[String].transformOrFail(
      s => Crypto.decodeB64Url(s).map(fromBytes),
      h => Right(Crypto.encodeB64Url(h.bytes)),
    )

final case class AuthorizationGrant(
    codeHash:        AuthorizationCodeHash,
    clientId:        ClientId,
    userId:          UserId,
    redirectUri:     RedirectUri,
    scopes:          Set[OAuthScope],
    resource:        Option[ResourceIndicator],
    codeChallenge:   CodeChallenge,
    challengeMethod: ChallengeMethod,
    issuedAt:        Instant,
    expiresAt:       Instant,
    consumedAt:      Option[Instant],
) derives Schema

enum ChallengeMethod derives CanEqual, Schema:
  case S256

object ChallengeMethod:
  def parse(s: String): Either[String, ChallengeMethod] = s match
    case "S256"  => Right(ChallengeMethod.S256)
    case "plain" => Left("plain is not allowed; use S256")
    case other   => Left(s"unknown code_challenge_method: $other")

  extension (m: ChallengeMethod)
    def asString: String = m match
      case ChallengeMethod.S256 => "S256"

object AuthorizationGrant:
  enum ConsumeError derives CanEqual:
    case AlreadyConsumed
    case Expired
    case ClientMismatch
    case RedirectUriMismatch
    case PkceMismatch
    case PkceVerifierInvalid

  def consume(
      grant:               AuthorizationGrant,
      presentedClient:     ClientId,
      presentedRedirectUri: RedirectUri,
      presentedChallenge:  String,
      now:                 Instant,
  ): Either[ConsumeError, AuthorizationGrant] =
    // Error ordering matters: PKCE check is reported LAST so an attacker
    // can't probe verifier guesses against a fresh code forever — they
    // must first acquire a valid, unconsumed, unexpired, right-client,
    // right-redirect code.
    if grant.consumedAt.isDefined then Left(ConsumeError.AlreadyConsumed)
    else if !now.isBefore(grant.expiresAt) then Left(ConsumeError.Expired)
    else if grant.clientId != presentedClient then Left(ConsumeError.ClientMismatch)
    else if grant.redirectUri != presentedRedirectUri then Left(ConsumeError.RedirectUriMismatch)
    else if !java.security.MessageDigest.isEqual(
              grant.codeChallenge.value.getBytes("UTF-8"),
              presentedChallenge.getBytes("UTF-8"),
            )
    then Left(ConsumeError.PkceMismatch)
    else Right(grant.copy(consumedAt = Some(now)))

opaque type AccessToken = String
object AccessToken:
  def fromBase64Url(s: String): AccessToken    = s
  extension (t: AccessToken) def value: String = t
  given CanEqual[AccessToken, AccessToken]     = CanEqual.derived
  given Schema[AccessToken]                    = Schema[String].transform(fromBase64Url, _.value)

opaque type AccessTokenHash = Array[Byte]
object AccessTokenHash:
  def fromBytes(b: Array[Byte]): AccessTokenHash       = b
  extension (h: AccessTokenHash) def bytes: Array[Byte] = h
  given CanEqual[AccessTokenHash, AccessTokenHash]     = CanEqual.derived
  given Schema[AccessTokenHash] =
    Schema[String].transformOrFail(
      s => Crypto.decodeB64Url(s).map(fromBytes),
      h => Right(Crypto.encodeB64Url(h.bytes)),
    )

enum SubjectKind derives CanEqual, Schema:
  case User, Client

object SubjectKind:
  def parse(s: String): Either[String, SubjectKind] = s match
    case "user"   => Right(SubjectKind.User)
    case "client" => Right(SubjectKind.Client)
    case other    => Left(s"unknown subject_kind: $other")

  extension (k: SubjectKind)
    def asString: String = k match
      case SubjectKind.User   => "user"
      case SubjectKind.Client => "client"

final case class IssuedAccessToken(
    hash:        AccessTokenHash,
    clientId:    ClientId,
    subjectKind: SubjectKind,
    userId:      Option[UserId],
    scopes:      Set[OAuthScope],
    resource:    Option[ResourceIndicator],
    issuedAt:    Instant,
    expiresAt:   Instant,
    revokedAt:   Option[Instant],
) derives Schema:
  def isActive(now: Instant): Boolean =
    revokedAt.isEmpty && now.isBefore(expiresAt)

opaque type RefreshToken = String
object RefreshToken:
  def fromBase64Url(s: String): RefreshToken    = s
  // 48 bytes → 64 b64url chars, comfortably above the 256-bit floor for
  // an opaque server-side credential. Plaintext is only emitted once at
  // /token; the server side keeps only HMAC(token, pepper).
  val mint: URIO[SecureRandomGen, RefreshToken] =
    ZIO.serviceWithZIO[SecureRandomGen](_.nextBytes(48)).map(b => Crypto.encodeB64Url(b))
  extension (t: RefreshToken) def value: String = t
  given CanEqual[RefreshToken, RefreshToken]    = CanEqual.derived
  given Schema[RefreshToken]                    = Schema[String].transform(fromBase64Url, _.value)

opaque type RefreshTokenHash = Array[Byte]
object RefreshTokenHash:
  def fromBytes(b: Array[Byte]): RefreshTokenHash       = b
  def hash(tokenValue: String, pepperValue: String): RefreshTokenHash =
    fromBytes(Crypto.hmacSha256(tokenValue, pepperValue))
  extension (h: RefreshTokenHash) def bytes: Array[Byte] = h
  given CanEqual[RefreshTokenHash, RefreshTokenHash]    = CanEqual.derived
  given Schema[RefreshTokenHash] =
    Schema[String].transformOrFail(
      s => Crypto.decodeB64Url(s).map(fromBytes),
      h => Right(Crypto.encodeB64Url(h.bytes)),
    )

// One row of `oauth_refresh_tokens` in domain shape. `parentHash` is the
// immediate predecessor in the rotation chain (None on the root); `rootHash`
// points at the root and is what chain-revocation indexes on.
//
// `rotatedAt` is the only field that changes after insert (besides
// `revokedAt` and `rotatedToHash`): once set, presenting this token is a
// replay attempt and the entire chain is revoked.
final case class IssuedRefreshToken(
    hash:           RefreshTokenHash,
    rootHash:       RefreshTokenHash,
    parentHash:     Option[RefreshTokenHash],
    clientId:       ClientId,
    userId:         Option[UserId],
    scopes:         Set[OAuthScope],
    resource:       Option[ResourceIndicator],
    issuedAt:       Instant,
    expiresAt:      Instant,
    revokedAt:      Option[Instant],
    rotatedAt:      Option[Instant],
    rotatedToHash:  Option[RefreshTokenHash],
) derives Schema:
  def isUsable(now: Instant): Boolean =
    revokedAt.isEmpty && rotatedAt.isEmpty && now.isBefore(expiresAt)
