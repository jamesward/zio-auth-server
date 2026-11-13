package com.jamesward.zioauthserver

import zio.*

/** An access token that passed [[AccessTokenVerifier.verify]]. */
final case class VerifiedAccessToken(
    clientId: ClientId,
    userId:   Option[UserId],
    scopes:   Set[OAuthScope],
    resource: Option[ResourceIndicator],
)

/**
 * Verifies a bearer token in-process, for a resource server that shares the store with the authorization server (the
 * factory's `/mcp`): no introspection call and no introspection credentials. A token passes when its stored row is
 * active (not expired, not revoked) and, if `resource` is given, its audience is that resource. Since the row is read
 * every time, a revoked token never passes.
 */
final class AccessTokenVerifier[U](cfg: AuthServerConfig, store: AuthStore[U]):

  def verify(bearer: String, resource: Option[ResourceIndicator]): IO[StoreError, Option[VerifiedAccessToken]] =
    val hash = AccessTokenHash.fromBytes(Crypto.hmacSha256(bearer, cfg.pepper.value))
    for
      now <- Clock.instant
      row <- store.findAccessToken(hash)
    yield row.collect {
      case t if t.isActive(now) && resource.forall(r => t.resource.contains(r)) =>
        VerifiedAccessToken(t.clientId, t.userId, t.scopes, t.resource)
    }
