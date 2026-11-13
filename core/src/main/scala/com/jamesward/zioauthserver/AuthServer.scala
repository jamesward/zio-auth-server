package com.jamesward.zioauthserver

import zio.*
import zio.http.*

/**
 * The whole server: first-party sign-in ([[LoginRoutes]]) and the OAuth 2.1 endpoints ([[OAuthRoutes]]).
 *
 * {{{
 * val server = AuthServer[MyUser](config, Pages.default, Messages.default("My App"))
 * Server.serve(server.routes)
 * }}}
 *
 * Provide an [[AuthStore]] for `U`, a [[Mailer]], a [[JwtSigner]], a [[SecureRandomGen]] and a zio-http `Client` (for
 * Client ID Metadata Documents), plus whatever the [[AuthorizeGate]] needs.
 */
final class AuthServer[R, U: Tag](
    cfg:      AuthServerConfig,
    pages:    Pages[U],
    messages: Messages,
    gate:     AuthorizeGate[R, U],
)(using AccountView[U]):

  val login: LoginRoutes[U]    = LoginRoutes(cfg, pages, messages)
  val oauth: OAuthRoutes[R, U] = OAuthRoutes(cfg, gate, pages)

  val routes: Routes[login.Env & oauth.Env, Response] = login.routes ++ oauth.routes

object AuthServer:

  def apply[U: Tag](cfg: AuthServerConfig, pages: Pages[U], messages: Messages)(using AccountView[U]): AuthServer[Any, U] =
    new AuthServer(cfg, pages, messages, AuthorizeGate.allowAll[U])
