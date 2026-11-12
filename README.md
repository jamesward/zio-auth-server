# zio-auth-server

[![javadocs.dev](https://www.javadocs.dev/com.jamesward/zio-auth-server_3/badge.svg)](https://www.javadocs.dev/com.jamesward/zio-auth-server_3/latest)

A Scala 3 / [ZIO](https://zio.dev) / [zio-http](https://zio.dev/zio-http) OAuth 2.1 authorization server with
first-party email sign-in, for apps whose MCP servers and web pages need signed-in users.

- **Email sign-in**: a magic link, or a six-digit code typed back (for a link opened on another device). Codes allow
  five attempts.
- **Browser sessions**: a revocable session cookie, a CSRF cookie, and a short-lived RS256 access-JWT cookie that
  other first-party servers can verify against `/oauth/jwks` without a database lookup. `/login?return_to=` resumes a
  live session without email.
- **OAuth 2.1 for MCP clients**: authorization code with PKCE (S256 only), refresh tokens that rotate and revoke their
  whole chain on replay, Dynamic Client Registration, Client ID Metadata Documents, resource indicators, token
  introspection and revocation, and `/.well-known/oauth-authorization-server`.
- **Your user type, your storage**: the server is generic over the app's user type (`AccountView[U]` says what it
  needs from it) and persists through the `AuthStore[U]` port, so an app can keep the data in its own database or
  behind its own API. Only hashes of secrets (HMAC with a pepper) are stored.
- **Your pages, your rules**: `Pages[U]` and `Messages` replace the plain default HTML and email text, and an
  `AuthorizeGate` can send a user elsewhere (terms, payment) before a code is issued.

## Install

```scala
libraryDependencies ++= Seq(
  "com.jamesward" %% "zio-auth-server"      % "<version>",
  // In-memory store, recording mailer, dev cookies, fixed sessions, throwaway keys. Test scope only.
  "com.jamesward" %% "zio-auth-server-test" % "<version>" % Test,
)
```

## A server

```scala
import com.jamesward.zioauthserver.*
import zio.*
import zio.http.*

final case class MyUser(id: UserId, email: Email)

given AccountView[MyUser] with
  def id(u: MyUser)     = u.id
  def email(u: MyUser)  = u.email
  def scopes(u: MyUser) = Set.empty

object Main extends ZIOAppDefault:
  val config = AuthServerConfig(
    baseUrl = URL.decode("https://login.example.com").toOption.get,
    cookies = CookieConfig(sessionName = "__Host-sid", csrfName = "__Host-csrf", secure = true),
    pepper  = Pepper.of(sys.env("AUTH_PEPPER")),
  )

  val server = AuthServer[MyUser](config, Pages.default, Messages.default("Example"))

  def run =
    Server.serve(server.routes).provide(
      Server.default,
      Client.default,
      SecureRandomGen.live,
      JwtSigner.fromEnv, // JWT_SIGNING_KEY_JWK: an RS256 private JWK
      myStore,           // an AuthStore[MyUser]
      myMailer,          // a Mailer
    )
```

## Tests and local development

`zio-auth-server-test` has what a test or a dev run needs and production must not have:

- `InMemoryAuthStore`: the whole `AuthStore` in a `Ref`, with the same consume-once and rotate-once rules.
- `RecordingMailer`: keeps and logs the emails instead of sending them, so a test can follow the link.
- `DevConfig`: plain cookie names over HTTP and a fixed pepper.
- `DevSessions.fixed`: a session with a chosen id, for a dev login that survives restarts.
- `DevJwtSigner`: a signer with a fresh or a fixed dev key.

```scala
val env =
  InMemoryAuthStore.layer[MyUser]((id, email, _) => MyUser(id, email)) ++ RecordingMailer.layer ++
    SecureRandomGen.live ++ DevJwtSigner.fresh ++ Client.default
```

## License

[Apache-2.0](LICENSE)
