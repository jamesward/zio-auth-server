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
- **Consent and scopes**: a signed-in user approves each client on a consent page (`Pages.consent`) before it gets a
  code, except clients you list in `AuthServerConfig.skipConsent`. A token carries the user's own scopes plus only the
  requested scopes in `AuthServerConfig.clientScopes`, so a client can't ask its way to a role.
- **Your user type, your storage**: the server is generic over the app's user type (`AccountView[U]` says what it
  needs from it) and persists through the `AuthStore[U]` port, so an app can keep the data in its own database or
  behind its own API. Only hashes of secrets (HMAC with a pepper) are stored.
- **Your pages, your rules**: `Pages[U]` and `Messages` replace the plain default HTML and email text, and an
  `AuthorizeGate` can send a user elsewhere (terms, payment) before a code is issued.
- **Closed sign-up when you want it**: a `SignUpPolicy` (`Open`, `ExistingUsersOnly`, `Allowlist`) decides whether an
  unknown address may create an account; for a closed one the server doesn't even send it a link.
- **Passkeys** (opt-in `PasskeyRoutes`): discoverable-credential sign-in and registration, verified with Yubico's
  `java-webauthn-server`, plus a small browser script (`Passkeys.script`).
- **Step-up**: adding a passkey or changing the address (opt-in `AccountRoutes`) needs a session that started in the
  last 10 minutes; otherwise the browser signs in again (`/login?reauth=1`).
- **Upstream connections**: `OAuthConnector` links a user to an OAuth provider (GitHub included), checks which account
  it is, stores the tokens sealed with AES-GCM (`TokenSealer`), refreshes them, and disconnects.
- **In-process token checks**: `AccessTokenVerifier` verifies a bearer token against the store for a resource server
  that shares it, with no introspection call.
- **Email through Mailgun**: `MailgunMailer`.

## Modules

| Artifact | Contains |
|---|---|
| `zio-auth-server` | The server, the store interfaces (`AuthStore`, `AccountStore`, `PasskeyStore`, `ConnectionStore`), passkeys, step-up, connections, Mailgun. |
| `zio-auth-server-magnum` | Every store on Postgres with [magnum](https://github.com/AugustNagro/magnum), and the migrations for its own schema (`AuthSchema`). |
| `zio-auth-server-test` | **Test scope only.** In-memory stores, the contract suite every store must pass (`AuthStoreContract`), a software passkey authenticator, a recording mailer, dev cookies, fixed sessions, throwaway keys. |

## Install

```scala
libraryDependencies ++= Seq(
  "com.jamesward" %% "zio-auth-server"      % "<version>",
  // Postgres stores, if you don't bring your own.
  "com.jamesward" %% "zio-auth-server-magnum" % "<version>",
  // In-memory stores, the contract suite, dev helpers. Test scope only.
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

## The Postgres stores and their schema

`zio-auth-server-magnum` keeps its tables in their own schema (default `auth`) and migrates them with its own Flyway
run, separate from the app's:

```scala
AuthSchema.migrate(dataSource) *> MyApp.migrate(dataSource) // for example in a Heroku release phase
val stores = MagnumAuthStore.layer(SignUpPolicy.ExistingUsersOnly) // AuthStore, AccountStore, PasskeyStore, ConnectionStore
```

- The migrations ship in the jar at `classpath:com/jamesward/zioauthserver/magnum/migrations`, not in `db/migration`,
  so the app's Flyway never picks them up and the two version sequences never collide.
- Flyway's history for them is `auth.flyway_schema_history`; the app's stays in `public`. Upgrading the library adds
  migrations to the `auth` history only.
- The app's own tables may reference `auth.users(id)`; run `AuthSchema.migrate` first.
- Don't add the library's location to the app's Flyway `locations`: both would share one history, and a library `V2`
  would clash with the app's `V2`.

The store uses [zio-magnum](https://github.com/cheleb/zio-magnum). Single-use rows are locked (`select … for update`) or
removed (`delete … returning`) inside one `transaction`. If your app installs the zio-logging SLF4J bridge, install it
with `Slf4jBridge.initWithoutFiberRefPropagation`: with `init`, an SLF4J log inside a zio-magnum transaction closes the
transaction's connection.

## Tests and local development

`zio-auth-server-test` has what a test or a dev run needs and production must not have:

- `InMemoryAuthStore`: every store trait in a `Ref`, with the same consume-once and rotate-once rules.
- `AuthStoreContract`: the behavior every store must have, one suite per store interface. A store with all four runs
  `AuthStoreContract.spec[R, MyUser]("MyStore", policy => MyStore.layer(policy))`; one that implements only some runs
  those: `authStore`, `signUpPolicy`, `accountStore`, `passkeyStore`, `connectionStore`.
- `SoftwareAuthenticator`: answers passkey options like a browser would, for testing passkey flows.
- `RecordingMailer`: keeps and logs the emails instead of sending them, so a test can follow the link.
- `DevConfig`: plain cookie names over HTTP and a fixed pepper.
- `DevSessions.fixed`: a session with a chosen id, for a dev login that survives restarts.
- `DevJwtSigner`: a signer with a fresh or a fixed dev key.

```scala
val env =
  InMemoryAuthStore.layer[MyUser]((id, email, _) => MyUser(id, email), (u, email) => u.copy(email = email)) ++ RecordingMailer.layer ++
    SecureRandomGen.live ++ DevJwtSigner.fresh ++ Client.default
```

## License

[Apache-2.0](LICENSE)
