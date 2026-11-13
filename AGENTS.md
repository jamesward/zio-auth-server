# AGENTS.md — zio-auth-server

`zio-auth-server` is a published Scala 3 / ZIO 2 library: an OAuth 2.1 authorization server with email sign-in
(magic link and one-time code), browser sessions and an access-JWT cookie, built on zio-http. It was extracted from
toolbook's `login` module. See `README.md` for the feature overview. Releases go through sbt-ci-release with
`versionScheme := Some("semver-spec")`.

## Modules

- `core` (artifact `zio-auth-server`): the server. Package `com.jamesward.zioauthserver`.
  - Persistence is the store traits, generic over the app's user type through `AccountView[U]`: `AuthStore[U]` (the
    sign-in and OAuth data toolbook's API layer implements), and the optional `AccountStore[U]`, `PasskeyStore`,
    `ConnectionStore`. New store needs go in new traits, or `AuthStore` methods with a default, so toolbook's
    `ApiAuthStore` keeps compiling.
  - Opt-in route sets beside `LoginRoutes` and `OAuthRoutes`: `PasskeyRoutes`, `AccountRoutes` (email change),
    `ConnectionRoutes` (an `OAuthConnector`'s callback). Identity changes require `StepUp`.
  - Passkeys use Yubico's `webauthn-server-core`. Its `CredentialRepository` is synchronous, so each ceremony loads
    what it needs from the store first and passes a snapshot.
- `magnum` (artifact `zio-auth-server-magnum`): `MagnumAuthStore` (every store trait on Postgres, user type `AuthUser`)
  and `AuthSchema` (its own Flyway run: migrations at `classpath:com/jamesward/zioauthserver/magnum/migrations`,
  schema and history table `auth`). Add migrations as new `V<n>__*.sql` files there; never edit a released one. Always
  zio-magnum (`transaction`, `zQuery`, `zUpdate`), not plain magnum. Its connection `FiberRef` is closed by the
  zio-logging SLF4J bridge's `init`; apps use `Slf4jBridge.initWithoutFiberRefPropagation` (see toolbook's AGENTS.md).
  Business failures are returned as `Either` from the transaction, so work before them (a counted OTP attempt, a revoked
  replay chain) commits. Store calls `resurrect` before mapping errors: `zUpdate` runs `executeUpdate()` in a `map`, so
  its SQL errors (a unique violation) arrive as defects.
- `testkit` (artifact `zio-auth-server-test`): development and test helpers, package
  `com.jamesward.zioauthserver.testkit`. Apps depend on it in the Test scope only, so anything that would be unsafe in
  production belongs here and not in `core`: `InMemoryAuthStore`, `AuthStoreContract`, `SoftwareAuthenticator`,
  `RecordingMailer`, `DevConfig` (plain cookies, fixed pepper), `DevSessions.fixed`, `DevJwtSigner`. `core` keeps such
  code `private[zioauthserver]` (for example `Sessions.fixed`) and `testkit` exposes it. `zio-test` is a compile
  dependency here (the contract suite is a Spec). The route specs live in `testkit`'s tests, since `core` can't depend
  on `testkit`.
- Every store implementation runs `AuthStoreContract`: `InMemoryAuthStoreSpec`, `MagnumAuthStoreSpec` (Testcontainers
  Postgres). A behavior every store must have goes into the contract, not into one store's spec.

## Skills

- Follow the `zen-of-projects` Skill (extract with `./sbta extractSkillsJars` into the gitignored `.kiro/skills/`);
  this file records only project-specific facts and exceptions. Read the relevant Skills before working.
- For Scala 3 and ZIO code (writing or reviewing it), follow `zen-of-scala`.
- For design, domain modeling, effects and testing strategy, follow `zen-of-james`.

## Build, Test & Dev Workflow

- MCP server `sbta` (this build's `./sbta --mcp`, configured in `.mcp.json` and `.kiro/settings/mcp.json`, approved in
  `.claude/settings.json`): use it for all sbt work: `compile`, `test` (`full` for all), `check` after editing Scala 3
  sources, `glob-search` / `inspect` / `symbol-location` for symbols, `sbt-task` for any other command. Its tools are
  deferred in Claude Code: load them with ToolSearch (search `sbta`). If it's unavailable, say so and use
  `./sbta <command>`.
- Commands (CLI fallback form): `./sbta "Test / compile"`, `./sbta testFull` (what CI runs).
- Tests need Docker for `magnum`'s Postgres (Testcontainers, Ryuk disabled; the specs stop their container), no network
  beyond dependency resolution and the image pull, and nothing paid or metered.
- Working on toolbook (or another app) against this checkout: the app's build uses a local `ProjectRef` to
  `../zio-auth-server` behind a flag (see that app's AGENTS.md). Run `./sbta publishLocal` only when a flag-free
  build needs it.

## Maintenance

- Maintenance routine: `.factory/MAINTENANCE.md` (weekly), following the `zen-of-projects` Skill.

## Releasing

- Run the `Tag Release` workflow (or push a `v<major>.<minor>.<patch>` tag); `release.yml` runs `testFull` then
  `ci-release`.

## Exceptions to zen-of-projects

None.
