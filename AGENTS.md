# AGENTS.md — zio-auth-server

`zio-auth-server` is a published Scala 3 / ZIO 2 library: an OAuth 2.1 authorization server with email sign-in
(magic link and one-time code), browser sessions and an access-JWT cookie, built on zio-http. It was extracted from
toolbook's `login` module. See `README.md` for the feature overview. Releases go through sbt-ci-release with
`versionScheme := Some("semver-spec")`.

## Modules

- `core` (artifact `zio-auth-server`): the server. Package `com.jamesward.zioauthserver`. Persistence is the
  `AuthStore[U]` port, generic over the app's user type through `AccountView[U]`; email goes through `Mailer`.
- `testkit` (artifact `zio-auth-server-test`): development and test helpers, package
  `com.jamesward.zioauthserver.testkit`. Apps depend on it in the Test scope only, so anything that would be unsafe in
  production belongs here and not in `core`: `InMemoryAuthStore`, `RecordingMailer`, `DevConfig` (plain cookies, fixed
  pepper), `DevSessions.fixed`, `DevJwtSigner`. `core` keeps such code `private[zioauthserver]` (for example
  `Sessions.fixed`) and `testkit` exposes it. The end-to-end `AuthServerSpec` lives in `testkit`'s tests, since `core`
  can't depend on `testkit`.

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
- Tests need no network beyond dependency resolution, no Docker, and nothing paid or metered.
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
