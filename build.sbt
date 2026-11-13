// Settings at the top of this file apply to every subproject (sbt 2).
organization := "com.jamesward"

scalaVersion := "3.9.0"

scalacOptions ++= Seq(
  "-language:strictEquality",
  "-deprecation",
  "-Werror",
)

licenses := Seq("Apache-2.0" -> uri("https://www.apache.org/licenses/LICENSE-2.0"))

homepage := Some(uri("https://github.com/jamesward/zio-auth-server"))

developers := List(
  Developer(
    "jamesward",
    "James Ward",
    "james@jamesward.com",
    uri("https://jamesward.com")
  )
)

versionScheme := Some("semver-spec")

fork := true

javaOptions ++= Seq(
  "--enable-native-access=ALL-UNNAMED",
  "--sun-misc-unsafe-memory-access=allow",
)

// SkillsJars: extract agent Skills with `./sbta extractSkillsJars`
skillsJarsOutputDir := Some(file(".kiro/skills"))

libraryDependencies += "com.jamesward" % "skills" % "0.0.27" % Skills

// The library: OAuth 2.1 authorization server, sign-in routes and the store interfaces.
lazy val core = project in file("core")

// Development and test helpers (artifact zio-auth-server-test): in-memory store, recording mailer, dev cookies, fixed
// sessions and throwaway signing keys. Depend on it in the Test scope only, so none of it can reach production.
lazy val testkit = (project in file("testkit")).dependsOn(core)

// Postgres stores with magnum, and the `auth` schema's migrations (artifact zio-auth-server-magnum).
lazy val magnum = (project in file("magnum")).dependsOn(core, testkit % Test)

lazy val root = (project in file("."))
  .aggregate(core, testkit, magnum)
  .settings(
    name := "zio-auth-server-root",
    publish / skip := true,
  )
