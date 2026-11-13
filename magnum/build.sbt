name := "zio-auth-server-magnum"

val zioVersion    = "2.1.27"
val flywayVersion = "13.12.2"

libraryDependencies ++= Seq(
  "dev.cheleb"       %% "zio-magnum"                 % "4.2.0",
  "org.flywaydb"     % "flyway-core"                % flywayVersion,
  "org.flywaydb"     % "flyway-database-postgresql" % flywayVersion,

  // The app brings its own driver and pool; the tests use these.
  "org.postgresql" % "postgresql"                       % "42.7.14" % Test,
  "com.dimafeng"  %% "testcontainers-scala-postgresql"  % "0.44.1"  % Test,
  "dev.zio"       %% "zio-test"                         % zioVersion % Test,
  "dev.zio"       %% "zio-test-sbt"                     % zioVersion % Test,
)

// The specs start and stop their Postgres container themselves; Ryuk's published port can collide under rootless
// Docker. Testcontainers reads this only from the environment (tests are forked).
Test / envVars += "TESTCONTAINERS_RYUK_DISABLED" -> "true"
