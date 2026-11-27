name := "zio-auth-server"

val zioVersion       = "2.1.27"
val zioSchemaVersion = "1.9.2"

libraryDependencies ++= Seq(
  "dev.zio"     %% "zio"                   % zioVersion,
  "dev.zio"     %% "zio-http"              % "3.12.0",
  "dev.zio"     %% "zio-json"              % "1.1.3",
  "dev.zio"     %% "zio-schema"            % zioSchemaVersion,
  "dev.zio"     %% "zio-schema-derivation" % zioSchemaVersion,
  "com.nimbusds" % "nimbus-jose-jwt"       % "10.10",
  // Passkeys: WebAuthn registration and assertion verification.
  "com.yubico"   % "webauthn-server-core"  % "2.10.1",

  "dev.zio" %% "zio-test"     % zioVersion % Test,
  "dev.zio" %% "zio-test-sbt" % zioVersion % Test,
)
