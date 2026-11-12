name := "zio-auth-server"

val zioVersion       = "2.1.27"
val zioSchemaVersion = "1.9.1"

libraryDependencies ++= Seq(
  "dev.zio"     %% "zio"                   % zioVersion,
  "dev.zio"     %% "zio-http"              % "3.11.6",
  "dev.zio"     %% "zio-json"              % "1.1.2",
  "dev.zio"     %% "zio-schema"            % zioSchemaVersion,
  "dev.zio"     %% "zio-schema-derivation" % zioSchemaVersion,
  "com.nimbusds" % "nimbus-jose-jwt"       % "10.10",

  "dev.zio" %% "zio-test"     % zioVersion % Test,
  "dev.zio" %% "zio-test-sbt" % zioVersion % Test,
)
