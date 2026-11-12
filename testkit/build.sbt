name := "zio-auth-server-test"

val zioVersion = "2.1.27"

libraryDependencies ++= Seq(
  "dev.zio" %% "zio-test"     % zioVersion % Test,
  "dev.zio" %% "zio-test-sbt" % zioVersion % Test,
)
