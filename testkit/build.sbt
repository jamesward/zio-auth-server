name := "zio-auth-server-test"

val zioVersion = "2.1.27"

// zio-test is a compile dependency: the contract suite (AuthStoreContract) is a zio-test Spec that store
// implementations run in their own tests. This artifact is Test scope only for its users.
libraryDependencies ++= Seq(
  "dev.zio" %% "zio-test"     % zioVersion,
  "dev.zio" %% "zio-test-sbt" % zioVersion % Test,
)
