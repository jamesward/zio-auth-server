package com.jamesward.zioauthserver.magnum

import com.jamesward.zioauthserver.testkit.AuthStoreContract
import zio.test.*

import javax.sql.DataSource

/** The Postgres store against the contract every store must pass. */
object MagnumAuthStoreSpec extends ZIOSpecDefault:

  def spec =
    AuthStoreContract
      .spec[DataSource, AuthUser]("MagnumAuthStore", policy => MagnumAuthStore.layer(policy))
      .provideShared(TestPostgres.migrated)
