package com.jamesward.zioauthserver.magnum

import org.flywaydb.core.Flyway
import zio.*
import zio.test.*

/** The migrations live in their own schema and history, next to an app's own Flyway. */
object AuthSchemaSpec extends ZIOSpecDefault:

  private def tablesIn(db: TestPostgres.Db, schema: String): Task[Set[String]] =
    db.query(s"select table_name from information_schema.tables where table_schema = '$schema'")(_.getString(1)).map(_.toSet)

  def spec = suite("AuthSchema")(
    test("migrates into `auth`, with its history there, and a second run applies nothing") {
      for
        db     <- ZIO.service[TestPostgres.Db]
        first  <- AuthSchema.migrate(db.dataSource)
        second <- AuthSchema.migrate(db.dataSource)
        tables <- tablesIn(db, "auth")
        public <- tablesIn(db, "public")
      yield assertTrue(
        first == 1,
        second == 0,
        tables.contains("flyway_schema_history"),
        tables.contains("users"),
        tables.contains("passkeys"),
        !public.contains("flyway_schema_history"),
      )
    },
    test("an app's own Flyway in `public` runs alongside, and its tables can refer to auth.users") {
      for
        db      <- ZIO.service[TestPostgres.Db]
        _       <- AuthSchema.migrate(db.dataSource)
        applied <- ZIO.attemptBlocking(
                     Flyway
                       .configure(getClass.getClassLoader)
                       .dataSource(db.dataSource)
                       .locations("classpath:app-migrations")
                       .load()
                       .migrate()
                       .migrationsExecuted
                   )
        public  <- tablesIn(db, "public")
      yield assertTrue(applied == 1, public.contains("flyway_schema_history"), public.contains("projects"))
    },
    test("another schema name works, and an unsafe one is refused") {
      for
        db      <- ZIO.service[TestPostgres.Db]
        n       <- AuthSchema.migrate(db.dataSource, "auth_other")
        tables  <- tablesIn(db, "auth_other")
        refused <- AuthSchema.migrate(db.dataSource, "auth; drop table x").either
      yield assertTrue(n == 1, tables.contains("sessions"), refused.isLeft)
    },
  ).provideShared(TestPostgres.db) @@ TestAspect.sequential
