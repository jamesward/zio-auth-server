package com.jamesward.zioauthserver.magnum

import org.flywaydb.core.Flyway
import zio.*

import javax.sql.DataSource

/**
 * The store's tables, migrated separately from the app's own. It runs its own Flyway with:
 *   - the migrations shipped in this jar (`classpath:com/jamesward/zioauthserver/magnum/migrations`), not the app's
 *     `db/migration`, so the two version sequences never meet;
 *   - the store's schema (default `auth`) as Flyway's only schema, so Flyway creates it, runs the migrations in it, and
 *     keeps its history table there (`auth.flyway_schema_history`), apart from the app's history in `public`.
 *
 * Call it where the app runs its own migrations (for example a Heroku release phase), before or after the app's:
 *
 * {{{
 * AuthSchema.migrate(dataSource) *> MyAppFlyway.migrate(dataSource)
 * }}}
 *
 * The app's migrations may refer to `auth.users(id)`; run `AuthSchema.migrate` first then.
 */
object AuthSchema:

  val DefaultSchema = "auth"

  val MigrationsLocation = "classpath:com/jamesward/zioauthserver/magnum/migrations"

  /** Applies pending migrations; returns how many ran. */
  def migrate(dataSource: DataSource, schema: String = DefaultSchema): Task[Int] =
    ZIO.fromEither(validSchema(schema).left.map(new IllegalArgumentException(_))) *>
      ZIO.attemptBlocking {
        Flyway
          .configure(getClass.getClassLoader)
          .dataSource(dataSource)
          .schemas(schema)
          .defaultSchema(schema)
          .createSchemas(true)
          .locations(MigrationsLocation)
          .load()
          .migrate()
          .migrationsExecuted
      }

  /** A schema name is spliced into SQL, so only plain lower-case identifiers are accepted. */
  def validSchema(schema: String): Either[String, String] =
    Either.cond(schema.matches("[a-z_][a-z0-9_]{0,62}"), schema, s"invalid schema name '$schema': use [a-z_][a-z0-9_]*")
