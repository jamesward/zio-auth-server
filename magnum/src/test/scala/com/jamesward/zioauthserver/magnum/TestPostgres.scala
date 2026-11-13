package com.jamesward.zioauthserver.magnum

import com.dimafeng.testcontainers.PostgreSQLContainer
import org.postgresql.ds.PGSimpleDataSource
import org.testcontainers.utility.DockerImageName
import zio.*

import javax.sql.DataSource

/** A Postgres container for a spec, started and stopped with its layer. */
object TestPostgres:

  final case class Db(container: PostgreSQLContainer, dataSource: DataSource):
    /** A plain JDBC connection, for checking what the migrations made. */
    def query[A](sql: String)(read: java.sql.ResultSet => A): Task[List[A]] =
      ZIO.attemptBlocking {
        val conn = dataSource.getConnection
        try
          val rs  = conn.createStatement().executeQuery(sql)
          val out = List.newBuilder[A]
          while rs.next() do out += read(rs)
          out.result()
        finally conn.close()
      }

  val db: ZLayer[Any, Throwable, Db] = ZLayer.scoped {
    ZIO
      .acquireRelease(ZIO.attemptBlocking {
        val c = PostgreSQLContainer(dockerImageNameOverride = DockerImageName.parse("postgres:17-alpine"))
        c.start()
        c
      })(c => ZIO.attemptBlocking(c.stop()).ignoreLogged)
      .map { c =>
        val ds = PGSimpleDataSource()
        ds.setUrl(c.jdbcUrl)
        ds.setUser(c.username)
        ds.setPassword(c.password)
        Db(c, ds)
      }
  }

  /** A migrated `auth` schema. */
  val migrated: ZLayer[Any, Throwable, DataSource] =
    db >>> ZLayer(ZIO.serviceWithZIO[Db](d => AuthSchema.migrate(d.dataSource).as(d.dataSource)))
