package com.jamesward.zioauthserver.testkit

import com.jamesward.zioauthserver.*
import zio.*
import zio.test.*

/** The in-memory store against the contract every store must pass. */
object InMemoryAuthStoreSpec extends ZIOSpecDefault:

  final case class TestUser(id: UserId, email: Email)

  given AccountView[TestUser] with
    def id(user: TestUser): UserId               = user.id
    def email(user: TestUser): Email             = user.email
    def scopes(user: TestUser): Set[OAuthScope] = Set(OAuthScope.of("role:user"))

  def spec =
    AuthStoreContract.spec[Any, TestUser](
      "InMemoryAuthStore",
      policy => InMemoryAuthStore.layer[TestUser]((id, email, _) => TestUser(id, email), (u, e) => u.copy(email = e), policy),
    )
