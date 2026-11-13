package com.jamesward.zioauthserver.testkit

import com.jamesward.zioauthserver.*
import zio.*
import zio.test.*

/** A store that implements only `AuthStore` (like toolbook's API-backed one) runs the `AuthStore` suites on their own. */
object AuthStoreOnlySpec extends ZIOSpecDefault:

  final case class TestUser(id: UserId, email: Email)

  given AccountView[TestUser] with
    def id(user: TestUser): UserId               = user.id
    def email(user: TestUser): Email             = user.email
    def scopes(user: TestUser): Set[OAuthScope] = Set.empty

  /** Only `AuthStore`: nothing else of the in-memory store is visible through it. */
  final class OnlyAuthStore(underlying: AuthStore[TestUser]) extends AuthStore[TestUser]:
    export underlying.*

  private val onlyAuthStore: ULayer[AuthStore[TestUser]] =
    ZLayer(
      InMemoryAuthStore
        .make[TestUser]((id, e, _) => TestUser(id, e), (u, e) => u.copy(email = e))
        .map(s => OnlyAuthStore(s): AuthStore[TestUser])
    )

  def spec = AuthStoreContract.authStore[Any, TestUser]("AuthStore only", onlyAuthStore)
