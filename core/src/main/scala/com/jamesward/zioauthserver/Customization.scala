package com.jamesward.zioauthserver

import zio.*
import zio.http.*
import zio.http.template2.*

import java.time.Instant

/** The sign-in pages. Applications supply their own to match their look; [[Pages.default]] is plain HTML. */
trait Pages[U]:
  def home(user: U): Dom
  def login(flash: Option[String], returnTo: Option[String]): Dom
  def otp(email: Email, returnTo: Option[String], error: Option[String]): Dom
  def logoutConfirm(user: U, csrf: CsrfToken): Dom
  def magicLinkSent: Dom
  def invalidLink: Dom

object Pages:

  def default[U](using view: AccountView[U]): Pages[U] =
    new Pages[U]:
      private def layout(titleStr: String)(content: Dom*): Dom =
        html(
          Dom.attr("lang", "en"),
          head(
            meta(charset := "utf-8"),
            meta(name := "viewport", Dom.attr("content", "width=device-width, initial-scale=1")),
            Dom.element("title")(titleStr),
          ),
          Dom.element("body")(Dom.fragment(content*)),
        )

      private def hidden(fieldName: String, value: String): Dom =
        Dom.element("input")(Dom.attr("type", "hidden"), Dom.attr("name", fieldName), Dom.attr("value", value))

      private def returnToField(returnTo: Option[String]): Dom =
        returnTo.fold(Dom.empty)(hidden("return_to", _))

      def home(user: U): Dom =
        layout("Signed in")(
          h1("Signed in"),
          p("as ", view.email(user).value),
          a(href := "/logout", "Sign out"),
        )

      def login(flash: Option[String], returnTo: Option[String]): Dom =
        layout("Sign in")(
          h1("Sign in"),
          flash.fold(Dom.empty)(msg => p(Dom.attr("role", "status"), msg)),
          Dom.element("form")(
            Dom.attr("method", "post"),
            Dom.attr("action", "/auth/email/start"),
            returnToField(returnTo),
            label(Dom.attr("for", "email"), "Email"),
            Dom.element("input")(
              Dom.attr("type", "email"),
              Dom.attr("name", "email"),
              Dom.attr("id", "email"),
              Dom.attr("required", "required"),
              Dom.attr("autocomplete", "email"),
            ),
            Dom.element("button")(Dom.attr("type", "submit"), "Email me a sign-in link"),
            Dom.element("button")(
              Dom.attr("type", "submit"),
              Dom.attr("formaction", "/auth/otp/start"),
              s"Email me a ${OtpCode.length}-digit code",
            ),
          ),
        )

      def otp(email: Email, returnTo: Option[String], error: Option[String]): Dom =
        layout("Enter your code")(
          h1("Enter your code"),
          error.fold(Dom.empty)(msg => p(Dom.attr("role", "alert"), msg)),
          p(s"We emailed a ${OtpCode.length}-digit code to ", email.value, "."),
          Dom.element("form")(
            Dom.attr("method", "post"),
            Dom.attr("action", "/auth/otp/verify"),
            returnToField(returnTo),
            label(Dom.attr("for", "code"), "Sign-in code"),
            Dom.element("input")(
              Dom.attr("type", "text"),
              Dom.attr("name", "code"),
              Dom.attr("id", "code"),
              Dom.attr("required", "required"),
              Dom.attr("inputmode", "numeric"),
              Dom.attr("autocomplete", "one-time-code"),
            ),
            Dom.element("button")(Dom.attr("type", "submit"), "Sign in"),
          ),
          a(href := "/login", "Use a different email address"),
        )

      def logoutConfirm(user: U, csrf: CsrfToken): Dom =
        layout("Sign out")(
          h1("Sign out"),
          p("Sign out of ", view.email(user).value, "?"),
          Dom.element("form")(
            Dom.attr("method", "post"),
            Dom.attr("action", "/auth/logout"),
            hidden("_csrf", csrf.value),
            Dom.element("button")(Dom.attr("type", "submit"), "Sign out"),
          ),
        )

      val magicLinkSent: Dom =
        layout("Check your inbox")(h1("Check your inbox"), p("We emailed you a sign-in link."))

      val invalidLink: Dom =
        login(Some("That sign-in link is no longer valid. Enter your email to get a fresh one."), None)

/** The sign-in emails. */
trait Messages:
  def magicLink(to: Email, link: String, now: Instant, expiresAt: Instant): EmailMessage
  def otpCode(to: Email, code: OtpCode, now: Instant, expiresAt: Instant): EmailMessage

object Messages:

  /** The default emails, naming `product` in the subject. */
  def default(product: String): Messages =
    new Messages:
      def magicLink(to: Email, link: String, now: Instant, expiresAt: Instant): EmailMessage =
        EmailMessage(
          to,
          s"Sign in to $product",
          s"""Click the link below to sign in. It ${EmailTime.describeExpiration(now, expiresAt)}.
             |
             |$link
             |
             |If you did not request this, you can safely ignore the email.
             |""".stripMargin,
        )

      def otpCode(to: Email, code: OtpCode, now: Instant, expiresAt: Instant): EmailMessage =
        EmailMessage(
          to,
          s"Your $product sign-in code",
          s"""Your sign-in code is ${code.value}
             |
             |Enter it on the sign-in page. It ${EmailTime.describeExpiration(now, expiresAt)}.
             |
             |If you did not request this, you can safely ignore the email.
             |""".stripMargin,
        )

/** What `/oauth/authorize` knows when it is about to issue a code for a signed-in user. */
final case class AuthorizeContext[U](
    user:        U,
    client:      OAuthClient,
    scopes:      Set[OAuthScope],
    resource:    Option[ResourceIndicator],
    /** The un-parsed `resource` query value, which keeps any path that [[ResourceIndicator]] drops. */
    rawResource: Option[String],
    request:     Request,
)

enum GateDecision:
  case Allow
  /** Answer the authorize request with this response instead of a code, for example a redirect to an onboarding page. */
  case Respond(response: Response)

object GateDecision:
  // Response has no CanEqual; matching on `Allow` only compares the case, never the response.
  given CanEqual[GateDecision, GateDecision] = CanEqual.derived

/**
 * An application's own checks before a code is issued to a signed-in user: terms of service, a purchase, an invite.
 * Failures are logged and answered with a server error.
 */
trait AuthorizeGate[-R, U]:
  def check(ctx: AuthorizeContext[U]): RIO[R, GateDecision]

object AuthorizeGate:
  def allowAll[U]: AuthorizeGate[Any, U] = _ => ZIO.succeed(GateDecision.Allow)
