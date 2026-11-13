package com.jamesward.zioauthserver

import zio.*
import zio.http.*

/**
 * Sends the sign-in emails through Mailgun's HTTP API (`POST /v3/<domain>/messages`).
 *
 * @param baseUrl `https://api.mailgun.net` (US) or `https://api.eu.mailgun.net` (EU)
 * @param from    for example `"Factory <login@mg.example.com>"`, an address on `domain`
 */
final case class MailgunConfig(
    apiKey:  String,
    domain:  String,
    from:    String,
    baseUrl: String = "https://api.mailgun.net",
)

object MailgunConfig:
  /** `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, `MAILGUN_FROM`, and optional `MAILGUN_BASE_URL`. */
  val fromEnv: ZLayer[Any, Throwable, MailgunConfig] = ZLayer {
    def need(name: String) = System.env(name).someOrFail(new Exception(s"missing env var: $name"))
    for
      key    <- need("MAILGUN_API_KEY")
      domain <- need("MAILGUN_DOMAIN")
      from   <- need("MAILGUN_FROM")
      base   <- System.env("MAILGUN_BASE_URL")
    yield MailgunConfig(key, domain, from, base.getOrElse("https://api.mailgun.net"))
  }

final class MailgunMailer(cfg: MailgunConfig, client: Client) extends Mailer:

  private val url =
    URL.decode(s"${cfg.baseUrl.stripSuffix("/")}/v3/${cfg.domain}/messages").toOption

  def send(message: EmailMessage): IO[StoreError, Unit] =
    val form = Form(
      FormField.simpleField("from", cfg.from),
      FormField.simpleField("to", message.to.value),
      FormField.simpleField("subject", message.subject),
      FormField.simpleField("text", message.text),
    )
    val effect =
      for
        u    <- ZIO.fromOption(url).orElseFail(new Exception(s"invalid Mailgun URL for domain ${cfg.domain}"))
        req   = Request
                  .post(u, Body.fromURLEncodedForm(form))
                  .addHeader(Header.Authorization.Basic("api", cfg.apiKey))
        resp <- client.batched(req)
        _    <- ZIO.unless(resp.status.isSuccess)(
                  resp.body.asString.flatMap(b => ZIO.fail(new Exception(s"Mailgun answered ${resp.status.code}: ${b.take(300)}")))
                )
      yield ()
    // The key is in the Authorization header only; the message carries no secret beyond the link the user gets anyway.
    effect.mapError(t => StoreError.Internal(s"mail to ${message.to.value} not sent: ${t.getMessage}"))

object MailgunMailer:
  val layer: URLayer[MailgunConfig & Client, Mailer] =
    ZLayer.fromFunction((cfg: MailgunConfig, client: Client) => MailgunMailer(cfg, client))
