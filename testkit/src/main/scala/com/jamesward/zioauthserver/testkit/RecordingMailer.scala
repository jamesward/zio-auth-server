package com.jamesward.zioauthserver.testkit

import com.jamesward.zioauthserver.*
import zio.*

/** A [[Mailer]] that keeps the messages instead of sending them, and logs each one so a dev run shows the link. */
final class RecordingMailer private (messages: Ref[Chunk[EmailMessage]]) extends Mailer:

  def send(message: EmailMessage): IO[StoreError, Unit] =
    messages.update(_ :+ message) *>
      ZIO.logInfo(s"dev mail to ${message.to.value}: ${message.subject}\n${message.text}")

  def sent: UIO[Chunk[EmailMessage]] = messages.get

  def lastTo(email: Email): UIO[Option[EmailMessage]] =
    messages.get.map(_.findLast(_.to == email))

object RecordingMailer:

  def make: UIO[RecordingMailer] = Ref.make(Chunk.empty[EmailMessage]).map(new RecordingMailer(_))

  /** Provides both the [[Mailer]] and the [[RecordingMailer]], so a test can read what was sent. */
  val layer: ULayer[Mailer & RecordingMailer] =
    ZLayer.fromZIOEnvironment(make.map(m => ZEnvironment[Mailer, RecordingMailer](m, m)))
