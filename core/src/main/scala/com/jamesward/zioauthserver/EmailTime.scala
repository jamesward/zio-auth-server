package com.jamesward.zioauthserver

import java.time.format.DateTimeFormatter
import java.time.{Duration, Instant, ZoneOffset}
import java.util.Locale

/** Human-readable times for sign-in emails. */
object EmailTime:

  private val dateTimeFormatter =
    DateTimeFormatter
      .ofPattern("MMM d, uuuu 'at' h:mm a 'UTC'", Locale.ENGLISH)
      .withZone(ZoneOffset.UTC)

  def format(instant: Instant): String =
    dateTimeFormatter.format(instant)

  def describeExpiration(now: Instant, expiresAt: Instant): String =
    val seconds = Duration.between(now, expiresAt).getSeconds
    if seconds <= 0 then "has expired"
    else s"expires in ${formatDuration(seconds)}"

  private def formatDuration(seconds: Long): String =
    val (value, unit) =
      if seconds >= 86400 then (seconds / 86400, "day")
      else if seconds >= 3600 then (seconds / 3600, "hour")
      else if seconds >= 60 then (seconds / 60, "minute")
      else (seconds, "second")
    s"$value $unit${if value == 1 then "" else "s"}"
