package com.jamesward.zioauthserver

import zio.*

trait SecureRandomGen:
  def nextBytes(length: Int): UIO[Array[Byte]]
  def nextUUID: UIO[java.util.UUID]

object SecureRandomGen:

  val live: ULayer[SecureRandomGen] =
    ZLayer.succeed(SecureRandomGenLive(new java.security.SecureRandom()))

final class SecureRandomGenLive(sr: java.security.SecureRandom) extends SecureRandomGen:
  def nextBytes(length: Int): UIO[Array[Byte]] =
    ZIO.succeed {
      val buf = Array.ofDim[Byte](length)
      sr.nextBytes(buf)
      buf
    }

  def nextUUID: UIO[java.util.UUID] =
    nextBytes(16).map { bytes =>
      // RFC 4122 §4.4: set the version (4) and variant (10) bits before composing the UUID's MSB/LSB longs.
      bytes(6) = ((bytes(6) & 0x0f) | 0x40).toByte
      bytes(8) = ((bytes(8) & 0x3f) | 0x80).toByte
      val msb = java.nio.ByteBuffer.wrap(bytes, 0, 8).getLong
      val lsb = java.nio.ByteBuffer.wrap(bytes, 8, 8).getLong
      new java.util.UUID(msb, lsb)
    }
