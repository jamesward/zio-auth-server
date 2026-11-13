package com.jamesward.zioauthserver

import zio.*
import zio.test.*

import java.net.InetAddress

// Literal addresses only, so nothing here needs DNS.
object CimdAddressPolicySpec extends ZIOSpecDefault:

  import CimdAddressPolicy.Refusal

  private def public(a: String): Boolean = CimdAddressPolicy.isPublic(InetAddress.getByName(a))

  private def check(url: String, allowLoopback: Boolean = false): UIO[Either[Refusal, Unit]] =
    CimdAddressPolicy.check(url, allowLoopback).either

  def spec = suite("CimdAddressPolicy")(
    test("public addresses are public") {
      assertTrue(public("8.8.8.8"), public("93.184.215.14"), public("2606:4700:4700::1111"))
    },
    test("loopback, private, link-local, shared, reserved and unique-local addresses are not") {
      val notPublic = List(
        "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "192.0.0.1",
        "198.18.0.1", "240.0.0.1", "255.255.255.255", "224.0.0.1", "::1", "::", "fe80::1", "fd00::1",
        "::ffff:10.0.0.1", "64:ff9b::a00:1",
      )
      assertTrue(notPublic.filter(public).isEmpty)
    },
    test("HTTPS to a public address is fetched; anything else is refused") {
      for
        ok         <- check("https://8.8.8.8/client.json")
        http       <- check("http://8.8.8.8/client.json")
        ftp        <- check("ftp://8.8.8.8/client.json")
        privateIp  <- check("https://10.0.0.1/client.json")
        loopback   <- check("https://127.0.0.1/client.json")
        noHost     <- check("https:///client.json")
      yield assertTrue(
        ok.isRight,
        http == Left(Refusal.Scheme("http")),
        ftp == Left(Refusal.Scheme("ftp")),
        privateIp == Left(Refusal.NotPublic("10.0.0.1", "10.0.0.1")),
        loopback == Left(Refusal.NotPublic("127.0.0.1", "127.0.0.1")),
        noHost == Left(Refusal.NoHost),
      )
    },
    test("with allowLoopback, HTTP and HTTPS reach loopback, and HTTP still reaches nothing else") {
      for
        http       <- check("http://127.0.0.1:8080/client.json", allowLoopback = true)
        https      <- check("https://[::1]/client.json", allowLoopback = true)
        httpPublic <- check("http://8.8.8.8/client.json", allowLoopback = true)
        privateIp  <- check("https://192.168.1.1/client.json", allowLoopback = true)
      yield assertTrue(
        http.isRight,
        https.isRight,
        httpPublic == Left(Refusal.NotPublic("8.8.8.8", "8.8.8.8")),
        privateIp == Left(Refusal.NotPublic("192.168.1.1", "192.168.1.1")),
      )
    },
  )
