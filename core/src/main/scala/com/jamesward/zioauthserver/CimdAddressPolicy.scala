package com.jamesward.zioauthserver

import zio.*

import java.net.{Inet4Address, Inet6Address, InetAddress, URI}

/**
 * Which Client ID Metadata Document URLs the server fetches. A CIMD `client_id` is a URL the server requests, so
 * without a check anyone could make it request the server's own or its network's private addresses (SSRF): HTTPS to
 * public addresses only, and with `allowLoopback` (development) HTTP or HTTPS to loopback addresses.
 *
 * The host is resolved here and again when the client connects, so a name whose answer changes in between (DNS
 * rebinding) isn't caught. The fetch doesn't follow redirects, so a public document can't send it elsewhere.
 */
object CimdAddressPolicy:

  enum Refusal derives CanEqual:
    case NotAUrl
    case Scheme(scheme: String)
    case NoHost
    case Unresolvable(host: String)
    case NotPublic(host: String, address: String)

  object Refusal:
    extension (r: Refusal)
      def message: String = r match
        case NotAUrl                  => "not a URL"
        case Scheme(s)                => s"scheme '$s' is not fetched"
        case NoHost                   => "no host"
        case Unresolvable(h)          => s"host '$h' doesn't resolve"
        case NotPublic(h, a)          => s"host '$h' is at $a, which is not a public address"

  /** Resolves the URL's host and checks every address it has. */
  def check(url: String, allowLoopback: Boolean): IO[Refusal, Unit] =
    for
      uri       <- ZIO.attempt(URI.create(url)).orElseFail(Refusal.NotAUrl)
      scheme     = Option(uri.getScheme).map(_.toLowerCase).getOrElse("")
      _         <- ZIO.unless(scheme == "https" || (scheme == "http" && allowLoopback))(ZIO.fail(Refusal.Scheme(scheme)))
      host      <- ZIO.fromOption(Option(uri.getHost).filter(_.nonEmpty)).orElseFail(Refusal.NoHost)
      addresses <- ZIO.attemptBlocking(InetAddress.getAllByName(host).toList).orElseFail(Refusal.Unresolvable(host))
      _         <- ZIO.foreachDiscard(addresses) { a =>
                     // Plain HTTP only to this machine: a request over the network would be readable and changeable.
                     val allowed = if a.isLoopbackAddress then allowLoopback else scheme == "https" && isPublic(a)
                     ZIO.unless(allowed)(ZIO.fail(Refusal.NotPublic(host, a.getHostAddress)))
                   }
    yield ()

  /** Not loopback, private, link-local (cloud metadata at 169.254.169.254), shared, multicast or reserved. */
  def isPublic(a: InetAddress): Boolean =
    !(a.isAnyLocalAddress || a.isLoopbackAddress || a.isLinkLocalAddress || a.isSiteLocalAddress || a.isMulticastAddress) &&
      (a match
        case v4: Inet4Address => publicV4(v4.getAddress.map(_ & 0xff))
        case v6: Inet6Address => publicV6(v6)
        case _                => false)

  private def publicV4(b: Array[Int]): Boolean =
    !(b(0) == 0 ||                               // 0.0.0.0/8 "this network"
      (b(0) == 100 && (b(1) & 0xc0) == 64) ||    // 100.64.0.0/10 shared address space (carrier NAT)
      (b(0) == 192 && b(1) == 0 && b(2) == 0) || // 192.0.0.0/24 protocol assignments
      (b(0) == 198 && (b(1) & 0xfe) == 18) ||    // 198.18.0.0/15 benchmarking
      b(0) >= 240)                               // 240.0.0.0/4 reserved, and broadcast

  private def publicV6(a: Inet6Address): Boolean =
    val b = a.getAddress.map(_ & 0xff)
    // NAT64 (64:ff9b::/96) and IPv4-compatible (::a.b.c.d) addresses reach the IPv4 address in their last four bytes.
    val nat64     = b(0) == 0x00 && b(1) == 0x64 && b(2) == 0xff && b(3) == 0x9b && b.slice(4, 12).forall(_ == 0)
    val embedded  = if nat64 || a.isIPv4CompatibleAddress then Some(InetAddress.getByAddress(b.takeRight(4).map(_.toByte))) else None
    val uniqueLocal = (b(0) & 0xfe) == 0xfc // fc00::/7
    !uniqueLocal && embedded.forall(isPublic)
