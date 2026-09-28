# L3 — Network

Namespace `TCP.L3.Network`. An IPv4 host with ICMPv4: local delivery, fragmentation
and reassembly, options, routing, and ICMP echo and errors. It is link-independent
and reaches the wire only through `IIPv4Link`; `EthernetStack` is the real link and
tests use fakes. Transport protocols register with it by protocol number, so L3 never
references L4.

```text
TcpHost / UdpHost          RegisterProtocol(6 or 17, handler), SendIPv4, Ticked, IcmpErrorReceived
        |
IPv4Host                   validate, reassemble, process options, deliver or answer with ICMP;
        |                  route, assign Identification, fragment on send
IIPv4Link                  SendToNeighbor / SendBroadcast / IsReady
        |
EthernetStack (L2)         ARP resolves the next hop, then calls FragmentForTransmit
```

It is a host, not a router: it never forwards datagrams between interfaces
(RFC 1122).

## Layout

| Folder | Contents |
| --- | --- |
| `.` | `IPv4Host` (receive and send paths, ICMP handling), `IIPv4Link` (the L2 seam) |
| `IPv4/` | `IPv4Packet` (codec), `IPv4Constants`, `IPv4ProtocolNumber`, `IPv4ProtocolDispatcher` and `IIPv4ProtocolHandler`, `RecentSendLog` (which ICMP errors to believe) |
| `IPv4/Fragmentation/` | `IPv4Fragmenter`, `IPv4Reassembler`, `IPv4IdentificationAllocator`, `IPv4FragmentField` |
| `IPv4/Options/` | `IPv4OptionReader`, `IPv4Options` (Record Route, Timestamp, source routes, copy-on-fragment), `IPv4OptionType` |
| `IPv4/Routing/` | `IPv4RouteTable`, `IPv4Route`, `IPv4Subnet` |
| `Icmp/` | `IcmpPacket`, `IcmpMessageType` and code enums, `IcmpEchoResponder`, `IcmpErrorQuote`, `IcmpErrorRateLimiter` |

The Internet checksum and the TCP/UDP pseudo-header live in `src/TCP.Core/Checksums`.
Every type carries XML documentation that explains its role and cites the RFC it
follows; start with `IPv4Host`.

## Using it

`EthernetStack` creates its host at `stack.IPv4`. Configure it before `Run`:

```csharp
// Off-subnet traffic goes through a gateway; a /0 network makes a default route.
stack.IPv4.Routes.Add(new IPv4Route(new IPv4Subnet(IPAddress.Any, IPAddress.Any), gateway, Mtu: 1500));
stack.IPv4.DefaultTimeToLive = 64;
stack.IPv4.EchoRequestAnswered += (packet, request) => Console.WriteLine($"ping from {packet.SourceAddress}");
stack.IPv4.IcmpErrorReceived += (packet, error) => Console.WriteLine($"ICMP {error.Type} from {packet.SourceAddress}");
```

Over any other link, construct `new IPv4Host(link, address, subnet, timeProvider, mtu)`
and call `Receive(datagram, linkBroadcast)` for each arriving datagram and `Tick()`
periodically. A transport registers with `RegisterProtocol(protocol, handler)` and
sends with `SendIPv4(packet)`, which returns false when there is no route or Don't
Fragment prevents the send. All calls run on the link's single protocol thread.

## Implemented

| Area | Behavior |
| --- | --- |
| Receive | Header, length and checksum validation; invalid sources dropped; delivery to our address, the subnet broadcast and limited broadcast; TTL is not decremented for local delivery |
| Fragmentation | Fragments to the route MTU; only copied options repeat in later fragments; Don't Fragment makes an oversized local send fail; Identification allocation per RFC 6864 |
| Reassembly | Out-of-order and duplicate fragments; overlaps rejected and never dispatched; ECN codepoints combined (RFC 3168 5.3); 128 pending assemblies with a 60-second timeout that returns ICMP Time Exceeded |
| Options | Record Route, Internet Timestamp (all three flag forms), loose and strict source routes; a completed source route is reversed for the reply, an incomplete one is refused rather than forwarded; malformed options draw Parameter Problem with a pointer |
| Routing | Connected subnet plus up to 1,024 static routes with longest-prefix match and metrics; ICMP Redirects accepted only from the current gateway and expiring after 10 minutes; a gateway that fails ARP is avoided for 30 seconds |
| Path size | Route MTU, capped at 576 bytes for off-subnet destinations since their path MTU is unknown |
| ICMP | Echo replies; Destination Unreachable (protocol, port, fragmentation needed, source route failed), Time Exceeded for reassembly, Parameter Problem; at most 10 errors a second; never about broadcasts, non-first fragments or other ICMP errors (RFC 1122 3.2.2) |
| ICMP received | Errors are believed only when they quote a datagram we sent recently (RFC 5927 4.1), then raised as `IcmpErrorReceived` for TCP and UDP |

## Scope

This is a tested learning implementation, not a certified one. Not implemented:
router forwarding (RFC 1812) and router-generated messages such as TTL expired in
transit, multicast group membership and IGMP, DHCP, and IPv6. The TCP segment codec
can checksum IPv6 segments, but no IPv6 network layer exists.

For how MTU here relates to TCP's MSS, see
[docs/standards.md](../../../docs/standards.md#mtu-versus-mss).

## Verification

```sh
dotnet run --project tests/TCP.Tests
```

`StandardsTests.cs` covers routing and gateways, fragmentation and reassembly
(order, overlap, duplicates, timeout), Don't Fragment, options and source routes,
redirects, and when ICMP errors must and must not be sent. `Program.cs` checks
malformed ICMP recovery and invalid sources on the receive path. The Explorer's
transmission lab runs ping, fragmentation and DF scenarios through this code.

References: [IPv4 (RFC 791)](https://www.rfc-editor.org/rfc/rfc791.html),
[ICMP (RFC 792)](https://www.rfc-editor.org/rfc/rfc792.html),
[host requirements (RFC 1122)](https://www.rfc-editor.org/rfc/rfc1122.html),
[path MTU (RFC 1191)](https://www.rfc-editor.org/rfc/rfc1191.html),
[IPv4 ID field (RFC 6864)](https://www.rfc-editor.org/rfc/rfc6864.html).
