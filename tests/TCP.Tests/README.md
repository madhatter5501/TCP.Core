# TCP.Core regression tests

Run from the repository root:

```sh
dotnet run --project tests/TCP.Tests
```

This dependency-free test executable prints `PASS:` for each check and exits with an
exception on the first failure. Every test runs over in-memory Ethernet ports and a
fake clock; nothing touches a real network interface.

| File | Covers |
| --- | --- |
| `Program.cs` | The receive path of `EthernetStack`: malformed ICMP recovery, local MAC filtering, ARP replies and conflict probes, invalid source rejection, connected-route neighbor learning, cancellation during startup and idle receive |
| `StandardsTests.cs` | L2 and L3 rules: Ethernet padding, VLAN and LLC/SNAP; ARP cache expiry, resolution and address claim; routing, gateways and redirects; fragmentation and reassembly; IPv4 options and source routes; ICMP errors and when they must not be sent |
| `BridgeTests.cs`, `SpanningTreeTests.cs` | `LearningBridge` learning, ageing, flooding, VLAN access and trunk ports, link-local control frames, and IEEE 802.1D spanning tree |
| `TcpTests.cs`, `TcpTests.Extensions.cs` | TCP core protocol and each extension; see the [transport guide](../../src/TCP.Core/L4.Transport/README.md#verification) |
| `UdpTests.cs` | UDP codec and checksum, port binding, ICMP port unreachable, broadcast, connected sockets, fragmented datagrams |
| `Http2Tests.cs` | The HTTP/2 frame decoder |
| `TlsTests*.cs`, `Rfc8448.cs` | TLS against the RFC 8448 traces, our client against our server, and SslStream / OpenSSL interop; see the [TLS guide](../../src/TCP.Core/L5_7.Application/Tls/README.md#verification) |
| `TcpConnectionStream.cs` | Test helper: a thread-safe `Stream` over `TcpConnection` for SslStream interop |

OpenSSL interop runs only when OpenSSL 3 is installed. Native libpcap behavior and
real packet delivery need a live-interface run of `TCP.Host` (see its
[README](../../src/TCP.Host/README.md)).
