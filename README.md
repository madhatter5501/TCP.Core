# TCP

A TCP/IP stack written from scratch in C# (.NET 10) to learn how the layers
actually work, from Ethernet frames through TLS. Each layer is plain, readable code
with XML documentation that cites the RFC or IEEE standard it follows, plus an
interactive Explorer that runs the real code and shows every byte.

This is a tested learning implementation, not a production or certified stack. It
does not replace `System.Net.Sockets`. See [docs/STANDARDS.md](docs/STANDARDS.md)
for what is and isn't implemented at each layer.

## The layers

All protocol code lives in `src/TCP.Core`, one folder per layer:

| Layer | Folder | What's there | Guide |
| --- | --- | --- | --- |
| L1 Physical | `L1.Physical` | `IPacketInterface`: whole frames in and out | [README](src/TCP.Core/L1.Physical/README.md) |
| L2 Link | `L2.Link` | Ethernet and 802.1Q, ARP and address conflict detection, learning bridge with spanning tree | [README](src/TCP.Core/L2.Link/README.md) |
| L3 Network | `L3.Network` | IPv4 host: fragmentation, options, routing, ICMPv4 | [README](src/TCP.Core/L3.Network/README.md) |
| L4 Transport | `L4.Transport` | TCP (RFC 9293 plus modern extensions) and UDP | [README](src/TCP.Core/L4.Transport/README.md) |
| L5–7 Application | `L5_7.Application` | TLS 1.3 and 1.2; HTTP/2 frame decoder | [README](src/TCP.Core/L5_7.Application/README.md), [TLS](src/TCP.Core/L5_7.Application/Tls/README.md) |

Two folders sit outside the layers: `Stack/` holds `EthernetStack`, which assembles
a complete host on one interface (`stack.IPv4`, `stack.Tcp`, `stack.Udp`), and
`Checksums/` holds the Internet checksum and the TCP/UDP pseudo-header.

```csharp
var stack = new EthernetStack(port, address, mac, new IPv4Subnet(address, mask));
using var listener = stack.Tcp.Listen(8080, connection => { /* ... */ });
stack.Run(cancellationToken); // all protocol work runs on this thread
```

## Projects

| Project | Purpose |
| --- | --- |
| `src/TCP.Core` | The stack itself; no dependencies beyond .NET |
| `src/TCP.Explorer` | ASP.NET Core + React app for learning the layers and running real transmissions ([README](src/TCP.Explorer/README.md)) |
| `src/TCP.Host` | Command line: offline diagnostics, a host on a real NIC, or a bridge ([README](src/TCP.Host/README.md)) |
| `src/TCP.Networking.Pcap` | `IPacketInterface` over libpcap/BPF on macOS, and `PcapNetworkConfiguration` to build a stack on a real interface |
| `src/TCP.Transport.Kestrel` | Lets ASP.NET Core's Kestrel serve HTTP over TCP.Core (`AddTcpCoreTransport`, `TcpCoreEndPoint`) |
| `tests/TCP.Tests` | Protocol regression tests for every layer ([README](tests/TCP.Tests/README.md)) |
| `tests/TCP.Explorer.Tests` | The Explorer's real-code transmission scenarios (ping, fragmentation, checksum faults, TCP) |
| `tests/TCP.Transport.Kestrel.Tests` | HTTP/1.1 and HTTP/2 through Kestrel over a virtual Ethernet link |

## Getting started

Requires the .NET 10 SDK; Node.js to build the Explorer's UI.

```sh
dotnet run --project src/TCP.Explorer
```

Then open <http://localhost:5097>. Nothing touches your real network: the Explorer's
transmissions run between two in-memory hosts.

Run the tests (each project is a plain executable):

```sh
dotnet run --project tests/TCP.Tests
dotnet run --project tests/TCP.Explorer.Tests
dotnet run --project tests/TCP.Transport.Kestrel.Tests
npm --prefix src/TCP.Explorer/ClientApp test
```

## Docs

- [docs/STANDARDS.md](docs/STANDARDS.md): scope per layer, and MTU versus MSS
- [docs/arp-cache.md](docs/arp-cache.md): designing the ARP cache
- [docs/TCP-WEB-SERVER-PLAN.md](docs/TCP-WEB-SERVER-PLAN.md): serving the Explorer through TCP.Core
