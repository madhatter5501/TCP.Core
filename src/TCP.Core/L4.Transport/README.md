# L4 — Transport

`TCP.L4.Transport.Tcp` implements an IPv4 TCP endpoint with the common modern
extensions; `TCP.L4.Transport.Udp` implements UDP beside it (see [UDP](#udp)). Each
`EthernetStack` has a `TcpHost` at `stack.Tcp` and a `UdpHost` at `stack.Udp`.
`TcpHost` registers itself with its `IPv4Host` for IP protocol 6 and runs its timers
from `IPv4Host.Ticked`, so L3 never references L4. Over any other `IIPv4Link`, create
one with `new TcpHost(ipv4Host, settings)`. The transport sends through `SendIPv4`
and never depends on Ethernet or ARP. This library does not replace
`System.Net.Sockets` or install an operating-system network stack.

## Layout

| Folder | Contents |
| --- | --- |
| `Tcp/` | `TcpHost` (demultiplexing, listeners, ports, ICMP routing), `TcpListener`, `TcpSettings`, `SequenceNumber`, `ConnectionKey`, `TcpMessages` |
| `Tcp/Connections/` | `TcpConnection`, split by concern: API and state (`TcpConnection.cs`), `.Receiving`, `.Sending`, `.Recovery`, `.Options`, `.Timers`; `TcpState` |
| `Tcp/Segments/` | Wire codec: `TcpSegment`, `TcpWireFormat`, `TcpFlags`, option reading, writing and decoding (`TcpOptions`) |
| `Tcp/Reliability/` | Retransmission queue, receive buffer, send window, RTT estimator, persist timer, RACK, tail loss probe, ISN generator, challenge-ACK limiter |
| `Tcp/Congestion/` | `CongestionController` with NewReno and CUBIC subclasses |
| `Tcp/Handshake/` | SYN cookies and Fast Open cookies |
| `Tcp/Authentication/` | TCP-AO and MD5 signing (`SegmentAuthenticator`, `AesCmac`, `TcpAuthenticationKey`) |
| `Tcp/Buffers/` | `ByteQueue`, the send and receive byte store |
| `Udp/` | `UdpHost`, `UdpSocket`, `UdpDatagram` |

Every type and member carries XML documentation that explains its role and cites
the RFC it follows; start with `TcpHost` and `TcpConnection`.

## API and threading

All connection operations, timers and callbacks must execute on the stack's single
protocol thread. Configure listeners before `EthernetStack.Run`; initiate outbound
connections from `AddressClaimed` or another callback on that thread, or hand work
over with `EthernetStack.TrySchedule`. Do not call `Send`, `Read` or `Close` directly
from another UI or worker thread. Callbacks must be short and must not throw. A
callback may abort its connection; further packet processing and notifications then
stop. Retain returned listeners and dispose them to stop accepting; established
connections survive listener disposal.

```csharp
// Configure before stack.Run(cancellationToken).
using var listener = stack.Tcp.Listen(8080, connection =>
{
    connection.DataAvailable += stream =>
    {
        var bytes = new byte[stream.Available];
        stream.Read(bytes);
        // Small echo example. Real applications retain any suffix not accepted
        // by Send and retry from SendReady when buffer capacity becomes available.
        var accepted = stream.Send(bytes);
        if (accepted != bytes.Length) stream.Abort();
    };
    connection.ReadClosed += stream => stream.Close();
});
```

For active open, use `stack.Tcp.Connect(peerAddress, peerPort)` and subscribe to
`Connected`, `DataAvailable`, `ReadClosed` and `StateChanged`. Check `State` after
`Connect`: local delivery can establish or refuse a connection synchronously. The
optional local port defaults to a free ephemeral port (49152–65535). Passing
`initialData` sends it on the SYN when a Fast Open cookie for that server is cached,
and after the handshake otherwise.

- `Send(ReadOnlySpan<byte>)` copies up to the free send capacity and returns the
  accepted count. This does not mean the peer application has read it.
- `SendUrgent(ReadOnlySpan<byte>)` sends urgent data: delivered inline, with the
  urgent pointer marking its end.
- `Read(Span<byte>)` returns buffered stream bytes and advertises freed receive
  space. `Available == 0 && PeerClosed` means EOF. Message boundaries are the
  application's responsibility.
- `Close()` half-closes writes after pending data; the application can keep reading
  and the peer can still send. `CloseRead()` declares that nothing more will be read:
  unread or later data resets the connection rather than being dropped silently.
  `Abort()` resets immediately.
- `SendReady` signals newly acknowledged send capacity while writes remain open.
- `FailureReason` describes refusal, reset, local abort, retry exhaustion, user
  timeout or keep-alive failure.
- `NoDelay` disables Nagle's small-write coalescing. `KeepAlive` and `UserTimeout`
  can be set per connection.
- `UrgentDataEnd` and `UrgentDataAvailable` expose incoming urgent indications; those
  bytes are delivered inline, not as a separate out-of-band stream.
- Diagnostics: `CongestionWindow`, `SlowStartThreshold`, `SmoothedRoundTripTime`,
  `RetransmissionTimeoutSeconds`, `Retransmissions`, `SpuriousRetransmissionTimeouts`,
  `NextSendSequence`, `NextReceiveSequence`, `ReceiveWindow`, `LastNetworkError`.

`TcpHost.AddAuthenticationKey` protects connections with a peer by TCP-AO or an MD5
signature; unsigned or wrongly signed segments from that peer are dropped.

## Settings

`TcpSettings` is host-wide policy, passed to `new TcpHost(ipv4Host, settings)` and
validated there. Negotiated extensions take effect only when the peer also offers
them on its SYN, so enabling one never breaks a peer that lacks it.

| Setting | Default | Effect |
| --- | --- | --- |
| `DelayedAcknowledgments`, `DelayedAckTimeout` | on, 200 ms | ACK every second full segment or after the timeout (at most 500 ms) |
| `WindowScaling` | on | Windows beyond 64 KiB (RFC 7323 2) |
| `Timestamps` | on | RTT measurement, PAWS, spurious-timeout detection (RFC 7323, RFC 3522) |
| `SelectiveAcknowledgments` | on | SACK and D-SACK (RFC 2018, RFC 2883) |
| `ExplicitCongestionNotification` | on | ECN (RFC 3168) |
| `CongestionControl` | `Cubic` | `Cubic` (RFC 9438) or `NewReno` (RFC 5681, RFC 6582) |
| `InitialWindowSegments` | 10 | Initial congestion window (RFC 6928) |
| `RecentAcknowledgment` | on | RACK-TLP loss detection and tail loss probes when SACK is in use (RFC 8985) |
| `SynCookies` | on | Stateless SYN-ACKs once a listener's backlog is full (RFC 4987) |
| `FastOpen` | on | TCP Fast Open for listeners and cached-cookie clients (RFC 7413) |
| `KeepAlive`, `KeepAliveIdle`, `KeepAliveInterval`, `KeepAliveProbes` | off, 2 h, 75 s, 9 | Idle probing (RFC 1122 4.2.3.6); off by default as that RFC requires |
| `UserTimeout`, `AcceptPeerUserTimeout`, `UserTimeoutLimits` | none, off, 100 s–1 h | User timeout and its option (RFC 5482) |
| `BlackHoleDetection` | on | Smaller segments after repeated timeouts without ICMP (RFC 4821) |
| `PathMtuRaiseInterval` | 10 min | When a lowered path MTU is tried again (RFC 1191 6.3) |

`EthernetStack` currently creates its `TcpHost` with `TcpSettings.Default`; to use
other settings over Ethernet, construct the host yourself over the stack's `IPv4`.

## Implemented

| Area | Behavior |
| --- | --- |
| Codec | Network byte order, variable header length, validated options (MSS, window scale, SACK-permitted, SACK, timestamps, user timeout, Fast Open, TCP-AO, MD5), IPv4 and IPv6 pseudo-header checksums, odd-length payloads |
| Open | Active, passive and simultaneous open; bounded backlog with SYN-cookie overflow; closed-port RST; keyed, time-varying ISNs (RFC 6528); Fast Open data on SYN; a new SYN may replace a TIME-WAIT connection |
| Stream | Full duplex, modulo-2^32 sequence arithmetic, duplicate suppression, bounded out-of-order reassembly, partial-ACK trimming, urgent send and receive |
| Flow control | Scaled receive windows up to the buffer capacity, read-driven window updates, zero-window persist probes, receiver and sender silly-window avoidance (RFC 1122 4.2.3.3–4), delayed ACKs |
| Loss recovery | RFC 6298 RTO (1–60 s) with Karn sampling and backoff, fast retransmit, NewReno partial-ACK recovery, limited transmit (RFC 3042), SACK-based recovery (RFC 6675), RACK-TLP, tail loss probes, spurious-timeout undo via timestamps, resending all presumed-lost segments after a timeout |
| Congestion | CUBIC or NewReno windows, ten-segment initial window, restart after idle (RFC 5681 4.1), ECN reacting once per round trip |
| Segmentation | MSS negotiation (536-byte IPv4 default when absent), route MTU and peer MSS limits, DF-marked packets, validated ICMP fragmentation-needed, splitting in-flight data after an MTU drop, black-hole detection, periodic MTU raise |
| Close | Half-close, `CloseRead`, simultaneous close, retransmitted FIN, all closing states, 4-minute TIME-WAIT (2 × 120 s MSL), TIME-WAIT RST ignored, FIN-WAIT-2 cleanup |
| Security | Exact-sequence reset acceptance and rate-limited challenge ACKs (RFC 5961), PAWS, TCP-AO (RFC 5925, 5926) with key rollover and MD5 signatures (RFC 2385), ICMP quotes matched to the connection and an outstanding sequence |

Limits: 256 connections per host, 128 pending handshakes per listener, a
256 KiB default and 16 MiB maximum receive buffer, and 4 MiB of queued plus
unacknowledged send data. Eight consecutive timeouts, eight unanswered zero-window
probes, or the keep-alive probe count end a connection; FIN-WAIT-2 has a
five-minute cleanup timeout. The first accepted byte wins if overlapping data
conflicts.

## Scope and interoperability

This is a tested learning implementation, not a claim of complete RFC conformance or
production hardening. It uses the standard IPv4/TCP wire format, but interoperability
with real operating systems and NICs has not been validated by these tests.

Not implemented: IPv6 transport (the segment codec can checksum IPv6 segments, but
no IPv6 network layer exists), Multipath TCP, AccECN, HyStart, PRR and BBR. Unknown
options are skipped after structural validation and never advertised.

TCP respects the IPv4 host's 576-byte off-subnet send cap. ICMP errors are validated
against recent IP sends and outstanding TCP sequences: fragmentation-needed lowers
the connection's path MTU, protocol or port unreachable during opening fails the
connection, and other errors are recorded as soft errors while retransmission
continues. This does not turn `IPv4Host` into a router.

## Verification

```sh
dotnet run --project tests/TCP.Tests
dotnet run --project tests/TCP.Explorer.Tests
dotnet run --project tests/TCP.Transport.Kestrel.Tests
```

`tests/TCP.Tests/TcpTests.cs` covers the core protocol: an independent
wire/checksum fixture, handshake loss, duplication and reordering, retransmission
and fast recovery, sequence wrap, partial ACKs, zero windows, half and simultaneous
close, reset checks, resource bounds, path-MTU feedback and callback aborts.
`TcpTests.Extensions.cs` covers each extension: option codec round trips, AES-CMAC
test vectors, negotiation, window scaling, delayed ACK, keep-alive, user timeout,
urgent send, `CloseRead`, Fast Open, TIME-WAIT reuse, MTU raise and black-hole
detection, SACK, tail loss probe, ECN, CUBIC and NewReno windows, the initial window,
limited transmit, SYN cookies, TCP-AO and MD5, PAWS and spurious-timeout undo.
Explorer and Kestrel tests run the same implementation over virtual Ethernet and ARP.

References: [TCP (RFC 9293)](https://www.rfc-editor.org/rfc/rfc9293.html),
[RTO (RFC 6298)](https://www.rfc-editor.org/rfc/rfc6298.html),
[congestion control (RFC 5681)](https://www.rfc-editor.org/rfc/rfc5681.html),
[CUBIC (RFC 9438)](https://www.rfc-editor.org/rfc/rfc9438.html),
[high performance extensions (RFC 7323)](https://www.rfc-editor.org/rfc/rfc7323.html),
[SACK (RFC 2018)](https://www.rfc-editor.org/rfc/rfc2018.html),
[RACK-TLP (RFC 8985)](https://www.rfc-editor.org/rfc/rfc8985.html),
[path MTU (RFC 1191)](https://www.rfc-editor.org/rfc/rfc1191.html).

## Named protocol values

`TcpWireFormat` defines header offsets, option layout and pseudo-header fields,
deriving combined lengths from their component fields. `TcpOptionKind`, `TcpFlags`
and the IPv4/ICMP enums name the wire identifiers. Timers, weights, limits and
thresholds are named constants in the class that uses them, each with the RFC value
it comes from. `TcpMessages` holds stable diagnostic text. Ordinary loop indices and
empty counts remain literal zero; independent test packet fixtures remain literal
bytes so they can detect mistakes in the implementation's constants.

## UDP

`TCP.L4.Transport.Udp` implements RFC 768 over the same `IPv4Host`; each
`EthernetStack` has a `UdpHost` at `stack.Udp`. `Bind(port)` (or `Bind()` for a
random ephemeral port, RFC 6056) returns a `UdpSocket`. `SendTo` sends one datagram,
and `Received` raises one event per datagram with its sender and payload: message
boundaries are preserved, but nothing is retransmitted, ordered or flow-controlled.

```csharp
using var dns = stack.Udp.Bind(53);
dns.Received += (socket, datagram) =>
    socket.SendTo(datagram.RemoteAddress, datagram.RemotePort, Answer(datagram.Payload.Span));
```

- Checksums cover the shared pseudo-header (`TCP.Checksums.PseudoHeader`). A zero
  checksum means "not computed" and is accepted over IPv4 only.
- A unicast datagram for an unbound port draws ICMP port unreachable (RFC 1122
  4.1.3.1). ICMP errors about our own datagrams reach the sending socket's
  `ErrorReceived` (RFC 1122 4.1.3.3).
- Broadcast and multicast datagrams are delivered with `Broadcast = true` and never
  draw errors. Sending to a broadcast address requires `EnableBroadcast`.
- `Connect(address, port)` sets a default destination for `Send` and filters
  arrivals to that peer; nothing goes on the wire.
- Payloads up to 65,507 bytes are allowed. IPv4 fragments anything larger than the
  MTU (Don't Fragment is left clear), and the receiver reassembles it.
