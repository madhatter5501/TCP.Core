# Serve TCP Explorer through TCP.Core

Status: stages 2–4 implemented and verified over a deterministic virtual link; stages 1 and 5 (live network) not started.

## Implementation status — 2026-09-27

The localhost Explorer remains the default. No physical interface has been opened and
no live-network address has been selected. Everything below was verified only over an
in-memory Ethernet link between two TCP.Core stacks; it proves the adapter, not
interoperability with an operating-system TCP stack.

| Plan stage | Status | Evidence / remaining work |
| --- | --- | --- |
| 1. Packet path | Not started | Needs a chosen interface, an address confirmed unused on that subnet, capture privileges and an independent client. See "Next: live validation" below. |
| 2. Protocol-thread dispatcher | Done (virtual link) | `EthernetStack.TrySchedule` bounded queue with a per-turn budget. `TcpCoreHostService` starts the stack in `StartingAsync` (before Kestrel binds) and stops it in `StoppedAsync` (after Kestrel drains), contains command exceptions, fails waiting callers fast once stopped, and stops the application if the protocol thread dies after startup (address conflict, interface failure). |
| 3. Kestrel transport | Done (virtual link) | `TcpCoreConnection` rewritten so each pipe end has one owner. Graceful close sends FIN and leaves FIN-WAIT/TIME-WAIT to `TcpHost`; only abort, failure or undrained output resets. Input backpressure reaches the TCP window; a drained input queue always resumes reading (no lost wakeup, including a FIN that arrived while full). |
| 4. Explorer integration | Done (virtual link) | `sockets` (default) and `tcp-core` modes. `tcp-core` requires an explicit interface and IPv4 address, binds only the TCP.Core endpoint, and fails clearly rather than falling back. Shared `MapExplorer` setup; `/api/transport` and a footer label show the serving transport. |
| Project boundaries | Done | `TCP.Networking.Pcap` holds the libpcap interface and `PcapNetworkConfiguration`; `TCP.Host` and `TCP.Transport.Kestrel` both reference it, and nothing references the Host executable. |
| Deterministic HTTP tests | Passing (21) | `tests/TCP.Transport.Kestrel.Tests`, stable across repeated runs (~55 s): 11 HTTP/1.1 and 10 HTTP/2 (h2c). See below. |
| HTTP/2 | h2c done (virtual link); h2 blocked on TLS | Cleartext HTTP/2 with prior knowledge on an `Http2`-only endpoint. Browsers need `h2` over TLS with ALPN; see "HTTP/2" below. |
| 5. Live browser / packet capture | Not started | Follows stage 1. |

Defects found and fixed while finishing stages 2–4:

- Every graceful response ended in RST: disposal aborted TCP instead of completing the
  application-facing pipes (Kestrel's contract) and letting the pump send FIN.
- Startup could deadlock and shutdown could hang: the stack's lifetime depended on
  hosted-service ordering, and protocol-thread waits never observed a stopped stack.
- A peer FIN that arrived while the input queue was full was never delivered.
- `Close()` completed pipe readers/writers from other threads while pumps used them.
- The listener cast Kestrel's endpoint to `IPEndPoint` and failed to bind.

### Deterministic test coverage

`dotnet run --project tests/TCP.Transport.Kestrel.Tests` (set `TEST_FILTER` to run a
subset). Real Kestrel and the real Explorer app, served by one TCP.Core stack; a second,
independent TCP.Core stack is the client; a virtual Ethernet link logs every frame and
injects faults. No OS socket carries the traffic.

- Only the TCP.Core endpoints (HTTP/1.1 and h2c) are bound (no socket fallback).
- GET closes with server FIN and server-side TIME-WAIT, never RST.
- Keep-alive requests on one connection; orderly client close.
- Slow reader drives the client window to zero; the response resumes intact.
- Response larger than TCP's 1 MiB send buffer streams through Kestrel backpressure.
- Request body split into ~200 small segments followed immediately by FIN.
- Sparse loss, corruption, duplication and reordering repaired end to end.
- Client RST mid-response releases the server connection; the server stays healthy.
- Explorer page, script, `/api/transport` and `/api/simulate` served through TCP.Core.
- 576-byte MTU with no oversized IPv4 packets.
- Shutdown closes an idle keep-alive connection and stops the protocol thread.

HTTP/2 tests use `HttpClient` pinned to `HttpVersion.Version20` with
`HttpVersionPolicy.RequestVersionExact`; `SocketsHttpHandler.ConnectCallback` returns a
`VirtualTcpStream` over the client TCP.Core stack. Every byte HttpClient wrote or read is
decoded with `TCP.L5_7.Application.Http2.Http2FrameReader`, so the assertions are about
frames that actually crossed TCP:

- h2c prior knowledge: SETTINGS first, client streams 1, 3, 5; the HTTP/1.1 port still works.
- An HTTP/1.1 request to the `Http2`-only endpoint gets Kestrel's HTTP/1.1 400, then FIN.
- A stream the server holds open does not block 12 others on the same TCP connection;
  completion order is read off the wire.
- Six concurrent 250 KB responses interleave DATA frames on one connection.
- 1 MB upload and 1 MB download: a replay of every SETTINGS, WINDOW_UPDATE and DATA frame
  shows neither side ever exceeded the peer's connection or stream window.
- An unread stream stalls at its 65,535-byte window while TCP stays open and other streams run;
  reading resumes it intact.
- The HTTP/1.1 test's loss, corruption, duplication and reordering pattern, applied to
  concurrent downloads and an upload.
- A client abort sends RST_STREAM for one stream; the connection keeps serving.
- A cleartext `Http1AndHttp2` endpoint serves HTTP/1.1 and answers the h2 preface with
  GOAWAY `HTTP_1_1_REQUIRED`.
- Shutdown sends GOAWAY (NO_ERROR, last stream 1) on an idle h2c connection, then closes TCP.

### HTTP/2

- **h2c needs its own endpoint.** Without TLS there is no ALPN to choose the protocol.
  Kestrel (.NET 10) then serves only HTTP/1.1 on an `Http1AndHttp2` endpoint (it logs
  "HTTP/2 requires TLS application protocol negotiation") and rejects the HTTP/2 preface
  there with GOAWAY `HTTP_1_1_REQUIRED`. So h2c runs on a separate `HttpProtocols.Http2`
  endpoint. The transport itself is protocol-agnostic: `TcpCoreConnection` carries bytes,
  and Kestrel does the HTTP/2 framing, HPACK and flow control.
- **Browsers do not use h2c.** Set `TCP_EXPLORER_H2C_PORT` to add the h2c endpoint to the
  Explorer beside the HTTP/1.1 port, then test with
  `curl --http2-prior-knowledge http://<address>:<h2c port>/api/transport`.
- **h2 over TLS is blocked on the TLS work.** Browsers speak HTTP/2 only as `h2` over TLS,
  chosen with ALPN (RFC 7301) in the handshake. `src/TCP.Core/L5_7.Application/Tls` has
  records, alerts and cryptography so far, but no handshake or ALPN extension. When it
  does, the Kestrel side needs a connection middleware (or `UseHttps` over the TCP.Core
  connection) that sets `ITlsConnectionFeature` and `ITlsApplicationProtocolFeature`
  ("h2" or "http/1.1"), so an `Http1AndHttp2` endpoint picks the protocol per connection.

### Known limitations relevant to live use

- **Lost retransmissions wait for the timer.** Without SACK, NewReno recovers a lost
  fast retransmission only by timeout, and Karn's rule keeps a backed-off RTO until a
  clean sample. Heavy loss (tested at ~20 %) degrades to multi-second stalls; the
  deterministic test uses a realistic few-percent rate.
- **TIME-WAIT is on the server.** The server closes first, so each closed HTTP
  connection holds one of `TcpHost.MaximumConnections` (256) for 4 minutes. Repeated
  non-keep-alive refreshes can exhaust it; prefer keep-alive and watch this in stage 5.
- **No HTTPS.** HTTP/1.1 for browsers; HTTP/2 only as h2c on a separate port (see "HTTP/2").
- **Same-machine browsing is unvalidated.** Whether a browser on the capturing Mac
  reaches injected frames on the same interface is exactly what stage 1 must answer.

### Next: live validation (stage 1)

Inputs to decide before anything touches a real network:

1. An Ethernet interface, ideally a wired isolated test link (`ifconfig` name, e.g. `en7`).
2. An IPv4 address on that interface's subnet that is unused and not assigned to the Mac.
   Address-conflict probing will refuse an address in use, but do not guess.
3. Capture privileges: libpcap needs root or read/write access to `/dev/bpf*`.
4. A second device as the client, as the plan recommends.

Then start the Explorer on the custom stack and capture on the client side:

```sh
sudo TCP_EXPLORER_TRANSPORT=tcp-core TCP_EXPLORER_INTERFACE=<interface> \
  TCP_EXPLORER_ADDRESS=<unused IPv4> TCP_EXPLORER_PORT=5097 \
  dotnet run --project src/TCP.Explorer
```

Return to localhost mode by omitting `TCP_EXPLORER_TRANSPORT` (or setting it to `sockets`).

## Outcome

Serve the existing Explorer HTML, scripts, styles and `/api/simulate` through
Kestrel HTTP/1.1 using TCP.Core as the server's TCP implementation. A real browser
continues using its OS TCP stack. The server owns ARP, IPv4, TCP sequencing,
retransmission, windows, connection closure and TIME_WAIT.

Successful completion requires a browser loading the app over the custom stack,
with a packet trace proving the path. A memory-only test or socket proxy is not
sufficient evidence of real-network interoperability.

## Architecture

Browser / client OS TCP
  ↕ physical or isolated virtual Ethernet link
IPacketInterface → EthernetStack → IPv4Host → TcpHost / TcpConnection
  ↕ single-thread dispatcher and bounded pipe adapter
Kestrel ConnectionContext.Transport (IDuplexPipe)
  ↕ HTTP/1.1
Existing Explorer routes and static files

Proposed project boundaries:

- `TCP.Core`: protocol implementation, independent of ASP.NET Core.
- `TCP.Networking.Pcap`: extract the existing macOS packet interface and host
  configuration from the executable into a reusable library. Preserve Host CLI
  behavior and its existing platform checks.
- `TCP.Transport.Kestrel`: listener factory, connection context, pipe pumps,
  options and protocol-thread dispatcher. Depends on Core and ASP.NET Core.
- `TCP.Explorer`: chooses the transport and retains the existing application.
- `TCP.Transport.Kestrel.Tests`: deterministic adapter and HTTP integration tests.

Keep one meaningful type per file, named protocol constants, enums for states and
identifiers, named diagnostics, and derived sizes. Runtime choices belong in
validated options; fixed wire-format values remain constants. Preserve the
existing developer edits and project organization.

## 1. Prove the packet path

Start with the existing macOS libpcap/BPF backend. Use an explicitly selected
Ethernet interface and an available IPv4 address on its subnet, owned by our
stack and not configured as an OS interface address. Reuse address-conflict
probing before declaring readiness. Prefer a wired isolated test link and a
second client device for the initial interoperability check.

Verify ARP resolution, SYN/SYN-ACK/ACK, a small echo, and FIN closure against an OS
socket client. Capture both directions and check for kernel-generated resets,
missing injected frames, duplicate capture delivery and checksum interpretation.
Capture privileges, actual interface, address and client availability are launch
inputs to resolve before live activation; do not guess an unused LAN address.

Do not assume the current Mac's browser can reach injected traffic through the
same physical interface. If same-machine use is required, validate a separate
virtual network path. Linux TAP inside an isolated VM is a fallback test backend,
not a capability currently present in the macOS packet interface. Do not assume
macOS loopback exposes Ethernet frames; the current backend explicitly requires
that link format.

Checkpoint: bidirectional TCP echo from an independent OS stack succeeds. Fix
protocol defects discovered here before building on them.

## 2. Add a protocol-thread dispatcher

Run packet reception, timers, listener operations and every TcpConnection API on
one owned protocol thread. Add a bounded command queue with wakeup and cancellation
support. Kestrel tasks post commands; TCP callbacks signal completion without
blocking that thread or running arbitrary application continuations inline.

Budget command and packet work per iteration so neither can starve TCP timers.
Propagate packet-interface failure and address conflict to the host. Make startup
wait for address readiness; make stop/dispose deterministic and idempotent.

Checkpoint: concurrent callers, cancellation, queue saturation, callback aborts
and shutdown cannot race TCP state or stall the protocol loop.

## 3. Implement the Kestrel transport

Implement `IConnectionListenerFactory`, `IConnectionListener` and a
`ConnectionContext` exposing an `IDuplexPipe`, endpoints, connection identity and
connection-closed notification. Bind only supported IPv4 endpoints; reject
wildcard/unsupported configurations explicitly. Bound the accepted-connection
queue and define what happens when it is full. Unbinding stops new accepts while
existing connections drain.

Inbound: move available TCP bytes into the input pipe in bounded batches. Stop
reading TCP when the pipe reaches its threshold so backpressure reaches the TCP
receive window. Resume on reader progress, including when no new packet arrives.
Never await a pipe flush on the protocol thread.

Outbound: consume only the bytes accepted by TcpConnection.Send; retain the
unaccepted suffix and resume after SendReady. Bound pipe and staging storage as
well as the existing TCP send buffer. Document the aggregate per-connection and
host memory budget; a pipe flush does not promise peer delivery.

Lifecycle: drain received bytes before delivering EOF; distinguish peer FIN from
reset/failure. Complete outbound data before initiating FIN. Map abort to RST,
wake blocked reads/writes on cancellation, and detach callbacks exactly once.
Do not discard TCP state merely because Kestrel disposes its application-side
context: graceful close and TIME_WAIT remain owned by TcpHost until expiry.
Allow a named shutdown grace period, then abort remaining active connections.

Checkpoint: deterministic tests cover partial sends, slow readers, zero windows,
lost wakeups, FIN with trailing data, reset, cancellation, listener disposal and
resource cleanup. Test both synchronous delivery and asynchronous scheduling.

## 4. Connect the Explorer application

Add explicit `sockets` and `tcp-core` transport modes with validated interface,
IPv4 address, prefix/network selection, HTTP port, MTU and optional gateway
configuration. In tcp-core mode, select only the custom transport; fail clearly
if it cannot start rather than silently serving through OS sockets.

Keep the existing localhost mode available as an explicit development option.
Start the custom endpoint alongside development work on its own address. Enable
HTTP/1.1 first. Retain Kestrel's HTTP parsing, request limits, static-file handling
and existing API behavior. TLS/HTTP/2 are follow-up work; HTTP/3 requires QUIC/UDP
and is outside this TCP transport.

Show the active transport and endpoint in startup output and a small lab status
indicator. Provide bounded frame/state diagnostics and exportable captures so
actual serving traffic can be distinguished from simulated experiments. Ensure
observability does not recursively grow without bound as its own HTTP requests
are captured.

Checkpoint: real Kestrel serves static assets and API requests through the
adapter over a deterministic in-memory link, with no server Socket/TcpListener
fallback. This validates the adapter but does not replace the live-network gate.

## 5. Validate and switch the browsing endpoint

Run all existing core and Explorer tests, then adapter and full HTTP tests:

- GET/HEAD, assets larger than MSS and send-buffer capacity, and API POST bodies
  split across arbitrary TCP segment boundaries.
- HTTP keep-alive, several browser connections, repeated refreshes, canceled
  downloads, slow reads/writes, orderly close and connection reset.
- Loss, duplication, reordering, corruption, small MTU and zero-window reopening
  using deterministic faults; verify response bytes and bounded memory.
- Stop accepting during shutdown; drain or abort as configured; verify tasks,
  listeners, buffers and TIME_WAIT records are released at their proper times.

Use curl and a real browser on the proven network path to load the complete app
and exercise the simulation API. Capture handshake, HTTP bytes, retransmission
where induced, FIN and TIME_WAIT. Demonstrate that the served endpoint is handled
by TCP.Core rather than an OS TCP listener. Record the exact client OS, interface,
address, MTU, privilege requirements and observed limitations.

Only after these checks pass, point the browser at the custom-stack URL. Document
startup, shutdown, troubleshooting and the command to return to localhost mode.

## Completion criteria

The entire app works over TCP.Core from an independent TCP implementation; all
regression suites pass; byte captures and server transport selection prove the
path; backpressure and teardown are bounded and tested; configuration and known
platform limitations are documented. This establishes tested interoperability
for the exercised configurations, not universal TCP conformance or production
readiness.

## References

- [Kestrel listener factory](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.connections.iconnectionlistenerfactory?view=aspnetcore-10.0)
- [Kestrel connection listener](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.connections.iconnectionlistener?view=aspnetcore-10.0)
- [ConnectionContext and IDuplexPipe transport](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.connections.connectioncontext?view=aspnetcore-10.0)
- [Linux TUN/TAP](https://www.kernel.org/doc/html/latest/networking/tuntap.html)
