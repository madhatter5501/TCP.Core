# TCP.Core Stack Explorer

An ASP.NET Core host with a React + TypeScript interface (Vite, React Router) in `ClientApp/`. Added to `TCP.slnx`; inherits .NET 10 from `Directory.Build.props`.

## Run

From the repository root:

```sh
dotnet run --project src/TCP.Explorer
```

Open <http://localhost:5097>. Building the project runs `npm ci` when packages are missing and `npm run build` when UI sources change, writing the bundle to `wwwroot/` (generated, not committed). Node.js is required for that step; pass `-p:SkipClientAppBuild=true` to build without it when `wwwroot/` already exists. If the port is occupied:

```sh
dotnet run --project src/TCP.Explorer --no-launch-profile --urls http://localhost:5098
```

For UI work with hot reload, keep the host running for `/api` and start Vite beside it:

```sh
npm --prefix src/TCP.Explorer/ClientApp run dev
```

### Serving through TCP.Core

By default Kestrel uses the operating system's sockets. Set `TCP_EXPLORER_TRANSPORT=tcp-core` to serve the Explorer through this repository's own stack on a real interface, via `TCP.Transport.Kestrel` and libpcap (macOS, usually with `sudo`):

```sh
sudo TCP_EXPLORER_TRANSPORT=tcp-core TCP_EXPLORER_INTERFACE=en0 TCP_EXPLORER_ADDRESS=192.168.1.250 dotnet run --project src/TCP.Explorer
```

| Variable | Meaning |
| --- | --- |
| `TCP_EXPLORER_INTERFACE`, `TCP_EXPLORER_ADDRESS` | Required: the interface and an unused IPv4 address on its subnet; there is no fallback to OS sockets |
| `TCP_EXPLORER_GATEWAY` | Optional default route |
| `TCP_EXPLORER_PORT` | HTTP/1.1 port (default 5097) |
| `TCP_EXPLORER_H2C_PORT` | Optional separate port for cleartext HTTP/2 with prior knowledge (`curl --http2-prior-knowledge`) |
| `TCP_EXPLORER_MTU` | Link MTU (default 1500) |

Browse to the configured address from another machine on the subnet; the host OS does not own that address. This mode is tested only over a virtual link so far; live-network validation is still open in [docs/TCP-WEB-SERVER-PLAN.md](../../docs/TCP-WEB-SERVER-PLAN.md).

## Explore

Each section is its own page with a single intent. Every URL is linkable; the host falls back to `index.html` for client routes. On desktop-sized windows the tool pages (layers, transmit, sizes) fill the viewport and their panes scroll independently, so nothing needs a page scroll; narrow or short windows fall back to normal flow.

| Route | Intent |
| --- | --- |
| `/` | Overview and where to start |
| `/layers/:layer/:view?` | Understand: encapsulation walkthrough; per-layer overview, header fields (`headers`), `gotchas` and source map (`code`) |
| `/transmit?scenario=…` | Observe: run real TCP.Core code on two in-memory hosts; a frame ladder beside a field / hex / trace inspector |
| `/sizes` | Experiment: MTU, MSS, options, VLAN tags and IPv4 fragmentation byte accounting |
| `/concepts/:concept` | Learn: vocabulary articles (PDU names, datagrams) and an A–Z glossary (`/concepts/glossary#fcs`); add one in `pages/concepts/concepts.ts` |

## Source layout

- `ClientApp/src/content/layers.ts` — layer teaching content and source-file map. Keep it in step with TCP.Core.
- `ClientApp/src/content/glossary.ts` — term definitions plus how TCP.Core handles each. Spellings listed in `matches` are linked automatically wherever `GlossaryText` renders prose, with the definition on hover or focus; use `<Term id="…">` in hand-written JSX.
- `ClientApp/src/model/packetModel.ts` — pure byte accounting behind the size lab.
- `ClientApp/src/pages/*` — one folder per section, with colocated styles.
- `ClientApp/src/pages/transmit/types.ts` — mirrors the JSON records in `TransmissionSimulation.cs`.

## Model boundaries

The content reflects the checked-in implementation as reviewed on 2026-09-27. It intentionally uses source rather than `docs/STANDARDS.md` where that document has fallen behind the implementation. Maintain `ClientApp/src/content/layers.ts` as the stack evolves.

The transmission lab references and executes TCP.Core against two in-memory interfaces. It never opens a physical NIC or sends packets onto your network. The original layer canvas illustrates TCP conceptually; the actual ICMP ping path bypasses L4. The five-layer diagram groups OSI layers 5–7. Diagram blocks are not to byte scale.

## Real-code transmissions

`POST /api/simulate` runs two fresh `EthernetStack` instances with static documentation-range addresses (192.0.2.10 and 192.0.2.20). The payload is the supplied UTF-8 seed repeated/truncated to the requested byte length. Real codecs serialize Ethernet, ARP, IPv4, TCP and ICMP. The receiver runs its normal protocol processing. The UI only displays the returned evidence; it does not fabricate protocol responses.

TCP experiments: stream echo with graceful close, dropped data segment, corrupt TCP checksum, zero-window recovery, and closed-port reset. A demo application on Host B reads the TCP stream and echoes it; Host A verifies all bytes. The trace includes SYN/ACK/FIN/RST, TCP checksum, MSS options, sequence/acknowledgment numbers, and advertised windows. Loss can trigger fast retransmit at the same virtual timestamp; it need not wait for RTO. Successful runs stop after the FIN exchange with Host A in TIME-WAIT; cleanup time is not included in that run.

ICMP experiments: successful ping, fragmentation/reassembly, oversized DF refusal, corrupt IPv4 checksum, one dropped non-first fragment, and dropped ARP replies. Inspect every captured frame, byte offsets, sent/received hex, and protocol events. Dropped frames have no received bytes; checksum corruption preserves the original bytes separately.

The harness uses the same internal `ProcessFrame` and `Tick` seams as the core tests through `InternalsVisibleTo`. It drives both stacks on one thread and advances a virtual clock, without calling `Run`. Consequently address-claim startup, real NIC behavior, signaling, preamble/FCS, physical delays and OS offload are not exercised. Each request owns its state; input and frame-count limits bound the experiment. The clock is virtual and is not a performance measurement.

TCP connection callbacks and `EchoRequestAnswered`, `NeighborResolutionFailed`, and `IcmpErrorReceived` provide direct core evidence. For ICMP only, a passive observer uses the production IPv4 reassembler and ICMP parser to verify captured replies because the host has no echo-reply notification. TCP uses the application's actual received stream. This is evidence of the tested paths, not proof of complete standards compliance or real-network interoperability. See `../TCP.Core/L4.Transport/README.md` for the TCP and UDP APIs and remaining extension limits; the lab runs TCP and ICMP scenarios only.

The transmission endpoint requires the ASP.NET host. Under `npm run dev` without the host, every page except real-code runs still works.

The lab models maximum-size IPv4/TCP data segments. Capacity is `max(0, min(min(link MTU, path MTU) - 40, peer MSS) - IP options - TCP options)`. The separate MSS advertisement example is `link MTU - 40`; optional headers reduce actual data, not that advertised example. A real stack also considers buffers, flow control, congestion control and path discovery. IPv6, retransmissions, TCP handshakes and ACK traffic are outside the size calculation.

Ethernet sizing matches the codec's minimum 60-byte serialized frame, plus hardware FCS. Preamble/SFD and inter-frame gap are excluded. VLAN tagging adds a header field; padding can absorb it in very small frames. The fragment experiment uses a fixed 20-byte IPv4 header, deliberately excluding IP option-copy rules. Large fragment sets show the first six and final fragment, with a total count.

The generic lab does not impose TCP.Core's current conservative 576-byte off-subnet cap. Its L3 gotchas explain this distinction and the local `SendIPv4` DF failure behavior.

## Validate

```sh
dotnet build src/TCP.Explorer
npm --prefix src/TCP.Explorer/ClientApp test
dotnet run --project tests/TCP.Explorer.Tests
dotnet run --project tests/TCP.Transport.Kestrel.Tests
```

Vitest covers the byte-accounting model (known examples and boundary invariants), the hex dump, and every route: deep links, tab keyboard navigation, walkthrough stepping, experiment preselection, a mocked transmission through the ladder and inspector, size-lab validation, DF behavior, not-found and render-error handling. The Kestrel tests serve the built UI, a deep link and the simulation API through TCP.Core itself. Browser checks should still cover canvas drawing and narrow layouts.

Protocol references are linked in the app: RFC 768, RFC 791, RFC 9293, RFC 6691 and RFC 1191.
