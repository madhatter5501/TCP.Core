# L1 — Physical

Namespace `TCP.L1.Physical`. The physical layer as this stack sees it: one
interface, `IPacketInterface`, that moves whole Ethernet frames in and out.
Signalling, the preamble and the frame check sequence (FCS) belong to the network
card and its driver, so they never appear in this library.

```csharp
public interface IPacketInterface : IDisposable
{
    const int MaximumFrameLength = 65_536;
    string InterfaceName { get; }
    int Receive(byte[] buffer);   // frame length, or 0 immediately when nothing is waiting
    void Send(byte[] frame);      // destination MAC through payload, already padded to 60 bytes
}
```

`Receive` must never block: `EthernetStack` and `LearningBridge` poll it in a loop
from one thread, between running timers and scheduled work.

## Implementations

| Implementation | Where | Use |
| --- | --- | --- |
| `PcapPacketInterface` | `src/TCP.Networking.Pcap` | A real network card through libpcap/BPF (macOS only) |
| In-memory ports | `tests/`, `src/TCP.Explorer` | Virtual wires for tests, the Explorer's transmission lab and the Kestrel tests |

`EthernetStack` runs a host on one port; `LearningBridge` switches between several.
See [L2 — Link](../L2.Link/README.md).
