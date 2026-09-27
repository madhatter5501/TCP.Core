# C# Network Stack From Scratch

## Goal

Build a small network stack in **C#** to understand how Ethernet, ARP, IPv4, ICMP, UDP, and TCP actually work.

The goal is **education and interoperability**, not production performance.

The final milestone:

```text
Normal OS TCP Client
        │
        │ Ethernet
        ▼
┌─────────────────────────────┐
│      My C# Network Stack    │
│                             │
│  Ethernet                   │
│      ↓                      │
│  ARP                        │
│      ↓                      │
│  IPv4                       │
│      ↓                      │
│  TCP                        │
│      ↓                      │
│  HTTP                       │
│                             │
└─────────────────────────────┘
        │
        ▼

HTTP/1.1 200 OK

Hello from my C# network stack
```

Eventually:

```bash
curl http://<my-stack-ip>/
```

should communicate with TCP and HTTP implemented by my own C# code.

---

# What I'm Building

```text
Application
────────────────────────────
HTTP                 ← mine
────────────────────────────
Layer 4
TCP                  ← mine
UDP                  ← mine
────────────────────────────
Layer 3
IPv4                 ← mine
ICMP                 ← mine
────────────────────────────
Layer 2
Ethernet             ← mine
ARP                  ← mine
────────────────────────────
OS / NIC Driver
────────────────────────────
Physical Network
```

The OS/NIC still handles actual transmission and reception of physical Ethernet frames.

Everything above that boundary should progressively become my implementation.

---

# Principles

## Don't Hide the Protocol

Avoid using abstractions that implement the protocol I'm trying to learn.

For example:

```csharp
new TcpClient()
```

is useful as an **interoperability test client**, but not as the implementation of my TCP stack.

My TCP implementation should deal with:

- TCP headers
- flags
- sequence numbers
- acknowledgment numbers
- checksums
- connection state
- retransmission
- receive windows
- connection establishment
- connection termination

## RFC → Code → Wireshark

The primary learning loop:

```text
RFC / Specification
        ↓
Implement behavior
        ↓
Generate packets
        ↓
Capture with Wireshark
        ↓
Compare expected vs actual
        ↓
Fix understanding
```

Wireshark is effectively the debugger for the network stack.

---

# Suggested Solution Structure

```text
NetworkStack/
│
├── NetworkStack.Protocols/
│   │
│   ├── Ethernet/
│   │   ├── EthernetFrame.cs
│   │   └── MacAddress.cs
│   │
│   ├── Arp/
│   │   ├── ArpPacket.cs
│   │   └── ArpCache.cs
│   │
│   ├── IPv4/
│   │   ├── IPv4Packet.cs
│   │   └── IPv4Checksum.cs
│   │
│   ├── Icmp/
│   │   └── IcmpPacket.cs
│   │
│   ├── Udp/
│   │   └── UdpDatagram.cs
│   │
│   └── Tcp/
│       ├── TcpSegment.cs
│       ├── TcpFlags.cs
│       └── TcpChecksum.cs
│
├── NetworkStack.Tcp/
│   │
│   ├── TcpConnection.cs
│   ├── TcpState.cs
│   ├── TcpStateMachine.cs
│   ├── TcpListener.cs
│   ├── SendBuffer.cs
│   ├── ReceiveBuffer.cs
│   └── RetransmissionQueue.cs
│
├── NetworkStack.Transport/
│   │
│   └── PacketInterface.cs
│
├── NetworkStack.Server/
│   └── Program.cs
│
└── NetworkStack.Tests/
```

The exact architecture should evolve as understanding improves.

---

# Phase 1 — Ethernet

## Objective

Understand Ethernet frames and Layer 2 addressing.

Implement parsing and construction of Ethernet II frames.

Basic frame:

```text
┌──────────────────────────┐
│ Destination MAC   6 B    │
├──────────────────────────┤
│ Source MAC        6 B    │
├──────────────────────────┤
│ EtherType         2 B    │
├──────────────────────────┤
│ Payload                  │
├──────────────────────────┤
│ FCS               4 B    │
└──────────────────────────┘
```

Understand:

- MAC addresses
- unicast
- broadcast
- multicast
- EtherType
- MTU
- frame payload
- FCS/CRC and what the NIC may handle automatically

Important EtherTypes:

```text
0x0800 → IPv4
0x0806 → ARP
0x86DD → IPv6
```

### Milestone

Given raw bytes, print:

```text
Source MAC:      12:34:56:78:90:AB
Destination MAC: FF:FF:FF:FF:FF:FF
EtherType:       ARP
Payload Length:  28
```

---

# Phase 2 — ARP

## Objective

Understand how IPv4 addresses are mapped onto Layer 2 addresses.

Example:

```text
Who has 10.0.0.2?
Tell 10.0.0.1

        ↓

10.0.0.2 is at
AA:BB:CC:DD:EE:FF
```

Implement:

- ARP request parsing
- ARP reply parsing
- ARP request generation
- ARP reply generation
- basic ARP cache

Example cache:

```text
IP              MAC
────────────────────────────────
10.0.0.1        12:34:56:78:90:AB
10.0.0.2        AA:BB:CC:DD:EE:FF
```

### Milestone

The OS sends:

```text
Who has <my-stack-ip>?
```

My C# stack replies with its MAC address.

The operating system should then populate its ARP/neighbor table with my stack.

---

# Phase 3 — IPv4

## Objective

Understand Layer 3 packet delivery.

Implement:

- IPv4 header parsing
- IPv4 packet construction
- header length
- total length
- TTL
- protocol
- source address
- destination address
- header checksum

Packet dispatch:

```text
Ethernet
    │
    │ EtherType 0x0800
    ▼
IPv4
    │
    ├── Protocol 1  → ICMP
    │
    ├── Protocol 6  → TCP
    │
    └── Protocol 17 → UDP
```

### Milestone

Given an IPv4 packet:

```text
Version:       IPv4
Header Length: 20
Source:        10.0.0.1
Destination:   10.0.0.2
TTL:           64
Protocol:      TCP
```

---

# Phase 4 — ICMP

## Objective

Get the first real interoperability test working.

Implement:

- ICMP parsing
- Echo Request
- Echo Reply
- ICMP checksum

Flow:

```text
OS

ping <my-stack-ip>

        │
        │ ICMP Echo Request
        ▼

My C# Stack

        │
        │ ICMP Echo Reply
        ▼

OS

Reply from <my-stack-ip>
```


### Running the stack

Protocol implementations live in `TCP.Core.csproj`; executable hosting and libpcap support live in `Host/TCP.Host.csproj`.

Build the solution and run the protocol diagnostics:

```bash
dotnet build TCP.slnx
dotnet run --project Host/TCP.Host.csproj
```

On macOS, start the Ethernet responder with an unused IPv4 address on the selected interface's subnet:

```bash
dotnet run --project Host/TCP.Host.csproj -- --serve --interface en7 --ip 172.16.10.250
```

The process uses libpcap/BPF for Ethernet capture and injection. Ping from a client whose packets reach that interface; a VPN may route same-host traffic through a tunnel instead.

### Major Milestone

```bash
ping <my-stack-ip>
```

works against my C# network stack.

At this point:

```text
Ethernet ✓
ARP      ✓
IPv4     ✓
ICMP     ✓
```

are working together.

---

# Phase 5 — UDP

## Objective

Learn the simpler Layer 4 protocol before tackling TCP.

Implement:

```text
Source Port
Destination Port
Length
Checksum
Payload
```

Build a simple UDP echo service.

```text
OS UDP Client

"Hello"
    │
    ▼
My UDP Stack
    │
    ▼
"Hello"
```

### Milestone

A normal OS UDP client communicates with my C# UDP implementation.

---

# Phase 6 — TCP Segment Parsing

## Objective

Understand the TCP wire format before implementing TCP behavior.

Parse:

```text
Source Port
Destination Port
Sequence Number
Acknowledgment Number
Header Length
Flags
Window
Checksum
Urgent Pointer
Options
Payload
```

Important flags:

```text
SYN
ACK
FIN
RST
PSH
URG
ECE
CWR
```

Example diagnostic output:

```text
Source:      10.0.0.1:49152
Destination: 10.0.0.2:8080

Sequence:    184739102
ACK:         0

SYN:         true
ACK flag:    false
FIN:         false

Window:      65535
```

---

# Phase 7 — TCP State Machine

Implement the TCP connection states.

```text
CLOSED
LISTEN
SYN-SENT
SYN-RECEIVED
ESTABLISHED
FIN-WAIT-1
FIN-WAIT-2
CLOSE-WAIT
CLOSING
LAST-ACK
TIME-WAIT
```

Initial server path:

```text
CLOSED
   ↓
LISTEN
   ↓
SYN-RECEIVED
   ↓
ESTABLISHED
```

Represent this explicitly rather than hiding it inside socket abstractions.

---

# Phase 8 — TCP Three-Way Handshake

This is the first major TCP milestone.

```text
OS Client                         My C# Server

   -------- SYN seq=100 -------->

   <---- SYN + ACK seq=500 -------
                   ack=101

   -------- ACK seq=101 --------->
                 ack=501

             ESTABLISHED
```

Implement:

- Initial Sequence Number
- SYN processing
- SYN+ACK generation
- ACK validation
- connection tracking

### Major Milestone

Use a **normal operating-system TCP client** against my implementation.

For example:

```csharp
using var client = new TcpClient();

await client.ConnectAsync("<my-stack-ip>", 8080);
```

If `ConnectAsync()` succeeds:

**my TCP implementation successfully interoperated with the OS TCP stack.**

---

# Phase 9 — TCP Data

Once connected:

```text
Client                           Server

   ------- "Hello" ------------>

   <---------- ACK --------------

   <------ "Hello back" ---------

   ---------- ACK -------------->
```

Implement:

- send sequence numbers
- receive sequence numbers
- ACK generation
- payload handling
- receive buffering
- send buffering

Understand exactly why:

```text
SEQ = N
LEN = 5

next expected sequence = N + 5
```

---

# Phase 10 — Retransmission

TCP must handle packet loss.

Experiment deliberately:

```text
Send segment
     ↓
Start timer
     ↓
Wait for ACK
     ↓
ACK missing
     ↓
Timer expires
     ↓
Retransmit
```

Implement initially:

- retransmission queue
- simple retransmission timeout
- ACK removal from queue

Then study proper TCP RTT/RTO behavior.

---

# Phase 11 — Flow Control

Implement the TCP receive window.

Understand:

```text
Sender
     │
     │ Can I send?
     ▼
Receiver advertised window
     │
     ▼
Available receive buffer
```

Explore:

- advertised receive window
- send window
- receive window
- zero-window conditions
- window updates

---

# Phase 12 — TCP Connection Shutdown

Implement:

```text
FIN
ACK
FIN
ACK
```

and understand:

```text
FIN-WAIT-1
FIN-WAIT-2
CLOSE-WAIT
LAST-ACK
TIME-WAIT
```

Experiment with half-closed connections.

Understand **why TIME_WAIT exists** instead of simply memorizing that it does.

---

# Phase 13 — HTTP

Once TCP works, put an extremely small HTTP implementation on top.

Request:

```http
GET / HTTP/1.1
Host: 10.0.0.2
```

Response:

```http
HTTP/1.1 200 OK
Content-Length: 30

Hello from my C# network stack
```

### Final Milestone

Run:

```bash
curl http://<my-stack-ip>/
```

and receive:

```text
Hello from my C# network stack
```

with the entire path:

```text
Ethernet
   ↓
ARP
   ↓
IPv4
   ↓
TCP
   ↓
HTTP
```

implemented by my C# code.

---

# C# Features Worth Using

This project should also be an opportunity to understand systems-oriented modern C#.

Explore:

```text
Span<byte>
ReadOnlySpan<byte>
Memory<byte>
ReadOnlyMemory<byte>
BinaryPrimitives
ArrayPool<byte>
ref struct
readonly struct
ValueTask
System.Net.IPAddress
```

Example packet parsing:

```csharp
public readonly ref struct TcpHeader
{
    private readonly ReadOnlySpan<byte> _data;

    public TcpHeader(ReadOnlySpan<byte> data)
    {
        _data = data;
    }

    public ushort SourcePort =>
        BinaryPrimitives.ReadUInt16BigEndian(_data);

    public ushort DestinationPort =>
        BinaryPrimitives.ReadUInt16BigEndian(_data[2..]);

    public uint SequenceNumber =>
        BinaryPrimitives.ReadUInt32BigEndian(_data[4..]);

    public uint AcknowledgmentNumber =>
        BinaryPrimitives.ReadUInt32BigEndian(_data[8..]);
}
```

Avoid unnecessary abstractions initially.

The bytes **are part of the lesson**.

---

# Testing Strategy

Every protocol should have unit tests using known byte sequences.

For example:

```text
Raw Bytes
    ↓
Parser
    ↓
Expected fields
```

And:

```text
Object
    ↓
Serializer
    ↓
Expected bytes
```

Eventually test:

```text
Parse(Serialize(packet))
```

but don't rely exclusively on round-trip tests because the parser and serializer can contain matching mistakes.

Use known-good packet captures as test vectors.

---

# Wireshark

Capture everything.

Useful filters:

```text
arp
icmp
tcp
udp
ip.addr == <my-stack-ip>
tcp.port == 8080
```

For TCP, inspect:

```text
SEQ
ACK
SYN
ACK flag
FIN
RST
Window
Checksum
Options
Payload
```

When something fails, inspect the actual bytes before changing the code.

---

# Specifications

Use the RFCs as specifications rather than tutorials.

Important starting points:

```text
Ethernet     IEEE 802.3 / Ethernet II framing
ARP          RFC 826
IPv4         RFC 791
ICMP         RFC 792
UDP          RFC 768
TCP          RFC 9293
```

Additional TCP RFCs will become relevant when implementing congestion control and modern TCP behavior.

---

# Progress

## Layer 2

- [x] Ethernet frame parser
- [x] Ethernet frame serializer
- [x] MAC address representation
- [x] EtherType dispatch
- [x] ARP parser
- [x] ARP serializer
- [x] ARP cache
- [x] Respond to ARP request

## Layer 3

- [x] IPv4 parser
- [x] IPv4 serializer
- [x] IPv4 checksum
- [x] Protocol dispatch
- [x] ICMP parser
- [x] ICMP Echo Reply
- [x] **Ping works**

## Layer 4 — UDP

- [ ] UDP parser
- [ ] UDP serializer
- [ ] UDP checksum
- [ ] UDP echo server
- [ ] **OS UDP client works**

## Layer 4 — TCP

- [ ] TCP parser
- [ ] TCP serializer
- [ ] TCP checksum
- [ ] TCP state machine
- [ ] LISTEN
- [ ] SYN processing
- [ ] SYN+ACK
- [ ] ACK processing
- [ ] **Three-way handshake works**
- [ ] Payload receive
- [ ] Payload send
- [ ] Sequence tracking
- [ ] ACK generation
- [ ] Retransmission
- [ ] Receive window
- [ ] FIN
- [ ] TIME_WAIT
- [ ] **OS TcpClient works**

## Application

- [ ] Minimal HTTP parser
- [ ] HTTP response
- [ ] **curl works**

---

# Success Criteria

The project is successful when I can explain **why each packet exists**, not merely make the tests pass.

I should eventually be able to look at:

```text
Ethernet
  IPv4
    TCP
```

in Wireshark and understand the relationship between:

```text
MAC address
    ↓
IP address
    ↓
Port
    ↓
TCP connection
    ↓
Application protocol
```

The ultimate test:

```text
curl
 ↓
OS networking
 ↓
Ethernet
 ↓
My C# Ethernet implementation
 ↓
My ARP implementation
 ↓
My IPv4 implementation
 ↓
My TCP implementation
 ↓
My HTTP implementation
 ↓
"Hello from my C# network stack"
```

At that point TCP/IP isn't just an abstraction I'm using.

**It's a system I've built.**