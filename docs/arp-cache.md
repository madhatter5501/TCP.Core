# C# ARP Cache From Scratch

## Goal

Implement an **ARP cache / IPv4 neighbor-resolution subsystem** in C# as part of a custom network stack.

The ARP cache is responsible for answering:

```text
Given:

    Interface + IPv4 next-hop address

Find:

    Ethernet MAC address
```

Conceptually:

```text
IPv4 Address → MAC Address
```

But a real cache needs more than a simple dictionary because resolution is asynchronous, mappings become stale, requests can fail, and packets may need to wait while an address is being resolved.

---

# Where ARP Fits

ARP sits between IPv4 routing and Ethernet transmission.

```text
Application
     │
     ▼
TCP / UDP / ICMP
     │
     ▼
IPv4
     │
     │ Destination: 8.8.8.8
     ▼
Routing Table
     │
     │ Next Hop: 192.168.1.1
     │ Interface: eth0
     ▼
ARP Cache
     │
     │ 192.168.1.1
     │      ↓
     │ AA:BB:CC:DD:EE:FF
     ▼
Ethernet
     │
     ▼
NIC
```

The routing table determines:

```text
Destination IP
      ↓
Outgoing Interface
      +
Next-Hop IPv4 Address
```

ARP determines:

```text
Interface + Next-Hop IPv4 Address
                 ↓
              MAC Address
```

Ethernet can then construct the frame.

---

# ARP Is Not the Routing Table

The routing table might contain:

```text
Destination       Gateway          Interface
─────────────────────────────────────────────
192.168.1.0/24    directly         eth0
0.0.0.0/0         192.168.1.1     eth0
```

ARP might contain:

```text
Interface    IPv4            MAC
────────────────────────────────────────────────
eth0         192.168.1.1     AA:BB:CC:DD:EE:FF
eth0         192.168.1.42    12:34:56:78:90:AB
```

These solve different problems.

---

# ARP Cache Is Not a Switch MAC Table

A Layer-2 switch maintains something conceptually like:

```text
MAC Address                 Switch Port
────────────────────────────────────────
AA:BB:CC:DD:EE:FF           Port 4
12:34:56:78:90:AB           Port 7
```

That answers:

> Which switch port should receive a frame destined for this MAC?

An ARP cache answers:

> Which MAC address should I use to reach this IPv4 neighbor?

```text
Switch:

MAC → physical/logical switch port


ARP:

IPv4 → MAC
```

---

# Basic ARP Cache Entry

Start simple.

```csharp
public sealed class ArpEntry
{
    public required IPv4Address IpAddress { get; init; }

    public required MacAddress MacAddress { get; set; }

    public required NetworkInterface Interface { get; init; }

    public DateTimeOffset UpdatedAt { get; set; }
}
```

Conceptually:

```text
┌─────────────────────────────────────┐
│ ARP Entry                           │
├─────────────────────────────────────┤
│ Interface      eth0                 │
│ IPv4           192.168.1.1          │
│ MAC            AA:BB:CC:DD:EE:FF    │
│ Updated        10:42:31             │
└─────────────────────────────────────┘
```

---

# Cache Key

Do not necessarily think of the cache as globally:

```text
IPv4 → MAC
```

Prefer:

```text
(Interface, IPv4) → ARP Entry
```

For example:

```csharp
public readonly record struct ArpCacheKey(
    NetworkInterfaceId Interface,
    IPv4Address Address);
```

Then:

```csharp
Dictionary<ArpCacheKey, ArpEntry>
```

This allows the stack to eventually support multiple Layer-2 interfaces correctly.

---

# Why It Isn't Just a Dictionary

Suppose IPv4 wants to transmit to:

```text
192.168.1.42
```

The cache contains no entry.

The stack cannot construct the Ethernet frame yet because it doesn't know:

```text
Destination MAC = ???
```

It must begin ARP resolution.

```text
IPv4 wants to send packet
          │
          ▼
Routing determines:
    interface = eth0
    next-hop  = 192.168.1.42
          │
          ▼
ARP lookup
          │
      ┌───┴────┐
      │        │
    HIT       MISS
      │        │
      ▼        ▼
Use MAC     Begin ARP
            resolution
```

A cache miss therefore starts an asynchronous process.

---

# ARP Resolution

For a missing address:

```text
192.168.1.42
```

create an unresolved entry:

```text
┌──────────────────────────────┐
│ IPv4       192.168.1.42      │
│ Interface  eth0              │
│ State      INCOMPLETE        │
│ MAC        unknown           │
│ Attempts   1                 │
└──────────────────────────────┘
```

Then broadcast:

```text
Ethernet Destination:
FF:FF:FF:FF:FF:FF

ARP:

Who has 192.168.1.42?
Tell 192.168.1.10
```

---

# Resolution Flow

```text
IPv4 Packet
     │
     ▼
Determine next-hop
     │
     ▼
ARP Cache Lookup
     │
     ├─────────────────────┐
     │                     │
    HIT                   MISS
     │                     │
     ▼                     ▼
Get MAC             Create INCOMPLETE
     │                     │
     │               Send ARP Request
     │                     │
     │               Queue IPv4 Packet
     │                     │
     │               Wait for Reply
     │                     │
     │                     ▼
     │               ARP Reply
     │                     │
     │                     ▼
     │                Update Entry
     │                     │
     │                     ▼
     │                Flush Queue
     │                     │
     └──────────┬──────────┘
                ▼
        Construct Ethernet Frame
                │
                ▼
               NIC
```

---

# Entry States

A useful initial state machine:

```csharp
public enum ArpState
{
    Incomplete,
    Reachable,
    Stale,
    Failed
}
```

## Incomplete

Resolution is currently happening.

```text
IPv4:       192.168.1.42
MAC:        unknown
State:      INCOMPLETE
Attempts:   1
```

An ARP request has been sent and the stack is waiting for a reply.

---

## Reachable

A valid mapping exists.

```text
IPv4:       192.168.1.42
MAC:        AA:BB:CC:DD:EE:FF
State:      REACHABLE
```

Packets can immediately be transmitted.

---

## Stale

A mapping exists but has aged enough that the stack should no longer assume indefinitely that it is correct.

```text
IPv4:       192.168.1.42
MAC:        AA:BB:CC:DD:EE:FF
State:      STALE
```

The exact stale/revalidation behavior can be added later.

---

## Failed

Resolution failed.

```text
IPv4:       192.168.1.42
MAC:        unknown
State:      FAILED
Attempts:   3
```

Queued packets cannot currently be delivered.

---

# State Machine

Initial simplified model:

```text
                 Lookup Miss
                     │
                     ▼
               ┌────────────┐
               │ INCOMPLETE │
               └──────┬─────┘
                      │
             ┌────────┴────────┐
             │                 │
         ARP Reply          Timeout
             │                 │
             ▼                 ▼
       ┌───────────┐      Retry Request
       │ REACHABLE │            │
       └─────┬─────┘            │
             │                  │
             │ age              │ max retries
             ▼                  ▼
         ┌───────┐          ┌────────┐
         │ STALE │          │ FAILED │
         └───────┘          └────────┘
```

Do not over-engineer the state machine initially.

Get basic resolution working first.

---

# More Complete Entry

Once basic ARP works, an entry might evolve toward:

```csharp
public sealed class ArpEntry
{
    public required IPv4Address IpAddress { get; init; }

    public MacAddress? MacAddress { get; set; }

    public required NetworkInterface Interface { get; init; }

    public ArpState State { get; set; }

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset LastUpdatedAt { get; set; }

    public DateTimeOffset? LastUsedAt { get; set; }

    public DateTimeOffset? LastRequestAt { get; set; }

    public int ResolutionAttempts { get; set; }

    public bool IsStatic { get; init; }
}
```

An unresolved entry intentionally has:

```csharp
MacAddress = null;
State = ArpState.Incomplete;
```

---

# Pending Packets

An important part of ARP resolution is deciding what happens to packets while resolution is underway.

Suppose TCP produces:

```text
IPv4 Packet #1
IPv4 Packet #2
IPv4 Packet #3
```

all destined through:

```text
192.168.1.42
```

but ARP hasn't resolved the MAC yet.

Don't send three ARP requests unnecessarily.

Instead:

```text
192.168.1.42

State:
INCOMPLETE

Pending:
┌───────────────┐
│ IPv4 Packet 1 │
│ IPv4 Packet 2 │
│ IPv4 Packet 3 │
└───────────────┘

ARP Requests:
1
```

When the reply arrives:

```text
192.168.1.42
      ↓
AA:BB:CC:DD:EE:FF
```

flush the pending packets:

```text
Packet 1 ──┐
Packet 2 ──┼──→ Ethernet → NIC
Packet 3 ──┘
```

---

# Possible Resolution API

Avoid designing ARP purely around:

```csharp
MacAddress? Lookup(IPv4Address address);
```

because that hides the asynchronous nature of resolution.

Eventually an API might look conceptually like:

```csharp
Task<MacAddress> ResolveAsync(
    NetworkInterface networkInterface,
    IPv4Address address,
    CancellationToken cancellationToken);
```

Usage:

```csharp
var mac = await arpCache.ResolveAsync(
    interface,
    nextHop,
    cancellationToken);
```

Internally:

```text
ResolveAsync()
     │
     ▼
Entry exists and usable?
     │
  ┌──┴───┐
 YES     NO
  │       │
return   Begin resolution
 MAC       │
           ▼
      Send ARP Request
           │
           ▼
      Await ARP Reply
           │
           ▼
       return MAC
```

The exact API should evolve from actual requirements rather than being fixed prematurely.

---

# ARP Request Handling

Your stack will also receive ARP requests.

Example:

```text
Who has 192.168.1.10?
Tell 192.168.1.5
```

If:

```text
192.168.1.10
```

belongs to your interface, respond:

```text
192.168.1.10 is at
AA:BB:CC:DD:EE:FF
```

Flow:

```text
Receive Ethernet Frame
          │
          ▼
EtherType = ARP
          │
          ▼
Parse ARP Packet
          │
          ▼
Is this a REQUEST?
          │
          ▼
Is Target IP ours?
       │
   ┌───┴───┐
  YES      NO
   │        │
   ▼        ▼
Reply     Ignore
```

---

# ARP Reply Handling

When receiving:

```text
192.168.1.42 is at
AA:BB:CC:DD:EE:FF
```

find the corresponding incomplete entry.

Before:

```text
IPv4:     192.168.1.42
MAC:      null
State:    INCOMPLETE
```

After:

```text
IPv4:     192.168.1.42
MAC:      AA:BB:CC:DD:EE:FF
State:    REACHABLE
```

Then:

```text
1. Cancel resolution timer
2. Reset retry state
3. Complete waiting resolution
4. Flush queued packets
```

---

# Retries

ARP requests can be lost.

Initial implementation:

```text
Send Request
     │
     ▼
Wait
     │
     ├── Reply → REACHABLE
     │
     └── Timeout
            │
            ▼
         Retry
            │
            ▼
       Max attempts?
        │        │
       NO       YES
        │        │
        ▼        ▼
      Retry    FAILED
```

Keep the retry policy configurable rather than embedding magic numbers throughout the implementation.

For example:

```csharp
public sealed class ArpOptions
{
    public TimeSpan ResolutionTimeout { get; init; }

    public int MaximumResolutionAttempts { get; init; }

    public TimeSpan ReachableLifetime { get; init; }
}
```

---

# Cache Expiration

ARP mappings should not live forever.

Example:

```text
192.168.1.42
     │
     ▼
AA:BB:CC:DD:EE:FF
```

Later, that machine could disappear and another machine could acquire the same IPv4 address.

Therefore:

```text
REACHABLE
    │
    │ time
    ▼
STALE
```

Eventually the entry can be refreshed or removed.

Don't implement sophisticated expiration behavior until basic ARP resolution works.

---

# Static Entries

Eventually support mappings that don't expire:

```text
192.168.1.1
     ↓
AA:BB:CC:DD:EE:FF

STATIC
```

Example:

```csharp
arpCache.AddStatic(
    interface,
    IPv4Address.Parse("192.168.1.1"),
    MacAddress.Parse("AA:BB:CC:DD:EE:FF"));
```

Static entries should not participate in normal expiration.

---

# Suggested Components

```text
Arp/
│
├── ArpPacket.cs
├── ArpOperation.cs
├── ArpCache.cs
├── ArpEntry.cs
├── ArpCacheKey.cs
├── ArpState.cs
├── ArpResolver.cs
├── ArpOptions.cs
└── MacAddress.cs
```

Potential responsibility split:

```text
ArpPacket
    Wire representation

ArpCache
    Stores neighbor information

ArpResolver
    Performs asynchronous resolution

ArpEntry
    Represents resolution state

ArpOptions
    Timing / retry configuration
```

Don't create every abstraction immediately. Introduce them when responsibilities actually emerge.

---

# First Implementation

Keep version 1 deliberately small.

```csharp
public sealed class ArpCache
{
    private readonly Dictionary<ArpCacheKey, ArpEntry> _entries = new();

    public bool TryGet(
        NetworkInterfaceId networkInterface,
        IPv4Address address,
        out MacAddress macAddress)
    {
        // ...
    }

    public void Update(
        NetworkInterfaceId networkInterface,
        IPv4Address address,
        MacAddress macAddress)
    {
        // ...
    }
}
```

Initially:

```text
ARP Request
     ↓
ARP Reply
     ↓
cache.Update()
     ↓
IPv4 → MAC available
```

Then evolve it.

---

# Implementation Progression

## Stage 1 — Basic Cache

- [ ] Define `MacAddress`
- [ ] Define `ArpCacheKey`
- [ ] Define `ArpEntry`
- [ ] Store IPv4 → MAC mappings
- [ ] Lookup mappings
- [ ] Associate entries with an interface

Success:

```text
eth0 + 192.168.1.1
        ↓
AA:BB:CC:DD:EE:FF
```

---

## Stage 2 — ARP Packets

- [ ] Parse ARP request
- [ ] Parse ARP reply
- [ ] Serialize ARP request
- [ ] Serialize ARP reply
- [ ] Validate packet fields

Success:

```text
Raw Ethernet payload
       ↓
    ArpPacket
```

---

## Stage 3 — Respond to ARP

- [ ] Receive broadcast ARP request
- [ ] Determine whether target IP belongs to us
- [ ] Generate ARP reply
- [ ] Send Ethernet response

Success:

```text
arp -a
```

or the operating system's equivalent neighbor command shows the MAC for the IP owned by the custom stack.

---

## Stage 4 — Active Resolution

- [ ] Detect cache miss
- [ ] Create `INCOMPLETE` entry
- [ ] Broadcast ARP request
- [ ] Receive ARP reply
- [ ] Update entry to `REACHABLE`

Success:

```text
ResolveAsync(192.168.1.42)

→ AA:BB:CC:DD:EE:FF
```

---

## Stage 5 — Pending Packets

- [ ] Queue packets while resolution is pending
- [ ] Prevent duplicate simultaneous resolutions
- [ ] Flush packets after successful resolution
- [ ] Fail/drop queued packets when resolution fails

---

## Stage 6 — Reliability

- [ ] Resolution timeout
- [ ] ARP request retries
- [ ] Maximum retry count
- [ ] `FAILED` state
- [ ] Cancellation

---

## Stage 7 — Cache Lifecycle

- [ ] Track entry age
- [ ] Mark old entries stale
- [ ] Remove expired entries
- [ ] Refresh mappings
- [ ] Static entries

---

## Stage 8 — Multiple Interfaces

- [ ] Interface-specific cache keys
- [ ] Independent resolution per interface
- [ ] Correct source IPv4 selection
- [ ] Correct source MAC selection

---

# Tests

## Cache Test

```text
Given:

eth0
192.168.1.42
AA:BB:CC:DD:EE:FF

When:

cache.Update(...)

Then:

cache lookup

returns:

AA:BB:CC:DD:EE:FF
```

---

## Resolution Test

```text
Resolve(192.168.1.42)
        │
        ▼
Cache Miss
        │
        ▼
ARP Request Sent
        │
        ▼
Inject ARP Reply
        │
        ▼
Resolution Completes
        │
        ▼
AA:BB:CC:DD:EE:FF
```

---

## Timeout Test

```text
Resolve()
    │
    ▼
ARP Request
    │
    X  no reply
    │
    ▼
Timeout
    │
    ▼
Retry
    │
    X
    ▼
FAILED
```

---

## Duplicate Resolution Test

Two callers simultaneously request:

```text
192.168.1.42
```

Expected:

```text
Caller A ──┐
           ├──→ ONE ARP resolution
Caller B ──┘

               ↓

        AA:BB:CC:DD:EE:FF

               ↓

Caller A ←─────┤
Caller B ←─────┘
```

Do not unnecessarily broadcast two independent ARP requests.

---

# Wireshark

Useful filter:

```text
arp
```

Watch for:

```text
ARP Request

Who has 192.168.1.42?
Tell 192.168.1.10
```

followed by:

```text
ARP Reply

192.168.1.42 is at
AA:BB:CC:DD:EE:FF
```

Then compare those packets with the internal cache state.

```text
Wireshark                       ArpCache

ARP Request        →           INCOMPLETE

ARP Reply          →           REACHABLE
                               MAC = AA:BB:...
```

---

# Questions the Implementation Should Eventually Answer

When writing each feature, be able to explain:

- Why does ARP use an Ethernet broadcast for requests?
- Why isn't the destination IP enough to send an Ethernet frame?
- Why does routing happen before ARP resolution?
- Why do I ARP for the gateway instead of a remote Internet host?
- Why is the interface part of neighbor resolution?
- Why can't an ARP cache simply live forever?
- What happens to an IP packet while ARP resolution is pending?
- What happens when ARP resolution fails?
- What happens when multiple packets need the same unresolved neighbor?
- What happens when an IP address moves to another MAC address?
- How should unsolicited ARP replies affect the cache?
- What is a gratuitous ARP?
- How does ARP spoofing/poisoning work?
- Why doesn't a normal Layer-2 switch need an ARP cache to forward Ethernet frames?

---

# Important Mental Model

The entire path can be reduced to three different questions:

```text
ROUTING

"Where should this IP packet go?"

Destination IP
      ↓
Next-Hop IP + Interface


ARP

"What Ethernet address represents that next hop?"

Interface + Next-Hop IP
      ↓
MAC Address


ETHERNET

"Send a frame to that MAC."

Destination MAC
      ↓
Ethernet Frame
      ↓
NIC
```

Or:

```text
Destination IP
      │
      ▼
  Routing Table
      │
      ▼
Next-Hop IP
      +
 Interface
      │
      ▼
   ARP Cache
      │
      ▼
Destination MAC
      │
      ▼
Ethernet Frame
```

The ARP cache is therefore not simply a lookup table.

It is the stateful bridge between **IPv4's idea of a neighbor** and **Ethernet's idea of a destination**.
