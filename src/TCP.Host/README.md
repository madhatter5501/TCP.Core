# TCP.Host

A command-line runner for TCP.Core. It has three modes: offline protocol
diagnostics, an IPv4 host on a real network card, and an Ethernet bridge between
real network cards.

## Diagnostics (no arguments)

```sh
dotnet run --project src/TCP.Host
```

Builds packets in memory and prints what each layer sees: an ARP request and
reply learned into an `ArpCache`, an IPv4 round trip, protocol dispatch by number,
and a series of ICMP echo round trips. Needs no network access or privileges.

## Host on a real interface (`--serve`)

```sh
sudo dotnet run --project src/TCP.Host -- --serve --interface en0 --ip 192.168.1.250
```

| Option | Required | Meaning |
| --- | --- | --- |
| `--interface <device>` | yes | An Ethernet interface that is up, such as `en0` |
| `--ip <IPv4>` | yes | An unused address on one of that interface's subnets; not one the OS already holds |
| `--gateway <IPv4>` | no | Adds a default route through this router; without it only the connected subnet is reachable |
| `--mtu <bytes>` | no | Link MTU, from 68 up to the interface's own MTU (the default) |
| `--ttl <1-255>` | no | TTL for datagrams this host originates (default 64) |

The stack claims the address with RFC 5227 probes, then answers ARP and ICMP echo,
so you can `ping` it from another machine. It logs each echo reply and each failed
ARP resolution. Ctrl+C stops it.

## Bridge (`--bridge`)

```sh
sudo dotnet run --project src/TCP.Host -- --bridge --interfaces en1,en2
```

Opens each interface in promiscuous, inbound-only mode as an access port on VLAN 1
and runs a `LearningBridge` across them. This mode does not enable spanning tree, so
connect the interfaces in a loop-free topology.

## Requirements

- macOS: capture goes through `/usr/lib/libpcap.A.dylib` (see
  `src/TCP.Networking.Pcap`), and other platforms throw `PlatformNotSupportedException`.
- Access to the BPF devices, usually by running with `sudo`.
- An interface that libpcap exposes with Ethernet framing (data link type 1).

Bad arguments, a missing interface or a capture failure print a message (the usage
line for unknown or missing options) and exit with code 2.
