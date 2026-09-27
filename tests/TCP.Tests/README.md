# Receive-path regression checks

Run from the repository root:

```sh
dotnet run --project tests/TCP.Tests/TCP.Tests.csproj
```

This dependency-free test executable uses an in-memory Ethernet port. It checks
malformed ICMP recovery, local MAC filtering, valid ARP and conflict probes,
invalid source rejection, connected-route neighbor learning, and cancellation
during startup and idle receive. Failed checks exit with an exception.

The host has a connected-subnet route by default. Supply `--gateway <IPv4>` to the host command to configure an off-subnet default route; neighbor resolution then targets that gateway.

Native libpcap behavior and actual packet delivery require a live-interface test.
