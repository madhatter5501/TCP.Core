using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using TCP.L2.Link.Ethernet;
using TCP.L3.Network.IPv4;
using TCP.L3.Network.IPv4.Routing;
using TCP.Stack;

namespace TCP.Networking.Pcap;

/// <summary>Creates an <see cref="TCP.Stack.EthernetStack"/> on a real interface through libpcap, validating the requested address, subnet and MTU.</summary>
public static class PcapNetworkConfiguration
{

    public static EthernetStack CreateStack(
        string interfaceName,
        IPAddress stackAddress,
        IPAddress? gateway,
        int? requestedMtu)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceName);
        if (stackAddress.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("An IPv4 address is required.", nameof(stackAddress));
        }

        var networkInterface = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(candidate =>
                candidate.Name == interfaceName &&
                candidate.OperationalStatus == OperationalStatus.Up)
            ?? throw new ArgumentException($"Network interface '{interfaceName}' is not present and up.");

        var macAddressBytes = networkInterface.GetPhysicalAddress().GetAddressBytes();
        if (macAddressBytes.Length != EthernetConstants.MacAddressLength)
        {
            throw new ArgumentException("An Ethernet interface is required.");
        }

        var configuredIPv4Addresses = networkInterface.GetIPProperties().UnicastAddresses
            .Where(unicast => unicast.Address.AddressFamily == AddressFamily.InterNetwork)
            .ToArray();
        if (configuredIPv4Addresses.Any(unicast => unicast.Address.Equals(stackAddress)))
        {
            throw new ArgumentException("The address is already assigned to the host interface.");
        }

        var subnet = configuredIPv4Addresses
            .Select(unicast => new IPv4Subnet(unicast.Address, unicast.IPv4Mask))
            .FirstOrDefault(candidate => candidate.Contains(stackAddress) && candidate.IsValidSource(stackAddress))
            ?? throw new ArgumentException("Choose a usable IPv4 address on an interface subnet.");

        var linkMtu = networkInterface.GetIPProperties().GetIPv4Properties().Mtu;
        var selectedMtu = requestedMtu ?? linkMtu;
        if (selectedMtu < IPv4Constants.MinimumMtu || selectedMtu > Math.Min(IPv4Packet.MaximumTotalLength, linkMtu))
        {
            throw new ArgumentOutOfRangeException(nameof(requestedMtu));
        }

        var packetInterface = PcapPacketInterface.Open(interfaceName);
        try
        {
            var stack = new EthernetStack(
                packetInterface,
                stackAddress,
                MacAddress.FromBytes(macAddressBytes),
                subnet,
                mtu: selectedMtu);
            if (gateway is not null)
            {
                var defaultRoute = new IPv4Route(
                    new IPv4Subnet(IPAddress.Any, IPAddress.Any),
                    gateway,
                    selectedMtu);
                stack.IPv4.Routes.Add(defaultRoute);
            }

            return stack;
        }
        catch
        {
            packetInterface.Dispose();
            throw;
        }
    }
}
