using System.Net;
using TCP.L2.Link.Bridge;
using TCP.Networking.Pcap;

namespace TCP.Host;

internal static class HostCommand
{
    private const string ServeCommand = "--serve";
    private const string BridgeCommand = "--bridge";
    private const string InterfaceOption = "--interface";
    private const string InterfacesOption = "--interfaces";
    private const string IpOption = "--ip";
    private const string GatewayOption = "--gateway";
    private const string MtuOption = "--mtu";
    private const string TtlOption = "--ttl";
    private const string ServeUsage = "Usage: --serve --interface <device> --ip <unused IPv4> [--gateway <IPv4>] [--mtu <bytes>] [--ttl <1-255>]";
    private const string BridgeUsage = "Usage: --bridge --interfaces <device1,device2,...>";
    private const ushort DefaultBridgeVlan = 1;
    private const int InvalidArgumentsExitCode = 2;

    public static int Run(string[] args)
    {
        try
        {
            var options = ParseOptions(args);
            using var cancellation = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cancellation.Cancel();
            };

            if (args[0] == ServeCommand)
            {
                RunHost(options, cancellation.Token);
            }
            else if (args[0] == BridgeCommand)
            {
                RunBridge(options, cancellation.Token);
            }
            else
            {
                throw new ArgumentException("Use --serve for an IPv4 host or --bridge for an Ethernet bridge.");
            }

            return 0;
        }
        catch (Exception error) when (error is ArgumentException or FormatException or OverflowException or IOException or InvalidOperationException)
        {
            Console.Error.WriteLine(error.Message);
            return InvalidArgumentsExitCode;
        }
    }

    private static Dictionary<string, string> ParseOptions(string[] args)
    {
        if ((args.Length - 1) % 2 != 0)
        {
            throw new ArgumentException("Options require a value.");
        }

        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 1; index < args.Length; index += 2)
        {
            var name = args[index];
            var value = args[index + 1];
            if (!options.TryAdd(name, value))
            {
                throw new ArgumentException($"Duplicate option {name}.");
            }
        }

        return options;
    }

    private static void RunHost(IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken)
    {
        var allowedOptions = new[] { InterfaceOption, IpOption, GatewayOption, MtuOption, TtlOption };
        if (options.Keys.Any(option => !allowedOptions.Contains(option, StringComparer.Ordinal)) ||
            !options.ContainsKey(InterfaceOption) || !options.ContainsKey(IpOption))
        {
            throw new ArgumentException(ServeUsage);
        }

        var interfaceName = options[InterfaceOption];
        var address = IPAddress.Parse(options[IpOption]);
        var gateway = options.TryGetValue(GatewayOption, out var gatewayText) ? IPAddress.Parse(gatewayText) : null;
        var mtu = options.TryGetValue(MtuOption, out var mtuText) ? int.Parse(mtuText) : (int?)null;

        using var host = PcapNetworkConfiguration.CreateStack(interfaceName, address, gateway, mtu);
        if (options.TryGetValue(TtlOption, out var ttlText))
        {
            host.IPv4.DefaultTimeToLive = byte.Parse(ttlText);
        }

        host.NeighborResolutionFailed += address => Console.Error.WriteLine($"ARP resolution failed for {address}.");
        host.AddressClaimed += () =>
        {
            Console.WriteLine($"Serving ARP and ICMPv4 for {address} on {interfaceName} ({host.HardwareAddress}).");
            Console.WriteLine("Press Ctrl+C to stop.");
        };
        host.IPv4.EchoRequestAnswered += (packet, request) => Console.WriteLine(
            $"ICMP: echo reply queued to {packet.SourceAddress} id={request.Identifier} seq={request.SequenceNumber}");
        host.Run(cancellationToken);
    }

    private static void RunBridge(IReadOnlyDictionary<string, string> options, CancellationToken cancellationToken)
    {
        if (options.Count != 1 || !options.TryGetValue(InterfacesOption, out var interfaceList))
        {
            throw new ArgumentException(BridgeUsage);
        }

        var interfaceNames = interfaceList.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (interfaceNames.Length < 2 || interfaceNames.Distinct(StringComparer.Ordinal).Count() != interfaceNames.Length)
        {
            throw new ArgumentException("Specify at least two distinct Ethernet interfaces.");
        }

        var ports = new List<BridgePort>();
        try
        {
            foreach (var interfaceName in interfaceNames)
            {
                var packetInterface = PcapPacketInterface.Open(interfaceName, promiscuous: true, inboundOnly: true);
                ports.Add(new BridgePort(packetInterface, DefaultBridgeVlan, new HashSet<ushort> { DefaultBridgeVlan }));
            }

            using var bridge = new LearningBridge(ports);
            Console.WriteLine($"Learning bridge on {string.Join(", ", interfaceNames)}. STP is not implemented; use a loop-free topology.");
            bridge.Run(cancellationToken);
        }
        finally
        {
            foreach (var port in ports)
            {
                port.Interface.Dispose();
            }
        }
    }
}
