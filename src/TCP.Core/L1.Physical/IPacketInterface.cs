namespace TCP.L1.Physical;

/// <summary>One Ethernet port. Receive must return immediately when no frame is available.</summary>
/// <remarks>
/// <para>
/// This is the physical layer (L1) as the stack sees it: a device that moves whole Ethernet frames, destination
/// MAC through payload, without preamble or FCS. Everything above is software in this library.
/// <see cref="Stack.EthernetStack"/> runs a host on one port; <see cref="L2.Link.Bridge.LearningBridge"/> switches
/// between several.
/// </para>
/// <para>
/// Implementations include a libpcap-backed network card (<c>TCP.Networking.Pcap</c>) and in-memory virtual wires
/// for tests and simulation. Callers use it from a single thread and poll <see cref="Receive"/> in a loop, so it must
/// never block.
/// </para>
/// </remarks>
public interface IPacketInterface : IDisposable
{
    /// <summary>Receive buffer and capture length large enough for any frame this stack accepts.</summary>
    const int MaximumFrameLength = 65_536;

    /// <summary>The device name, such as <c>en0</c>. The bridge uses it to reject the same port being added twice.</summary>
    string InterfaceName { get; }

    /// <summary>Copies the next received frame, if any, into <paramref name="buffer"/> without waiting.</summary>
    /// <param name="buffer">At least <see cref="MaximumFrameLength"/> bytes.</param>
    /// <returns>The frame's length, or 0 when no frame is waiting.</returns>
    int Receive(byte[] buffer);

    /// <summary>Transmits one complete frame. The hardware adds the preamble and FCS.</summary>
    /// <param name="frame">The frame from destination MAC through payload, already padded to the Ethernet minimum.</param>
    void Send(byte[] frame);
}
