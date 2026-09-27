using System.Runtime.InteropServices;
using System.Text;
using TCP.L1.Physical;

namespace TCP.Networking.Pcap;

/// <summary>Ethernet frame capture and injection through macOS libpcap/BPF.</summary>
public sealed class PcapPacketInterface : IPacketInterface
{
    public const int EthernetDataLinkType = 1;
    private const string PcapLibrary = "/usr/lib/libpcap.A.dylib";
    private const int ReadTimeoutMilliseconds = 100;

    private IntPtr _handle;

    private PcapPacketInterface(string interfaceName, IntPtr handle)
    {
        InterfaceName = interfaceName;
        _handle = handle;
    }

    public string InterfaceName { get; }

    public static PcapPacketInterface Open(string interfaceName, bool promiscuous = false, bool inboundOnly = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interfaceName);
        if (!OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException("The BPF packet interface currently supports macOS only.");
        }

        var errorBuffer = new StringBuilder(256);
        var handle = NativeMethods.OpenLive(
            interfaceName,
            IPacketInterface.MaximumFrameLength,
            promiscuous ? 1 : 0,
            ReadTimeoutMilliseconds,
            errorBuffer);
        if (handle == IntPtr.Zero)
        {
            throw new IOException($"Could not open packet capture on {interfaceName}: {errorBuffer}");
        }

        if (NativeMethods.DataLink(handle) != EthernetDataLinkType)
        {
            NativeMethods.Close(handle);
            throw new IOException($"Interface {interfaceName} does not expose Ethernet frames.");
        }

        if (NativeMethods.SetNonBlocking(handle, 1, errorBuffer) != 0)
        {
            NativeMethods.Close(handle);
            throw new IOException($"Could not enable nonblocking capture on {interfaceName}: {errorBuffer}");
        }

        if (inboundOnly && NativeMethods.SetDirection(handle, 1) != 0)
        {
            var error = GetError(handle);
            NativeMethods.Close(handle);
            throw new IOException($"Could not select inbound-only capture on {interfaceName}: {error}");
        }
        return new PcapPacketInterface(interfaceName, handle);
    }

    /// <summary>Returns a captured frame length, or zero immediately when no frame is available.</summary>
    public int Receive(byte[] buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        var handle = GetHandle();
        var result = NativeMethods.NextPacket(handle, out var headerPointer, out var packetPointer);
        if (result == 0)
        {
            return 0;
        }

        if (result < 0)
        {
            throw new IOException($"Packet capture failed on {InterfaceName}: {GetError(handle)}");
        }

        var header = Marshal.PtrToStructure<PacketHeader>(headerPointer);
        if (header.CapturedLength > buffer.Length)
        {
            throw new InvalidDataException("The captured Ethernet frame exceeds the receive buffer.");
        }

        var length = checked((int)header.CapturedLength);
        Marshal.Copy(packetPointer, buffer, 0, length);
        return length;
    }

    public void Send(byte[] frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        var handle = GetHandle();
        if (NativeMethods.SendPacket(handle, frame, frame.Length) != 0)
        {
            throw new IOException($"Packet injection failed on {InterfaceName}: {GetError(handle)}");
        }
    }

    private IntPtr GetHandle() => _handle != IntPtr.Zero
        ? _handle
        : throw new ObjectDisposedException(nameof(PcapPacketInterface));

    private static string GetError(IntPtr handle) =>
        Marshal.PtrToStringUTF8(NativeMethods.GetError(handle)) ?? "unknown libpcap error";

    public void Dispose()
    {
        var handle = _handle;
        _handle = IntPtr.Zero;
        if (handle != IntPtr.Zero)
        {
            NativeMethods.Close(handle);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PacketHeader
    {
        public long Seconds;
        public long Microseconds;
        public uint CapturedLength;
        public uint OriginalLength;
    }

    private static class NativeMethods
    {
        [DllImport(PcapLibrary, EntryPoint = "pcap_setdirection", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SetDirection(IntPtr handle, int direction);

        [DllImport(PcapLibrary, EntryPoint = "pcap_setnonblock", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SetNonBlocking(IntPtr handle, int nonBlocking, StringBuilder errorBuffer);

        [DllImport(PcapLibrary, EntryPoint = "pcap_open_live", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr OpenLive(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string device,
            int snapshotLength,
            int promiscuous,
            int timeoutMilliseconds,
            StringBuilder errorBuffer);

        [DllImport(PcapLibrary, EntryPoint = "pcap_datalink", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int DataLink(IntPtr handle);

        [DllImport(PcapLibrary, EntryPoint = "pcap_next_ex", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int NextPacket(IntPtr handle, out IntPtr header, out IntPtr packet);

        [DllImport(PcapLibrary, EntryPoint = "pcap_sendpacket", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SendPacket(IntPtr handle, byte[] packet, int length);

        [DllImport(PcapLibrary, EntryPoint = "pcap_geterr", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr GetError(IntPtr handle);

        [DllImport(PcapLibrary, EntryPoint = "pcap_close", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void Close(IntPtr handle);
    }
}
