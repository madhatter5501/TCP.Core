using System.Collections.Concurrent;
using TCP.L1.Physical;

namespace TCP.Transport.Kestrel.Tests;

/// <summary>An in-memory Ethernet cable between a server port and a client port, with a frame log and fault injection.</summary>
internal sealed class VirtualEthernet
{
    public VirtualEthernet()
    {
        Server = new VirtualPort(this, fromServer: true, "virtual-server");
        Client = new VirtualPort(this, fromServer: false, "virtual-client");
    }

    public VirtualPort Server { get; }
    public VirtualPort Client { get; }
    public ConcurrentQueue<FrameInfo> Log { get; } = new();

    /// <summary>Decides the fault for each frame. Replace it between tests; frames already queued are unaffected.</summary>
    public volatile Func<FrameInfo, FrameFault> Fault = _ => FrameFault.None;

    private void Transmit(VirtualPort from, byte[] frame)
    {
        var info = FrameInfo.Parse(from.FromServer, frame);
        Log.Enqueue(info);
        var destination = from == Server ? Client : Server;
        switch (Fault(info))
        {
            case FrameFault.Drop:
                return;
            case FrameFault.Duplicate:
                destination.Deliver([.. frame]);
                destination.Deliver([.. frame]);
                return;
            case FrameFault.Corrupt:
                var corrupted = frame.ToArray();
                corrupted[^1] ^= 0xFF;
                destination.Deliver(corrupted);
                return;
            case FrameFault.Reorder:
                destination.Hold([.. frame]);
                return;
            default:
                destination.Deliver([.. frame]);
                destination.ReleaseHeld();
                return;
        }
    }

    internal sealed class VirtualPort(VirtualEthernet link, bool fromServer, string name) : IPacketInterface
    {
        private readonly ConcurrentQueue<byte[]> _received = new();
        private byte[]? _held; // Only touched by the single sender thread of this direction.
        public bool FromServer { get; } = fromServer;
        public string InterfaceName { get; } = name;

        public int Receive(byte[] buffer)
        {
            if (!_received.TryDequeue(out var frame)) return 0;
            frame.CopyTo(buffer, 0);
            return frame.Length;
        }

        public void Send(byte[] frame) => link.Transmit(this, frame);
        internal void Deliver(byte[] frame) => _received.Enqueue(frame);

        internal void Hold(byte[] frame)
        {
            ReleaseHeld();
            _held = frame;
        }

        internal void ReleaseHeld()
        {
            if (_held is { } frame) { _held = null; Deliver(frame); }
        }
        public void Dispose() => _received.Clear();
    }
}
