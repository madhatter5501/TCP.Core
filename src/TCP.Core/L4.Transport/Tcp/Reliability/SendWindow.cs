using TCP.L4.Transport.Tcp.Connections;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.L4.Transport.Tcp.Reliability;

/// <summary>The window the peer offers us: SND.WND with its update guards SND.WL1 and SND.WL2 (RFC 9293 3.10.7.4).</summary>
/// <remarks>
/// This is flow control: every segment the peer sends advertises how many more bytes its receive buffer
/// can take. The <see cref="TcpConnection"/> never has more than min(<see cref="Size"/>, the congestion window)
/// bytes in flight. A size of zero stops sending and hands control to the <see cref="PersistTimer"/>. Segments can
/// arrive reordered, so WL1 and WL2 record which segment last set the window, and older segments cannot shrink it
/// back. With window scaling (RFC 7323 2) the 16-bit field is shifted left by the peer's scale, except on SYNs.
/// </remarks>
internal sealed class SendWindow
{
    private SequenceNumber _updateSequence; // SND.WL1
    private SequenceNumber _updateAcknowledgment; // SND.WL2
    private int _scale;

    /// <summary>SND.WND: bytes the peer will accept beyond SND.UNA.</summary>
    public uint Size { get; private set; } = TcpWireFormat.MaximumUnscaledWindow;

    /// <summary>Largest window the peer has offered; sender silly-window avoidance measures against it.</summary>
    public uint Largest { get; private set; }

    /// <summary>Takes the first window from the peer's SYN unconditionally; it is never scaled and has no earlier update to guard against.</summary>
    public void Start(TcpSegment syn)
    {
        Accept(syn);
        Largest = Size;
    }

    /// <summary>Applies the peer's window scale shift (RFC 7323 2.2) to every later, non-SYN window field.</summary>
    public void SetScale(int shift) => _scale = shift;

    /// <summary>Takes the segment's window unless an earlier-sent segment carried it.</summary>
    public void Update(TcpSegment segment)
    {
        if (!IsNewerThanLastUpdate(segment)) return;
        Accept(segment);
        Largest = Math.Max(Largest, Size);
    }

    /// <summary>
    /// RFC 9293's update rule: the segment carries a later sequence number than the last update (SND.WL1 &lt; SEG.SEQ),
    /// or the same one with an equal or later acknowledgment (SND.WL1 = SEG.SEQ and SND.WL2 =&lt; SEG.ACK).
    /// </summary>
    private bool IsNewerThanLastUpdate(TcpSegment segment) =>
        _updateSequence < segment.SequenceNumber ||
        (_updateSequence == segment.SequenceNumber && _updateAcknowledgment <= segment.AcknowledgmentNumber);

    /// <summary>Records the segment's window and remembers the segment as the latest update (WL1, WL2).</summary>
    private void Accept(TcpSegment segment)
    {
        Size = segment.Has(TcpFlags.Syn) ? segment.Window : (uint)segment.Window << _scale;
        _updateSequence = segment.SequenceNumber;
        _updateAcknowledgment = segment.AcknowledgmentNumber;
    }
}
