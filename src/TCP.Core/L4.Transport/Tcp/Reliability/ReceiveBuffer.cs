using TCP.L4.Transport.Tcp.Buffers;
using TCP.L4.Transport.Tcp.Connections;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.L4.Transport.Tcp.Reliability;

/// <summary>What one arriving segment did to the receive sequence space; the connection's ACK policy depends on it.</summary>
/// <param name="StreamEnded">The peer's FIN was reached in order.</param>
/// <param name="OutOfOrder">New data landed beyond a gap, so the peer needs a duplicate ACK and SACK now.</param>
/// <param name="FilledGap">The segment advanced RCV.NXT across data that had been waiting out of order.</param>
/// <param name="Duplicate">Some of the segment had already been received (a D-SACK will report it).</param>
internal readonly record struct ReceiveOutcome(bool StreamEnded, bool OutOfOrder, bool FilledGap, bool Duplicate);

/// <summary>
/// The receive sequence space: reassembles out-of-order data, holds in-order bytes until the application reads
/// them, decides the window to offer (RCV.NXT and RCV.WND), and describes its holes as SACK blocks.
/// </summary>
/// <remarks>
/// <para>
/// IP may deliver segments late, duplicated or out of order. Data that arrives ahead of RCV.NXT waits as
/// non-overlapping ranges sorted by sequence number. When the gap fills they move, in order, to the readable queue
/// that <see cref="TcpConnection.Read"/> drains. A FIN is remembered at its sequence number and takes effect only
/// once every byte before it has arrived.
/// </para>
/// <para>
/// The waiting ranges are exactly what SACK (RFC 2018) reports, most recently changed first. When a segment repeats
/// data we already hold, the repeat is reported once as a D-SACK block (RFC 2883), which lets the sender detect
/// spurious retransmissions and reordering.
/// </para>
/// <para>
/// The window this buffer offers is the flow-control half of TCP on our side: free space the peer may fill.
/// It is written into every outgoing segment by <see cref="TcpConnection"/>.
/// </para>
/// </remarks>
/// <param name="capacity">Maximum bytes buffered, which caps the window we can offer.</param>
internal sealed class ReceiveBuffer(int capacity)
{
    private const int MaximumRecentArrivals = 8;

    private readonly ByteQueue _readable = new();
    private readonly List<(SequenceNumber Start, byte[] Data)> _outOfOrder = []; // Sorted, non-overlapping.
    private readonly List<SequenceNumber> _recentArrivals = []; // One byte of each recently changed range, newest first.
    private SackBlock? _duplicate;
    private SequenceNumber? _finSequence;
    private SequenceNumber _advertisedEdge; // RCV.NXT + RCV.WND as last sent.
    private bool _hasAdvertised;
    private int _maximumWindow = TcpWireFormat.MaximumUnscaledWindow;

    /// <summary>RCV.NXT: the next sequence number expected from the peer.</summary>
    public SequenceNumber Next { get; private set; }

    /// <summary>In-order bytes waiting for the application to read.</summary>
    public int Available => _readable.Count;

    /// <summary>Whether any data waits beyond a gap.</summary>
    public bool HasOutOfOrderData => _outOfOrder.Count > 0;

    /// <summary>
    /// Begins the receive sequence space from the peer's SYN: its SYN consumes the initial sequence number
    /// (IRS), so the first data byte is expected at IRS + 1.
    /// </summary>
    public void Start(SequenceNumber peerInitialSequence)
    {
        Next = peerInitialSequence + TcpWireFormat.ControlSequenceLength;
        _hasAdvertised = false;
    }

    /// <summary>Caps the window at what the 16-bit field can express with the negotiated scale (65,535 x 2^scale).</summary>
    public void SetMaximumWindow(int maximum) => _maximumWindow = maximum;

    /// <summary>
    /// The window to offer. Its right edge never moves backward, and only advances once it can move by at least
    /// min(buffer / 2, MSS), so a slow reader does not invite tiny segments (RFC 1122 4.2.3.3).
    /// </summary>
    public int Window(int mss)
    {
        var free = Math.Clamp(capacity - _readable.Count, 0, _maximumWindow);
        if (!_hasAdvertised) return free;
        var offered = (int)Math.Clamp((long)unchecked((int)(_advertisedEdge - Next)), 0, _maximumWindow);
        var step = Math.Max(1, Math.Min(capacity / 2, mss));
        return free - offered >= step ? free : offered;
    }

    /// <summary>
    /// Remembers the right edge (RCV.NXT + window) just sent to the peer. A window may shrink only by the
    /// peer filling it, never by us pulling the edge back, and <see cref="Window"/> honors that.
    /// </summary>
    public void RecordAdvertisement(int window)
    {
        _advertisedEdge = Next + (uint)window;
        _hasAdvertised = true;
    }

    /// <summary>
    /// Whether a window update would tell the peer anything new. After the application reads, this decides
    /// if an ACK is worth sending or would only repeat the last advertisement.
    /// </summary>
    public bool AdvertisedEdgeWouldMove(int mss) => Next + (uint)Window(mss) != _advertisedEdge;

    /// <summary>Moves readable bytes into <paramref name="destination"/>, freeing buffer space.</summary>
    /// <returns>Bytes copied; zero when nothing is readable.</returns>
    public int Read(Span<byte> destination) => _readable.Dequeue(destination);

    /// <summary>
    /// Buffers the bytes and FIN of a segment that fall within <paramref name="window"/>. Bytes already held are
    /// ignored (the first arrival wins) and remembered for a D-SACK.
    /// </summary>
    /// <param name="sequence">Sequence number of the first payload byte.</param>
    /// <param name="payload">The segment's data.</param>
    /// <param name="fin">Whether the segment carries FIN, which follows the last payload byte.</param>
    /// <param name="window">Bytes acceptable beyond RCV.NXT.</param>
    public ReceiveOutcome Accept(SequenceNumber sequence, ReadOnlySpan<byte> payload, bool fin, int window)
    {
        var hadGap = HasOutOfOrderData;
        var nextBefore = Next;
        var duplicate = NoteDuplicate(sequence, payload.Length);
        var outOfOrder = BufferPayload(sequence, payload, window);
        if (fin) BufferFin(sequence + (uint)payload.Length, window);
        MoveInOrderBytesToReadable();
        var filledGap = hadGap && Next != nextBefore && !outOfOrder;
        if (_finSequence != Next) return new ReceiveOutcome(false, outOfOrder, filledGap, duplicate);
        ConsumeFin();
        return new ReceiveOutcome(true, outOfOrder, filledGap, duplicate);
    }

    /// <summary>
    /// SACK blocks for the next ACK, at most <paramref name="maximum"/>: a pending D-SACK first (reported only once),
    /// then the ranges that changed most recently, as RFC 2018 4 requires, then any others in sequence order.
    /// </summary>
    public IReadOnlyList<SackBlock> SackBlocks(int maximum)
    {
        var blocks = new List<SackBlock>();
        if (maximum <= 0) return blocks;
        if (_duplicate is { } duplicate) blocks.Add(duplicate);
        _duplicate = null;
        var ranges = MergedRanges();
        _recentArrivals.RemoveAll(marker => !ranges.Any(r => r.Covers(marker, marker + 1)));
        foreach (var marker in _recentArrivals)
        {
            var range = ranges.First(r => r.Covers(marker, marker + 1));
            if (!blocks.Contains(range)) blocks.Add(range);
        }
        blocks.AddRange(ranges.Where(r => !blocks.Contains(r)));
        return [.. blocks.Take(maximum)];
    }

    /// <summary>
    /// Records a segment that lay wholly below RCV.NXT, so rejected before reaching <see cref="Accept"/>, as a D-SACK
    /// block: the sender learns its retransmission was unnecessary (RFC 2883 4.1).
    /// </summary>
    public void ReportDuplicate(SequenceNumber start, uint length)
    {
        if (length > 0) _duplicate = new SackBlock(start, start + length);
    }

    /// <summary>Drops data still waiting for a gap to fill. Used when the connection closes: it can never become readable.</summary>
    public void DiscardOutOfOrder()
    {
        _outOfOrder.Clear();
        _recentArrivals.Clear();
    }

    /// <summary>Drops unread in-order bytes. Used when the connection fails, so an aborted stream yields no further data.</summary>
    public void DiscardReadable() => _readable.Clear();

    /// <summary>
    /// Records the first stretch of the segment we already hold, below RCV.NXT or inside a waiting range, as the
    /// D-SACK block for the next ACK (RFC 2883 4).
    /// </summary>
    /// <returns>Whether any of the segment was a duplicate.</returns>
    private bool NoteDuplicate(SequenceNumber sequence, int length)
    {
        if (length == 0) return false;
        var end = sequence + (uint)length;
        if (sequence < Next)
        {
            _duplicate = new SackBlock(sequence, end < Next ? end : Next);
            return true;
        }
        foreach (var (start, data) in _outOfOrder)
        {
            var rangeEnd = start + (uint)data.Length;
            if (end <= start || rangeEnd <= sequence) continue;
            _duplicate = new SackBlock(sequence > start ? sequence : start, end < rangeEnd ? end : rangeEnd);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Inserts the new parts of the payload that lie in the window and before any FIN, around the ranges already
    /// held.
    /// </summary>
    /// <returns>Whether new data landed beyond RCV.NXT (out of order).</returns>
    private bool BufferPayload(SequenceNumber sequence, ReadOnlySpan<byte> payload, int window)
    {
        var start = sequence < Next ? Next : sequence;
        var end = sequence + (uint)payload.Length;
        var windowEnd = Next + (uint)window;
        if (windowEnd < end) end = windowEnd;
        if (_finSequence is { } fin && fin < end) end = fin;
        if (end <= start) return false;
        var outOfOrder = false;
        var cursor = start;
        foreach (var (held, data) in _outOfOrder.ToArray())
        {
            var heldEnd = held + (uint)data.Length;
            if (heldEnd <= cursor) continue;
            if (end <= held) break;
            if (cursor < held) outOfOrder |= Insert(cursor, payload, sequence, held);
            cursor = heldEnd;
        }
        if (cursor < end) outOfOrder |= Insert(cursor, payload, sequence, end);
        return outOfOrder;
    }

    /// <summary>Stores payload bytes [from, to) as a new waiting range and notes it as the most recent arrival.</summary>
    /// <returns>Whether the range lies beyond RCV.NXT.</returns>
    private bool Insert(SequenceNumber from, ReadOnlySpan<byte> payload, SequenceNumber payloadStart, SequenceNumber to)
    {
        var data = payload.Slice((int)(from - payloadStart), (int)(to - from)).ToArray();
        var index = _outOfOrder.FindIndex(r => from < r.Start);
        _outOfOrder.Insert(index < 0 ? _outOfOrder.Count : index, (from, data));
        if (from == Next) return false;
        _recentArrivals.Remove(from);
        _recentArrivals.Insert(0, from);
        if (_recentArrivals.Count > MaximumRecentArrivals) _recentArrivals.RemoveAt(_recentArrivals.Count - 1);
        return true;
    }

    /// <summary>
    /// Remembers where the peer's stream ends. A FIN seen earlier in sequence space replaces a later one,
    /// so a retransmission cannot extend the stream.
    /// </summary>
    private void BufferFin(SequenceNumber fin, int window)
    {
        if (!fin.IsWithin(Next, (uint)window) || _finSequence is { } existing && existing <= fin) return;
        _finSequence = fin;
        _outOfOrder.RemoveAll(r => fin <= r.Start);
    }

    /// <summary>Advances RCV.NXT across every contiguous range now present, stopping at a gap or at the FIN.</summary>
    private void MoveInOrderBytesToReadable()
    {
        while (_outOfOrder.Count > 0 && _outOfOrder[0].Start == Next)
        {
            var data = _outOfOrder[0].Data;
            _outOfOrder.RemoveAt(0);
            _readable.Enqueue(data);
            Next += (uint)data.Length;
        }
    }

    /// <summary>The FIN occupies one sequence number; step past it and discard anything buffered beyond the stream's end.</summary>
    private void ConsumeFin()
    {
        Next += TcpWireFormat.ControlSequenceLength;
        DiscardOutOfOrder();
        _finSequence = null;
    }

    /// <summary>The waiting ranges with adjacent ones joined: the blocks SACK can report.</summary>
    private List<SackBlock> MergedRanges()
    {
        var ranges = new List<SackBlock>();
        foreach (var (start, data) in _outOfOrder)
        {
            var end = start + (uint)data.Length;
            if (ranges.Count > 0 && ranges[^1].End == start) ranges[^1] = ranges[^1] with { End = end };
            else ranges.Add(new SackBlock(start, end));
        }
        return ranges;
    }
}
