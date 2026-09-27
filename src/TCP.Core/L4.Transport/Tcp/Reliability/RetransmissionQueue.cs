using TCP.L4.Transport.Tcp.Connections;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.L4.Transport.Tcp.Reliability;

/// <summary>What the SACK blocks of one ACK changed.</summary>
/// <param name="NewlySacked">Segments the ACK reported as received for the first time.</param>
/// <param name="DuplicateBlock">A D-SACK block (RFC 2883): data the peer received more than once, or null.</param>
internal readonly record struct SackOutcome(IReadOnlyList<UnackedSegment> NewlySacked, SackBlock? DuplicateBlock);

/// <summary>Sent segments awaiting acknowledgment, oldest first, with the SACK scoreboard.</summary>
/// <remarks>
/// <para>
/// TCP delivers reliably by keeping a copy of everything sent until the peer acknowledges it. This queue holds
/// that sequence space, from SND.UNA up to SND.NXT, so the <see cref="TcpConnection"/> can resend after a
/// timeout, a detected loss, a path MTU drop or a zero-window probe.
/// </para>
/// <para>
/// It is also the scoreboard of RFC 6675: each segment records whether the peer has selectively acknowledged it
/// (SACKed), whether it is presumed lost and awaiting resend, and when it was last sent. From those flags the
/// connection computes "pipe", its estimate of the data actually still in the network.
/// </para>
/// </remarks>
internal sealed class RetransmissionQueue
{
    private readonly List<UnackedSegment> _segments = [];

    /// <summary>Number of segments awaiting acknowledgment.</summary>
    public int Count => _segments.Count;

    /// <summary>Nothing is in flight, so no retransmission timer needs to run.</summary>
    public bool IsEmpty => _segments.Count == 0;

    /// <summary>The segment at SND.UNA: the one retransmitted first.</summary>
    public UnackedSegment Oldest => _segments[0];

    /// <summary>The most recently sent new data, which a tail loss probe resends.</summary>
    public UnackedSegment Newest => _segments[^1];

    /// <summary>The segments, oldest first.</summary>
    public IReadOnlyList<UnackedSegment> Segments => _segments;

    /// <summary>Payload bytes held for retransmission; counts against the send buffer limit.</summary>
    public int BufferedBytes => _segments.Sum(s => s.Data.Length);

    /// <summary>Whether any unacknowledged segment carries data, as opposed to only SYN or FIN. Nagle's algorithm uses this.</summary>
    public bool HasData => _segments.Any(s => s.Data.Length > 0);

    /// <summary>Segments the peer has selectively acknowledged.</summary>
    public int SackedCount => _segments.Count(s => s.Sacked);

    /// <summary>RFC 6675 pipe: sequence space presumed still in the network, meaning neither SACKed nor presumed lost.</summary>
    public long Pipe => _segments.Where(s => s.InPipe).Sum(s => (long)s.Length);

    /// <summary>Whether any segment is presumed lost and waiting to be resent.</summary>
    public bool HasLost => _segments.Any(s => s.Lost);

    /// <summary>Appends a newly sent segment; it must start at the previous segment's end.</summary>
    public void Add(UnackedSegment segment) => _segments.Add(segment);

    /// <summary>Forgets everything in flight, as when the connection closes.</summary>
    public void Clear() => _segments.Clear();

    /// <summary>Whether <paramref name="segment"/> is still awaiting acknowledgment and has not been removed meanwhile.</summary>
    public bool Contains(UnackedSegment segment) => _segments.Contains(segment);

    /// <summary>Whether <paramref name="sequence"/> falls inside data still in flight. Used to check that an ICMP error quotes a live segment.</summary>
    public bool Covers(SequenceNumber sequence) => _segments.Any(s => s.Covers(sequence));

    /// <summary>A copy for iterating while resends, which can deliver ACKs synchronously, modify the queue.</summary>
    public UnackedSegment[] Snapshot() => [.. _segments];

    /// <summary>
    /// After a retransmission timeout, presume everything not SACKed lost so it is resent as the window allows. SACKed
    /// segments stay: the receiver holds them unless it reneges, which the cumulative ACK would reveal (RFC 2018 8).
    /// </summary>
    public void MarkAllLost()
    {
        foreach (var segment in _segments.Where(s => !s.Sacked)) segment.Lost = true;
    }

    /// <summary>Withdraws every loss presumption, when a timeout proves spurious (RFC 4015).</summary>
    public void ClearLost()
    {
        foreach (var segment in _segments) segment.Lost = false;
    }

    /// <summary>After a path MTU drop, presume every segment too big for the new MSS lost: routers discard rather than fragment it.</summary>
    public void MarkOversizedLost(int maximumPayload)
    {
        foreach (var segment in _segments.Where(s => s.Data.Length > maximumPayload && !s.Sacked)) segment.Lost = true;
    }

    /// <summary>
    /// Cuts every segment carrying more than <paramref name="maximumPayload"/> bytes into pieces that fit, so each
    /// piece is resent and acknowledged on its own rather than only the first MSS of it.
    /// </summary>
    public void SplitOversized(int maximumPayload)
    {
        // A tail that is still too big is visited, and cut again, on the next iteration.
        for (var i = 0; i < _segments.Count; i++)
            if (_segments[i].Data.Length > maximumPayload) _segments.Insert(i + 1, _segments[i].SplitAt(maximumPayload));
    }

    /// <summary>Drops everything below <paramref name="acknowledgment"/>, trimming a partly acknowledged segment.</summary>
    public AcknowledgedSegments RemoveAcknowledged(SequenceNumber acknowledgment)
    {
        var completed = _segments.Where(s => s.End <= acknowledgment).ToArray();
        var includesRetransmission = _segments.Any(s => s.Sequence < acknowledgment && s.Retransmitted);
        _segments.RemoveAll(s => s.End <= acknowledgment);
        if (!IsEmpty && Oldest.Sequence < acknowledgment) Oldest.TrimThrough(acknowledgment);
        return new AcknowledgedSegments(completed, includesRetransmission);
    }

    /// <summary>
    /// Applies the SACK blocks of an ACK (RFC 2018, RFC 6675 5): marks each segment they fully cover, splitting
    /// segments at block edges so partial coverage is recorded exactly. A first block below the cumulative ACK, or
    /// inside the second block, is a D-SACK and marks nothing (RFC 2883 4). Blocks outside (SND.UNA, SND.NXT] are
    /// ignored as invalid.
    /// </summary>
    public SackOutcome ApplySack(IReadOnlyList<SackBlock> blocks, SequenceNumber acknowledgment, SequenceNumber sendNext)
    {
        SackBlock? duplicate = null;
        var newlySacked = new List<UnackedSegment>();
        for (var i = 0; i < blocks.Count; i++)
        {
            var block = blocks[i];
            if (!(block.Start < block.End)) continue;
            if (i == 0 && IsDuplicateReport(blocks, acknowledgment))
            {
                duplicate = block;
                continue;
            }
            if (block.Start < acknowledgment || sendNext < block.End) continue;
            SplitAt(block.Start);
            SplitAt(block.End);
            foreach (var segment in _segments.Where(s => !s.Sacked && block.Covers(s.Sequence, s.End)))
            {
                segment.Sacked = true;
                segment.Lost = false;
                newlySacked.Add(segment);
            }
        }
        return new SackOutcome(newlySacked, duplicate);
    }

    /// <summary>RFC 2883 4: the first block reports a duplicate if it lies below the cumulative ACK or within the second block.</summary>
    private static bool IsDuplicateReport(IReadOnlyList<SackBlock> blocks, SequenceNumber acknowledgment) =>
        blocks[0].End <= acknowledgment || (blocks.Count > 1 && blocks[1].Covers(blocks[0].Start, blocks[0].End));

    /// <summary>Splits the data segment that contains <paramref name="sequence"/> strictly inside it, so a block edge falls between segments.</summary>
    private void SplitAt(SequenceNumber sequence)
    {
        var index = _segments.FindIndex(s => s.Sequence < sequence && sequence < s.End);
        if (index < 0) return;
        var segment = _segments[index];
        var offset = (int)(sequence - segment.Sequence) - (segment.Has(TcpFlags.Syn) ? 1 : 0);
        if (offset <= 0 || offset >= segment.Data.Length) return;
        _segments.Insert(index + 1, segment.SplitAt(offset));
    }
}

/// <summary>A sent segment kept until acknowledged so it can be retransmitted.</summary>
/// <remarks>
/// It stores the stream content (data plus SYN/FIN) rather than the wire bytes, so a resend can carry a fresh
/// ACK number, window and options, and can be cut to a smaller MSS after a path MTU drop. It also records when it
/// was sent, for RTT sampling and RACK, and its place on the SACK scoreboard.
/// </remarks>
/// <param name="sequence">Sequence number of its first byte, or of its SYN.</param>
/// <param name="flags">Flags it was sent with; SYN and FIN occupy sequence space.</param>
/// <param name="data">Payload bytes.</param>
/// <param name="firstSent">Time of the original transmission, used for RTT sampling.</param>
internal sealed class UnackedSegment(SequenceNumber sequence, TcpFlags flags, byte[] data, DateTimeOffset firstSent)
{
    /// <summary>First unacknowledged sequence number; advances if the peer acknowledges part of the segment.</summary>
    public SequenceNumber Sequence { get; private set; } = sequence;

    /// <summary>Flags to resend with. Settable because a simultaneous open turns our SYN into a SYN-ACK.</summary>
    public TcpFlags Flags { get; set; } = flags;

    /// <summary>Unacknowledged payload; shrinks from the front on a partial acknowledgment.</summary>
    public byte[] Data { get; private set; } = data;

    /// <summary>When the segment first went out; the start of its RTT sample.</summary>
    public DateTimeOffset FirstSent { get; } = firstSent;

    /// <summary>When the segment was most recently sent; RACK compares these times (RFC 8985 5.2).</summary>
    public DateTimeOffset LastSent { get; set; } = firstSent;

    /// <summary>
    /// Position of the most recent transmission in the connection's send order. RACK breaks ties between equal send
    /// times with it, so a retransmission always counts as sent after everything sent before it.
    /// </summary>
    public long TransmitOrder { get; set; }

    /// <summary>The timestamp value (TSval) of the most recent transmission, for spurious-retransmission detection.</summary>
    public uint TimestampValue { get; set; }

    /// <summary>Resent at least once. Its ACK is then ambiguous and must not be timed (Karn's algorithm).</summary>
    public bool Retransmitted { get; set; }

    /// <summary>Presumed lost, by a timeout, RACK, duplicate ACKs or a path MTU drop, and not yet resent.</summary>
    public bool Lost { get; set; }

    /// <summary>The peer reported this segment in a SACK block, so it need not be resent.</summary>
    public bool Sacked { get; set; }

    /// <summary>Counted in pipe: neither SACKed nor waiting to be resent.</summary>
    public bool InPipe => !Sacked && !Lost;

    /// <summary>Sequence space occupied: payload bytes plus one each for SYN and FIN.</summary>
    public uint Length => TcpSegment.SequenceLengthOf(Flags, Data.Length);

    /// <summary>The sequence number just past this segment. An ACK at or beyond it acknowledges the whole segment.</summary>
    public SequenceNumber End => Sequence + Length;

    /// <summary>Whether any of the given flags is set.</summary>
    public bool Has(TcpFlags flag) => (Flags & flag) != TcpFlags.None;

    /// <summary>Whether <paramref name="sequence"/> lies within [Sequence, End).</summary>
    public bool Covers(SequenceNumber sequence) => sequence >= Sequence && sequence < End;

    /// <summary>
    /// Drops what the peer has already acknowledged, so a resend carries only the rest. An acknowledged SYN is
    /// removed first; with Fast Open the SYN can be acknowledged while the data it carried is not.
    /// </summary>
    public void TrimThrough(SequenceNumber acknowledgment)
    {
        if (Has(TcpFlags.Syn))
        {
            Flags = WithoutSyn(Flags);
            Sequence += TcpWireFormat.ControlSequenceLength;
        }
        Data = Data[checked((int)Math.Min(acknowledgment - Sequence, (uint)Data.Length))..];
        Sequence = acknowledgment;
    }

    /// <summary>
    /// Keeps the first <paramref name="size"/> payload bytes and returns the rest as a new segment that follows it.
    /// A FIN moves to the tail, since it comes after the last byte; the tail inherits the timing and scoreboard state.
    /// </summary>
    public UnackedSegment SplitAt(int size)
    {
        var tailData = Data[size..];
        var tailFlags = Has(TcpFlags.Syn) ? WithoutSyn(Flags) : Flags;
        Data = Data[..size];
        Flags &= ~TcpFlags.Fin;
        return new UnackedSegment(End, tailFlags, tailData, FirstSent)
        {
            LastSent = LastSent,
            TransmitOrder = TransmitOrder,
            TimestampValue = TimestampValue,
            Retransmitted = Retransmitted,
            Lost = Lost,
            Sacked = Sacked
        };
    }

    /// <summary>
    /// Flags for data that followed a SYN: without SYN or its ECN setup bits, and with ACK, which every segment
    /// after the handshake carries (a client's SYN had none).
    /// </summary>
    private static TcpFlags WithoutSyn(TcpFlags flags) => (flags & ~(TcpFlags.Syn | TcpFlags.Ece | TcpFlags.Cwr)) | TcpFlags.Ack;
}

/// <summary>
/// What one advancing ACK acknowledged, as returned by <see cref="RetransmissionQueue.RemoveAcknowledged"/>.
/// The <see cref="TcpConnection"/> uses it to take an RTT sample and to notice that its FIN was acknowledged.
/// </summary>
/// <param name="Completed">Segments acknowledged in full, oldest first.</param>
/// <param name="IncludesRetransmission">Whether any acknowledged byte had been retransmitted.</param>
internal sealed record AcknowledgedSegments(IReadOnlyList<UnackedSegment> Completed, bool IncludesRetransmission)
{
    /// <summary>Our FIN is now acknowledged, which advances the close handshake.</summary>
    public bool IncludesFin => Completed.Any(s => s.Has(TcpFlags.Fin));

    /// <summary>A SYN that needed resending is acknowledged, which triggers the RFC 6298 5.7 timeout floor.</summary>
    public bool IncludesRetransmittedSyn => Completed.Any(s => s.Retransmitted && s.Has(TcpFlags.Syn));

    /// <summary>The segment to time, if any: Karn's algorithm never samples across a retransmission.</summary>
    public UnackedSegment? RoundTripSample => Completed.Count > 0 && !IncludesRetransmission ? Completed[0] : null;
}
