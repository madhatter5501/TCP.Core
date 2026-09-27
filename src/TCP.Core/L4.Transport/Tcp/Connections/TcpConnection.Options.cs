using TCP.L4.Transport.Tcp.Handshake;
using TCP.L4.Transport.Tcp.Segments;

namespace TCP.L4.Transport.Tcp.Connections;

/// <summary>What a passive open learned about Fast Open from the SYN (RFC 7413 4.2).</summary>
/// <param name="Present">The SYN carried a Fast Open option, a cookie or a request for one.</param>
/// <param name="Accepted">The cookie was valid and the SYN carried data, so the data is accepted before the handshake completes.</param>
/// <param name="CookieToSend">A cookie to give the client on the SYN-ACK, when it asked for one or presented a stale one.</param>
internal readonly record struct FastOpenRequest(bool Present, bool Accepted, byte[]? CookieToSend)
{
    /// <summary>A Fast Open SYN whose cookie failed: its data must be ignored and resent by the client after the handshake.</summary>
    public bool RefusesData => Present && !Accepted;
}

/// <summary>Option negotiation on the SYN exchange, timestamps (RFC 7323) and the options each segment carries.</summary>
/// <remarks>
/// <para>
/// Every extension here is offered on our SYN and used only if the peer's SYN offers it too, so a peer without it
/// sees plain RFC 9293 TCP. A SYN-ACK may only carry options the SYN offered.
/// </para>
/// <list type="bullet">
/// <item>Window scaling (RFC 7323 2): each side states a shift; later window fields are multiplied by 2^shift.</item>
/// <item>Timestamps (RFC 7323 3-5): every segment carries our clock and echoes the peer's, which gives an RTT sample on
/// every ACK and lets PAWS reject old duplicates whose sequence numbers have wrapped.</item>
/// <item>SACK-permitted (RFC 2018): the receiver may report out-of-order blocks.</item>
/// <item>ECN (RFC 3168): negotiated by the ECE and CWR flags rather than an option.</item>
/// <item>User Timeout (RFC 5482) and Fast Open (RFC 7413).</item>
/// </list>
/// </remarks>
public sealed partial class TcpConnection
{
    private const int MaximumOptionSackBlocks = 4;
    private const int SackOptionOverhead = 4; // Two NOPs, kind and length.
    private static readonly TimeSpan TimestampRecentLifetime = TimeSpan.FromDays(24); // RFC 7323 5.5.

    private int _receiveScale;
    private int _sendScale;
    private bool _windowScaling;
    private bool _timestamps;
    private readonly uint _timestampOffset;
    private uint _recentTimestamp; // TS.Recent
    private DateTimeOffset _recentTimestampTime;
    private SequenceNumber _lastAcknowledgmentSent; // Last.ACK.sent
    private bool _sackPermitted;
    private bool _ecnRequested;
    private bool _ecn;
    private FastOpenRequest _fastOpen;
    private byte[]? _fastOpenCookie; // Client: the cookie (or empty request) our SYN carries.
    private bool _fastOpenDataSent;
    private ulong _sendNext64; // SND.NXT with its sequence number extension, for TCP-AO.
    private ulong _receiveNext64; // RCV.NXT likewise.

    /// <summary>Whether window scaling was negotiated.</summary>
    public bool WindowScalingEnabled => _windowScaling;

    /// <summary>Whether timestamps were negotiated.</summary>
    public bool TimestampsEnabled => _timestamps;

    /// <summary>Whether SACK was negotiated.</summary>
    public bool SelectiveAcknowledgmentsEnabled => _sackPermitted;

    /// <summary>Whether ECN was negotiated.</summary>
    public bool ExplicitCongestionNotificationEnabled => _ecn;

    /// <summary>Whether segments are signed and verified with TCP-AO or MD5.</summary>
    public bool Authenticated => _authenticator is not null;

    /// <summary>Whether data went, or came, on the SYN under a valid Fast Open cookie.</summary>
    public bool FastOpenUsed => FastOpenAccepted || _fastOpenDataSent;

    /// <summary>A server accepted Fast Open data before the handshake completed.</summary>
    private bool FastOpenAccepted => _fastOpen.Accepted;

    /// <summary>Bytes of options on every segment, which the payload budget must leave room for.</summary>
    private int FixedOptionLength => (_timestamps ? TcpOptions.AlignedTimestampLength : 0) + (_authenticator?.OptionLength ?? 0);

    /// <summary>Our timestamp clock (TSval): host milliseconds plus a per-connection offset, so it reveals nothing across connections.</summary>
    private uint TimestampClock => unchecked(_host.TimestampClock + _timestampOffset);

    /// <summary>SYN, plus ECE and CWR to request ECN (RFC 3168 6.1.1), or ACK and ECE to accept it.</summary>
    private TcpFlags SynFlags()
    {
        if (_activeOpen)
        {
            _ecnRequested = _settings.ExplicitCongestionNotification;
            return TcpFlags.Syn | (_ecnRequested ? TcpFlags.Ece | TcpFlags.Cwr : TcpFlags.None);
        }
        return TcpFlags.Syn | TcpFlags.Ack | (_ecn ? TcpFlags.Ece : TcpFlags.None);
    }

    /// <summary>The smallest shift that lets <paramref name="capacity"/> bytes be advertised in 16 bits (RFC 7323 2.3).</summary>
    internal static int WindowScaleFor(int capacity)
    {
        var shift = 0;
        while (shift < TcpOptions.MaximumWindowScale && capacity >> shift > TcpWireFormat.MaximumUnscaledWindow) shift++;
        return shift;
    }

    /// <summary>
    /// Everything a SYN teaches us about the peer: its initial sequence number (which starts our receive space), its
    /// MSS and first window, and which extensions both sides offered. The MSS then fixes the initial congestion window.
    /// </summary>
    private void LearnPeerSyn(TcpSegment syn, TcpOptions options)
    {
        _peerInitialSequence = syn.SequenceNumber;
        _receive.Start(_peerInitialSequence);
        _receiveNext64 = _receive.Next.Value;
        _peerMss = options.MaximumSegmentSize is > 0 and var mss ? mss : TcpWireFormat.DefaultIPv4Mss;
        _authenticator?.SetInitialSequences(_initialSequence.Value, _peerInitialSequence.Value);
        Negotiate(options.WindowScale, _settings.SelectiveAcknowledgments && options.SackPermitted,
            _activeOpen ? _ecnRequested && syn.Has(TcpFlags.Ece) && !syn.Has(TcpFlags.Cwr)
                        : _settings.ExplicitCongestionNotification && syn.Has(TcpFlags.Ece) && syn.Has(TcpFlags.Cwr));
        if (_settings.Timestamps && options.Timestamp is { } timestamp)
        {
            _timestamps = true;
            RememberTimestamp(timestamp.Value);
        }
        if (options.UserTimeout is { } timeout) AdoptPeerUserTimeout(timeout);
        _sendWindow.Start(syn);
        _congestion.Start(MaximumSegmentSize, _settings.InitialWindowSegments);
        _persist.Schedule(Now, _rtt.TimeoutSeconds);
    }

    /// <summary>
    /// Rebuilds negotiated state from a SYN cookie and the ACK that returned it. Options survive only if timestamps
    /// carried them; the peer's window in the ACK is already scaled.
    /// </summary>
    private void LearnCookie(TcpSegment ack, TcpOptions options, SynCookie cookie)
    {
        _peerInitialSequence = (SequenceNumber)ack.SequenceNumber - TcpWireFormat.ControlSequenceLength;
        _receive.Start(_peerInitialSequence);
        _receiveNext64 = _receive.Next.Value;
        _peerMss = cookie.MaximumSegmentSize;
        _authenticator?.SetInitialSequences(_initialSequence.Value, _peerInitialSequence.Value);
        var agreed = cookie.Options;
        Negotiate(agreed?.PeerWindowScale, agreed?.SackPermitted == true, agreed?.ExplicitCongestionNotification == true);
        if (agreed is not null && options.Timestamp is { } timestamp)
        {
            _timestamps = true;
            RememberTimestamp(timestamp.Value);
        }
        _sendWindow.Start(ack); // Not a SYN, so the negotiated scale already applies.
        _congestion.Start(MaximumSegmentSize, _settings.InitialWindowSegments);
        _persist.Schedule(Now, _rtt.TimeoutSeconds);
    }

    /// <summary>Settles window scaling, SACK and ECN once both SYNs are known.</summary>
    private void Negotiate(byte? peerWindowScale, bool sack, bool ecn)
    {
        _windowScaling = _settings.WindowScaling && peerWindowScale is not null;
        _sendScale = _windowScaling ? peerWindowScale!.Value : 0;
        if (!_windowScaling) _receiveScale = 0;
        _sendWindow.SetScale(_sendScale);
        _receive.SetMaximumWindow(TcpWireFormat.MaximumUnscaledWindow << _receiveScale);
        _sackPermitted = sack;
        _ecn = ecn;
    }

    /// <summary>
    /// RFC 5482 3.1: when allowed, adopt the peer's advertised user timeout if it is longer than ours, within the
    /// configured bounds: min(U_LIMIT, max(local, remote, L_LIMIT)).
    /// </summary>
    private void AdoptPeerUserTimeout(TimeSpan remote)
    {
        if (!_settings.AcceptPeerUserTimeout) return;
        var (lower, upper) = _settings.UserTimeoutLimits;
        var local = _userTimeout ?? TimeSpan.Zero;
        var adopted = remote > local ? remote : local;
        if (adopted < lower) adopted = lower;
        _userTimeout = adopted < upper ? adopted : upper;
    }

    /// <summary>
    /// The options for one outgoing segment, in priority order so that the least important drop out when 40 bytes
    /// are not enough: authentication, MSS, timestamps and SACK-permitted, window scale, user timeout, Fast Open,
    /// then SACK blocks, which must also fit in the segment's payload budget.
    /// </summary>
    /// <returns>The options area and the offset of the MAC placeholder, if the segment is to be signed.</returns>
    private (byte[] Options, int? MacOffset) BuildOptions(TcpFlags flags, int dataLength)
    {
        var writer = new TcpOptionWriter();
        var macOffset = _authenticator?.AddOption(writer);
        var timestamp = new TcpTimestamp(TimestampClock, (flags & TcpFlags.Ack) != TcpFlags.None ? _recentTimestamp : 0);
        if ((flags & TcpFlags.Syn) != TcpFlags.None) AddSynOptions(writer, timestamp);
        else if (_timestamps && (flags & TcpFlags.Rst) == TcpFlags.None) writer.TryAdd(TcpOptionWriter.Timestamp(timestamp));
        if (_advertiseUserTimeout && _userTimeout is { } timeout && (flags & TcpFlags.Rst) == TcpFlags.None)
            writer.TryAdd(TcpOptionWriter.UserTimeout(timeout));
        if ((flags & (TcpFlags.Syn | TcpFlags.Rst)) == TcpFlags.None && (flags & TcpFlags.Ack) != TcpFlags.None)
            AddSackBlocks(writer, dataLength);
        return (writer.ToArray(), macOffset);
    }

    /// <summary>
    /// A SYN offers what the settings allow; a SYN-ACK echoes only what the SYN offered (RFC 7323 2.2, 3.2; RFC 2018 2).
    /// </summary>
    private void AddSynOptions(TcpOptionWriter writer, TcpTimestamp timestamp)
    {
        writer.TryAdd(TcpOptionWriter.MaximumSegmentSize(_host.AdvertisedMss));
        var offerTimestamps = _activeOpen ? _settings.Timestamps : _timestamps;
        var offerSack = _activeOpen ? _settings.SelectiveAcknowledgments : _sackPermitted;
        var offerScale = _activeOpen ? _settings.WindowScaling : _windowScaling;
        if (offerTimestamps && offerSack) writer.TryAdd(TcpOptionWriter.SackPermittedAndTimestamp(timestamp));
        else if (offerTimestamps) writer.TryAdd(TcpOptionWriter.Timestamp(timestamp));
        else if (offerSack) writer.TryAdd(TcpOptionWriter.SackPermitted());
        if (offerScale) writer.TryAdd(TcpOptionWriter.WindowScale((byte)_receiveScale));
        if (_activeOpen && _fastOpenCookie is { } cookie) writer.TryAdd(TcpOptionWriter.FastOpen(cookie));
        if (!_activeOpen && _fastOpen.CookieToSend is { } issued) writer.TryAdd(TcpOptionWriter.FastOpen(issued));
    }

    /// <summary>Adds as many SACK blocks (and any pending D-SACK) as fit in the options area and the segment's payload budget.</summary>
    private void AddSackBlocks(TcpOptionWriter writer, int dataLength)
    {
        if (!_sackPermitted) return;
        var room = Math.Min(TcpWireFormat.MaximumOptionsLength - writer.Length, BaseSegmentSize - dataLength - writer.Length);
        var count = Math.Min(MaximumOptionSackBlocks, (room - SackOptionOverhead) / TcpOptions.SackBlockLength);
        var blocks = _receive.SackBlocks(count);
        if (blocks.Count > 0) writer.TryAdd(TcpOptionWriter.Sack(blocks));
    }

    /// <summary>Records the peer's TSval as TS.Recent, the value our segments echo.</summary>
    private void RememberTimestamp(uint value)
    {
        _recentTimestamp = value;
        _recentTimestampTime = Now;
    }

    /// <summary>
    /// PAWS (RFC 7323 5.3): a segment whose TSval is older than TS.Recent is an old duplicate, perhaps from a previous
    /// wrap of the sequence space. TS.Recent that has been idle for 24 days is stale and no longer trusted.
    /// </summary>
    private bool FailsPaws(TcpSegment segment, TcpOptions options)
    {
        if (!_timestamps || segment.Has(TcpFlags.Rst) || options.Timestamp is not { } timestamp) return false;
        if (unchecked((int)(timestamp.Value - _recentTimestamp)) >= 0) return false;
        if (Now - _recentTimestampTime <= TimestampRecentLifetime) return true;
        RememberTimestamp(timestamp.Value);
        return false;
    }

    /// <summary>
    /// RFC 7323 4.3: take the segment's TSval as TS.Recent when it is not older and the segment starts at or before
    /// the last acknowledgment we sent, so the echoed value belongs to the data that moved RCV.NXT.
    /// </summary>
    private void UpdateRecentTimestamp(TcpSegment segment, TcpOptions options)
    {
        if (!_timestamps || options.Timestamp is not { } timestamp) return;
        if (unchecked((int)(timestamp.Value - _recentTimestamp)) >= 0 && (SequenceNumber)segment.SequenceNumber <= _lastAcknowledgmentSent)
            RememberTimestamp(timestamp.Value);
    }

    /// <summary>
    /// The Fast Open part of an active open (RFC 7413 4.1): with a cached cookie, move up to one segment of queued
    /// data onto the SYN; without one, send a cookie request when the application supplied initial data.
    /// </summary>
    private byte[] TakeFastOpenData()
    {
        if (!_settings.FastOpen || _unsent.Count == 0 || _authenticator is not null) return [];
        if (!_host.FastOpenCookies.TryGet(RemoteAddress, out var cookie, out var mss))
        {
            _fastOpenCookie = [];
            return [];
        }
        _fastOpenCookie = cookie;
        _peerMss = mss;
        // MSS excludes options (RFC 6691), so leave room for a full SYN options area.
        _fastOpenDataSent = true;
        return _unsent.Dequeue(Math.Max(0, BaseSegmentSize - TcpWireFormat.MaximumOptionsLength));
    }

    /// <summary>
    /// The SYN-ACK of a Fast Open attempt (RFC 7413 4.1.3): cache any cookie it carries, and if it acknowledged only
    /// our SYN, the SYN's data was refused and must be resent now.
    /// </summary>
    private void LearnFastOpenReply(TcpSegment synAck, TcpOptions options)
    {
        if (_fastOpenCookie is null) return;
        if (options.FastOpenCookie is { Length: > 0 } cookie) _host.FastOpenCookies.Store(RemoteAddress, cookie, _peerMss);
        if (!_fastOpenDataSent || _unacknowledged.IsEmpty) return;
        // Only the SYN was acknowledged: the server refused the data. Without a fresh cookie, stop trying.
        _fastOpenDataSent = false;
        if (options.FastOpenCookie is not { Length: > 0 }) _host.FastOpenCookies.Remove(RemoteAddress);
        foreach (var segment in _unacknowledged.Segments) segment.Lost = true;
    }

    /// <summary>
    /// Buffers data a SYN carried (RFC 9293 3.10.7.2, RFC 7413 4.2.2). It becomes readable immediately; the
    /// application hears of it on Fast Open acceptance, or otherwise once the handshake completes.
    /// </summary>
    private void BufferSynData(TcpSegment syn)
    {
        _receive.Accept(_receive.Next, syn.Payload.Span, fin: false, ReceiveWindow);
        _receiveNext64 = _receive.Next.Value;
    }

    /// <summary>The 64-bit form of <paramref name="sequence"/> nearest <paramref name="reference"/>, whose high half is TCP-AO's SNE.</summary>
    private static uint SequenceExtension(SequenceNumber sequence, ulong reference) =>
        (uint)((ulong)((long)reference + unchecked((int)(sequence.Value - (uint)reference))) >> 32);
}
