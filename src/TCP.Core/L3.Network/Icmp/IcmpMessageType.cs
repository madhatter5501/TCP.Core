namespace TCP.L3.Network.Icmp;

/// <summary>ICMPv4 message type numbers used by the host.</summary>
/// <remarks>
/// Types 0 and 8 are queries (ping). The rest are error messages, which quote the offending datagram. A host
/// never sends an error about another error, which prevents error storms (RFC 1122 3.2.2).
/// </remarks>
public enum IcmpMessageType : byte
{
    /// <summary>Answer to an echo request ("pong").</summary>
    EchoReply = 0,
    /// <summary>A datagram could not be delivered; the code says why. Also carries "fragmentation needed" for path MTU discovery.</summary>
    DestinationUnreachable = 3,
    /// <summary>Obsolete congestion signal (RFC 6633). Recognized only so it is never answered with an error.</summary>
    SourceQuench = 4,
    /// <summary>A router advising that another on-link gateway is a better first hop for a destination.</summary>
    Redirect = 5,
    /// <summary>A ping: asks the target to echo the message back.</summary>
    EchoRequest = 8,
    /// <summary>TTL reached zero in transit, or fragment reassembly timed out.</summary>
    TimeExceeded = 11,
    /// <summary>A header field, identified by a pointer, was invalid.</summary>
    ParameterProblem = 12
}
