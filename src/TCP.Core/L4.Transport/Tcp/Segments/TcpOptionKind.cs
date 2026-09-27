namespace TCP.L4.Transport.Tcp.Segments;

/// <summary>
/// Option kind values in a TCP header (the first byte of each option). Only the options this stack
/// understands are named; <see cref="TcpOptionReader"/> skips any other kind by its length byte.
/// </summary>
internal enum TcpOptionKind : byte
{
    /// <summary>Single byte marking the end of the options; the remainder is padding.</summary>
    EndOfList = 0,
    /// <summary>Single padding byte used to align the following option.</summary>
    NoOperation = 1,
    /// <summary>Largest segment the sender can receive, carried only on SYN segments (4 bytes).</summary>
    MaximumSegmentSize = 2,
    /// <summary>Window scale shift count (RFC 7323 2), carried only on SYN segments (3 bytes).</summary>
    WindowScale = 3,
    /// <summary>The sender can receive SACK blocks (RFC 2018 2), carried only on SYN segments (2 bytes).</summary>
    SackPermitted = 4,
    /// <summary>Blocks of data received above the cumulative acknowledgment (RFC 2018 3).</summary>
    Sack = 5,
    /// <summary>Timestamp value and echo reply (RFC 7323 3), 10 bytes.</summary>
    Timestamp = 8,
    /// <summary>TCP MD5 signature (RFC 2385), 18 bytes. Obsoleted by TCP-AO but still deployed for BGP.</summary>
    Md5Signature = 19,
    /// <summary>User Timeout (RFC 5482), 4 bytes.</summary>
    UserTimeout = 28,
    /// <summary>TCP Authentication Option (RFC 5925).</summary>
    Authentication = 29,
    /// <summary>TCP Fast Open cookie or cookie request (RFC 7413 4.1.1).</summary>
    FastOpen = 34
}
