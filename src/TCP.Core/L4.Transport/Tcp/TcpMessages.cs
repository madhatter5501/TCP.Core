using TCP.L4.Transport.Tcp.Connections;

namespace TCP.L4.Transport.Tcp;

/// <summary>
/// Stable diagnostics exposed by TCP validation and connection failures. They surface as exception
/// messages and as <see cref="TcpConnection.FailureReason"/> and <see cref="TcpConnection.LastNetworkError"/>,
/// so tests and tools can match them.
/// </summary>
internal static class TcpMessages
{
    public const string NetworkErrorFormat = "ICMP type {0}, code {1}";
    public const string ConnectionFailedFormat = "Connection failed: {0}.";
    public const string SegmentTooLarge = "TCP segment exceeds the IPv4 payload limit.";
    public const string InvalidSegmentLength = "Invalid TCP segment length.";
    public const string InvalidDataOffset = "Invalid TCP data offset.";
    public const string InvalidChecksum = "Invalid TCP checksum.";
    public const string AddressFamilyMismatch = "TCP segment addresses must both be IPv4 or both be IPv6.";
    public const string InvalidOptionsSize = "TCP options must fit in 40 bytes and be word-aligned.";
    public const string InvalidOptionLength = "Truncated or invalid TCP option.";
    public const string InvalidMssOption = "Invalid MSS option.";
    public const string PortInUse = "Port is already in use.";
    public const string InvalidEndpoint = "A unicast IPv4 endpoint and valid buffer capacity are required.";
    public const string ConnectionLimitReached = "TCP connection limit reached.";
    public const string EphemeralPortsExhausted = "No ephemeral port is available.";
    public const string EndpointInUse = "TCP endpoint is already in use, possibly in TIME-WAIT.";
    public const string NotWritable = "Connection is not open for writing.";
    public const string LocallyAborted = "Connection aborted locally.";
    public const string PeerReset = "Connection reset by peer.";
    public const string ConnectionRefused = "Connection refused.";
    public const string FinWait2Expired = "Peer did not close before FIN-WAIT-2 timeout.";
    public const string ProbeLimitExceeded = "TCP zero-window probe limit exceeded without a peer response.";
    public const string RetransmissionLimitExceeded = "TCP retransmission limit exceeded.";
    public const string KeepAliveExpired = "Peer did not answer TCP keep-alive probes.";
    public const string UserTimeoutExpired = "Data remained unacknowledged beyond the TCP user timeout.";
    public const string ReceivedDataDiscarded =
        "Connection reset because received data was discarded after the application stopped reading.";
    public const string AuthenticationKeyConflict = "An authentication key with the same peer and send identifier already exists.";
    public const string InvalidAuthenticationKey = "Authentication keys need a non-empty master key.";
}
