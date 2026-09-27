namespace TCP.L4.Transport.Tcp.Connections;

/// <summary>
/// The connection states of the RFC 9293 state machine (section 3.3.2). Every <see cref="TcpConnection"/>
/// is in exactly one; <see cref="TcpConnection.StateChanged"/> reports each transition. LISTEN is not
/// represented here because a <see cref="TcpListener"/> plays that role.
/// </summary>
public enum TcpState
{
    /// <summary>No connection. Both the starting point and the end of every connection.</summary>
    Closed,
    /// <summary>Active open: our SYN is sent and we wait for the peer's SYN-ACK.</summary>
    SynSent,
    /// <summary>A SYN has been received and answered with SYN-ACK; waiting for the final ACK of the handshake.</summary>
    SynReceived,
    /// <summary>The handshake is complete and data flows both ways.</summary>
    Established,
    /// <summary>We have sent FIN (closed our direction) and wait for it to be acknowledged.</summary>
    FinWait1,
    /// <summary>Our FIN is acknowledged; waiting for the peer to close its direction.</summary>
    FinWait2,
    /// <summary>The peer has sent FIN; we may still send until the application closes.</summary>
    CloseWait,
    /// <summary>Both sides sent FIN at once; waiting for ours to be acknowledged.</summary>
    Closing,
    /// <summary>The peer closed first, and we have now sent our FIN; waiting for its acknowledgment.</summary>
    LastAck,
    /// <summary>Both directions are closed; lingering 2 x MSL so stray segments die before the port pair is reused.</summary>
    TimeWait
}