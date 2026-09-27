namespace TCP.L4.Transport.Tcp.Segments;

/// <summary>
/// Control bits carried in the TCP flags octet (header byte 13). They drive the connection state
/// machine: SYN and FIN open and close, RST aborts, and ACK marks the acknowledgment field valid.
/// </summary>
[Flags]
public enum TcpFlags : byte
{
    /// <summary>No control bits set.</summary>
    None = 0,
    /// <summary>The sender has finished sending; occupies one sequence number.</summary>
    Fin = 0x01,
    /// <summary>Synchronize sequence numbers when opening; occupies one sequence number.</summary>
    Syn = 0x02,
    /// <summary>Reset: abort the connection immediately.</summary>
    Rst = 0x04,
    /// <summary>Push: ask the receiver to hand buffered data to the application promptly.</summary>
    Psh = 0x08,
    /// <summary>The acknowledgment number field is significant.</summary>
    Ack = 0x10,
    /// <summary>The urgent pointer field is significant.</summary>
    Urg = 0x20,
    /// <summary>ECN-Echo (RFC 3168). Parsed but not acted on by this stack.</summary>
    Ece = 0x40,
    /// <summary>Congestion Window Reduced (RFC 3168). Parsed but not acted on by this stack.</summary>
    Cwr = 0x80
}
