namespace TCP.L5_7.Application.Tls;

/// <summary>Where a <see cref="TlsConnection"/> is in its life.</summary>
public enum TlsConnectionState
{
    /// <summary>The handshake is running; application data cannot flow yet.</summary>
    Handshaking,
    /// <summary>The handshake completed; application data flows both ways until either side closes.</summary>
    Established,
    /// <summary>Finished: both sides closed cleanly, or <see cref="TlsConnection.FailureReason"/> says why not.</summary>
    Closed,
}
