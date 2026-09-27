namespace TCP.L5_7.Application.Tls.Alerts;

/// <summary>
/// A protocol error detected while processing the peer's bytes. The engine catches it, sends <see cref="Description"/>
/// as a fatal alert (RFC 8446 6.2) and closes the connection, so parsing and handshake code can simply throw at the
/// point of failure.
/// </summary>
internal sealed class TlsAlertException(TlsAlertDescription description, string message) : Exception(message)
{
    /// <summary>The alert to send to the peer.</summary>
    public TlsAlertDescription Description { get; } = description;
}
