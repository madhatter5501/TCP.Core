namespace TCP.L5_7.Application.Tls.Alerts;

/// <summary>
/// An alert's severity (RFC 5246 7.2). TLS 1.2 lets a warning leave the connection open. TLS 1.3 keeps the field
/// only for compatibility: every alert except close_notify and user_canceled is fatal whatever its level (RFC 8446 6).
/// </summary>
public enum TlsAlertLevel : byte
{
    /// <summary>Informational; the connection may continue.</summary>
    Warning = 1,
    /// <summary>The connection is terminated at once.</summary>
    Fatal = 2,
}
