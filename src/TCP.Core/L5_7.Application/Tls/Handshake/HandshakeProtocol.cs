using TCP.L5_7.Application.Tls.Alerts;
using TCP.L5_7.Application.Tls.Handshake.Messages;

namespace TCP.L5_7.Application.Tls.Handshake;

/// <summary>
/// One stage of the handshake state machine. The engine passes it each complete handshake message; it checks the
/// message is the one expected next, acts on it, and sends its own flight in reply.
/// </summary>
/// <remarks>
/// The handshake starts version-neutral (<see cref="ClientHandshake"/>, <see cref="ServerHandshake"/>). Once the
/// hellos settle the version, it switches to <see cref="Tls13ClientHandshake"/>, <see cref="Tls13ServerHandshake"/>,
/// <see cref="Tls12ClientHandshake"/> or <see cref="Tls12ServerHandshake"/>, which stay in charge after the handshake
/// for post-handshake messages. Any message out of order is an unexpected_message alert (RFC 8446 6.2).
/// </remarks>
internal abstract class HandshakeProtocol(TlsEngine engine)
{
    /// <summary>The connection this handshake belongs to.</summary>
    protected TlsEngine Engine { get; } = engine;

    /// <summary>The connection's settings.</summary>
    protected TlsOptions Options => Engine.Options;

    /// <summary>Handles the next handshake message.</summary>
    public abstract void OnMessage(HandshakeMessage message);

    /// <summary>TLS 1.2 ChangeCipherSpec; unexpected unless a stage expects it.</summary>
    public virtual void OnChangeCipherSpec() =>
        throw new TlsAlertException(TlsAlertDescription.UnexpectedMessage, TlsMessages.InvalidChangeCipherSpec);

    /// <summary>A handshake message after the handshake finished.</summary>
    public virtual void OnPostHandshakeMessage(HandshakeMessage message) => throw Unexpected(message);

    /// <summary>The error for a message that is not valid at this point.</summary>
    protected static TlsAlertException Unexpected(HandshakeMessage message) =>
        new(TlsAlertDescription.UnexpectedMessage, string.Format(TlsMessages.UnexpectedHandshakeFormat, message.Type));

    /// <summary>Throws <paramref name="alert"/> unless <paramref name="condition"/> holds.</summary>
    protected static void Require(bool condition, TlsAlertDescription alert, string message)
    {
        if (!condition) throw new TlsAlertException(alert, message);
    }

    /// <summary>32 fresh random bytes for a hello.</summary>
    protected byte[] NewRandom()
    {
        var random = new byte[ClientHello.RandomLength];
        Options.FillRandom(random);
        return random;
    }
}
