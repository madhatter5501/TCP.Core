using TCP.L5_7.Application.Http2;

namespace TCP.Transport.Kestrel.Tests;

/// <summary>One HTTP/2 frame seen on a test connection, and which side sent it.</summary>
internal sealed record Http2WireFrame(bool FromClient, Http2Frame Frame)
{
    public override string ToString() => $"{(FromClient ? "C>S" : "S>C")} {Frame}";
}
