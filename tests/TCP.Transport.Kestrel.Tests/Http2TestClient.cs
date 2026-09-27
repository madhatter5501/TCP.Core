using System.Collections.Concurrent;
using System.Net;

namespace TCP.Transport.Kestrel.Tests;

/// <summary>
/// HttpClient pinned to HTTP/2 over cleartext with prior knowledge: <see cref="HttpVersionPolicy.RequestVersionExact"/>
/// on an http:// URI makes SocketsHttpHandler send the connection preface immediately instead of HTTP/1.1.
/// Its ConnectCallback returns a <see cref="VirtualTcpStream"/>, so no OS socket is involved.
/// </summary>
internal sealed class Http2TestClient : IDisposable
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(60);
    private readonly ConcurrentQueue<VirtualTcpStream> _connections = new();

    public Http2TestClient(TestNetwork network, int port, int? initialStreamWindowSize)
    {
        var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (_, cancellationToken) =>
            {
                var stream = new VirtualTcpStream(await network.ConnectAsync(port: port).WaitAsync(cancellationToken));
                _connections.Enqueue(stream);
                return stream;
            }
        };
        if (initialStreamWindowSize is { } window) handler.InitialHttp2StreamWindowSize = window;
        Http = new HttpClient(handler)
        {
            BaseAddress = new Uri($"http://{TestNetwork.ServerAddress}:{port}"),
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Timeout = RequestTimeout
        };
    }

    public HttpClient Http { get; }

    /// <summary>Every TCP connection HttpClient opened, in order.</summary>
    public IReadOnlyList<VirtualTcpStream> Connections => [.. _connections];

    public VirtualTcpStream SingleConnection => Connections is [var only]
        ? only
        : throw new InvalidOperationException($"Expected one HTTP/2 connection, found {Connections.Count}.");

    public void Dispose() => Http.Dispose();
}
