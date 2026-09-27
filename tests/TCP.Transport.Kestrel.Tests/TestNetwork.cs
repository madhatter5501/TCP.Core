using System.Collections.Concurrent;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TCP.Explorer;
using TCP.L2.Link.Ethernet;
using TCP.L3.Network.IPv4;
using TCP.L3.Network.IPv4.Routing;
using TCP.L4.Transport.Tcp;
using TCP.Stack;

namespace TCP.Transport.Kestrel.Tests;

/// <summary>
/// A real Kestrel app served by one TCP.Core stack, and a second independent TCP.Core stack as the client,
/// joined by <see cref="VirtualEthernet"/>. No OS socket carries any of the traffic. The server listens on
/// <see cref="HttpPort"/> for HTTP/1.1 and on <see cref="H2cPort"/> for HTTP/2 without TLS.
/// </summary>
internal sealed class TestNetwork : IAsyncDisposable
{
    public const int HttpPort = 18_080;
    /// <summary>Cleartext HTTP/2 (h2c) with prior knowledge. Browsers never use h2c; HttpClient and curl can.</summary>
    public const int H2cPort = 18_082;
    public const string HealthBody = "served by TCP.Core";
    private static readonly TimeSpan StartTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan StopTimeout = TimeSpan.FromSeconds(30);
    private static readonly IPAddress SubnetMask = IPAddress.Parse("255.255.255.0");
    public static readonly IPAddress ServerAddress = IPAddress.Parse("192.0.2.10");
    public static readonly IPAddress ClientAddress = IPAddress.Parse("192.0.2.20");

    private readonly CancellationTokenSource _clientStop = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource> _gates;
    private Thread? _clientThread;
    private bool _appStopped;

    private TestNetwork(VirtualEthernet link, EthernetStack clientStack, WebApplication app, ConcurrentDictionary<string, TaskCompletionSource> gates)
    {
        _gates = gates;
        Link = link;
        ClientStack = clientStack;
        App = app;
    }

    public VirtualEthernet Link { get; }
    public EthernetStack ClientStack { get; }
    public EthernetStack ServerStack { get; private set; } = null!;
    public WebApplication App { get; }
    public TcpCoreHostService HostService => App.Services.GetRequiredService<TcpCoreHostService>();

    /// <param name="httpProtocols">
    /// Protocols for <see cref="HttpPort"/>. Without TLS there is no ALPN to choose between HTTP/1.1 and HTTP/2,
    /// so Kestrel serves only HTTP/1.1 on an Http1AndHttp2 endpoint; h2c needs an Http2-only endpoint.
    /// </param>
    public static async Task<TestNetwork> StartAsync(int mtu = IPv4Constants.DefaultMtu, HttpProtocols httpProtocols = HttpProtocols.Http1)
    {
        var link = new VirtualEthernet();
        var clientStack = new EthernetStack(link.Client, ClientAddress, MacAddress.FromBytes([0x02, 0, 0, 0, 0, 20]),
            new IPv4Subnet(ClientAddress, SubnetMask), mtu: mtu);
        var clientReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        clientStack.AddressClaimed += () => clientReady.TrySetResult();

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = "Testing",
            ContentRootPath = AppContext.BaseDirectory,
            WebRootPath = FindExplorerWebRoot()
        });
        builder.Logging.ClearProviders();
        EthernetStack? serverStack = null;
        builder.Services.AddTcpCoreTransport(
            new TcpCoreServerOptions { InterfaceName = link.Server.InterfaceName, Address = ServerAddress, Mtu = mtu },
            () => serverStack = new EthernetStack(link.Server, ServerAddress, MacAddress.FromBytes([0x02, 0, 0, 0, 0, 10]),
                new IPv4Subnet(ServerAddress, SubnetMask), mtu: mtu));
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Listen(new TcpCoreEndPoint(ServerAddress, HttpPort), listen => listen.Protocols = httpProtocols);
            kestrel.Listen(new TcpCoreEndPoint(ServerAddress, H2cPort), listen => listen.Protocols = HttpProtocols.Http2);
        });
        var app = builder.Build();
        var gates = new ConcurrentDictionary<string, TaskCompletionSource>();
        MapTestRoutes(app, gates);
        app.MapExplorer(new ExplorerTransportInfo("tcp-core", $"http://{ServerAddress}:{HttpPort} on {link.Server.InterfaceName}"));

        var network = new TestNetwork(link, clientStack, app, gates);
        network._clientThread = new Thread(() => clientStack.Run(network._clientStop.Token)) { IsBackground = true, Name = "Test client stack" };
        network._clientThread.Start();
        await Task.WhenAll(app.StartAsync(), clientReady.Task).WaitAsync(StartTimeout);
        network.ServerStack = serverStack!;
        return network;
    }

    private static void MapTestRoutes(WebApplication app, ConcurrentDictionary<string, TaskCompletionSource> gates)
    {
        app.MapGet("/health", () => Results.Text(HealthBody));
        app.MapGet("/large", (int bytes) => Results.Bytes(TestPayload.Create(bytes), "application/octet-stream"));
        app.MapPost("/echo", async (HttpRequest request) =>
        {
            using var body = new MemoryStream();
            await request.Body.CopyToAsync(body);
            return Results.Bytes(body.ToArray(), "application/octet-stream");
        });
        // Responds only after the test calls OpenGate(name): a request the server holds open indefinitely.
        app.MapGet("/gate/{name}", async (string name) =>
        {
            await Gate(gates, name).Task;
            return Results.Text(name);
        });
    }

    private static TaskCompletionSource Gate(ConcurrentDictionary<string, TaskCompletionSource> gates, string name) =>
        gates.GetOrAdd(name, _ => new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));

    public void OpenGate(string name) => Gate(_gates, name).TrySetResult();

    /// <summary>The Explorer's real wwwroot, found from the build output by walking up to the solution.</summary>
    private static string FindExplorerWebRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "TCP.slnx")))
                return Path.Combine(directory.FullName, "src", "TCP.Explorer", "wwwroot");
        throw new DirectoryNotFoundException("Could not locate TCP.slnx above the test output directory.");
    }

    public Task<VirtualTcpClient> ConnectAsync(int receiveCapacity = TcpHost.MaximumReceiveCapacity, bool manualRead = false, bool noDelay = false,
        int port = HttpPort) =>
        VirtualTcpClient.ConnectAsync(ClientStack, ServerAddress, port, receiveCapacity, manualRead, noDelay);

    /// <summary>
    /// An HttpClient that speaks HTTP/2 with prior knowledge (h2c) over the client TCP.Core stack. Every TCP
    /// connection it opens is recorded in <see cref="Http2TestClient.Connections"/>.
    /// </summary>
    public Http2TestClient CreateHttp2Client(int port = H2cPort, int? initialStreamWindowSize = null) =>
        new(this, port, initialStreamWindowSize);

    public Task<T> RunOnServerAsync<T>(Func<T> action) => ProtocolThread.RunAsync(ServerStack, action);

    public async Task StopAppAsync()
    {
        if (_appStopped) return;
        _appStopped = true;
        await App.StopAsync().WaitAsync(StopTimeout);
    }

    public async ValueTask DisposeAsync()
    {
        await StopAppAsync();
        await App.DisposeAsync();
        _clientStop.Cancel();
        _clientThread?.Join(TimeSpan.FromSeconds(5));
        ClientStack.Dispose();
    }
}
