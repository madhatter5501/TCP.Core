using System.Globalization;
using System.Net;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using TCP.Explorer;
using TCP.L3.Network.IPv4;
using TCP.Transport.Kestrel;

const string TransportVariable = "TCP_EXPLORER_TRANSPORT";
const string InterfaceVariable = "TCP_EXPLORER_INTERFACE";
const string AddressVariable = "TCP_EXPLORER_ADDRESS";
const string GatewayVariable = "TCP_EXPLORER_GATEWAY";
const string PortVariable = "TCP_EXPLORER_PORT";
const string H2cPortVariable = "TCP_EXPLORER_H2C_PORT";
const string MtuVariable = "TCP_EXPLORER_MTU";
const string OsTransportName = "sockets";
const string TcpCoreTransportName = "tcp-core";
const int DefaultHttpPort = 5097;

var builder = WebApplication.CreateBuilder(args);
var transportName = Environment.GetEnvironmentVariable(TransportVariable) ?? OsTransportName;
var transportMode = transportName.ToLowerInvariant() switch
{
    OsTransportName => ExplorerTransportMode.OperatingSystemSockets,
    TcpCoreTransportName => ExplorerTransportMode.TcpCore,
    _ => throw new InvalidOperationException($"{TransportVariable} must be '{OsTransportName}' or '{TcpCoreTransportName}'.")
};

ExplorerTransportInfo transport;
if (transportMode == ExplorerTransportMode.TcpCore)
{
    // Every value is explicit: there is no default interface or address, and no fallback to OS sockets.
    var interfaceName = RequiredEnvironment(InterfaceVariable);
    var stackAddress = ParseAddress(AddressVariable, RequiredEnvironment(AddressVariable));
    var gatewayText = Environment.GetEnvironmentVariable(GatewayVariable);
    var gateway = string.IsNullOrWhiteSpace(gatewayText) ? null : ParseAddress(GatewayVariable, gatewayText);
    var port = ReadInteger(PortVariable, DefaultHttpPort);
    var h2cPortText = Environment.GetEnvironmentVariable(H2cPortVariable);
    int? h2cPort = string.IsNullOrWhiteSpace(h2cPortText) ? null : ReadInteger(H2cPortVariable, 0);
    if (h2cPort == port) throw new InvalidOperationException($"{H2cPortVariable} must differ from {PortVariable}.");
    var mtu = ReadInteger(MtuVariable, IPv4Constants.DefaultMtu);
    var endpoint = new TcpCoreEndPoint(stackAddress, port);
    builder.Services.AddTcpCoreTransport(new TcpCoreServerOptions
    {
        InterfaceName = interfaceName,
        Address = stackAddress,
        Gateway = gateway,
        Mtu = mtu
    });
    // An explicit Listen replaces ASPNETCORE_URLS and launch-profile URLs, so only these endpoints are bound.
    // Without TLS there is no ALPN, and Kestrel serves only HTTP/1.1 on an Http1AndHttp2 endpoint. Browsers
    // need that. Cleartext HTTP/2 (h2c) needs its own Http2-only endpoint, reachable by clients with prior
    // knowledge, such as curl --http2-prior-knowledge or HttpClient with RequestVersionExact.
    builder.WebHost.ConfigureKestrel(kestrel =>
    {
        kestrel.Listen(endpoint, listen => listen.Protocols = HttpProtocols.Http1);
        if (h2cPort is { } http2Port)
            kestrel.Listen(new TcpCoreEndPoint(stackAddress, http2Port), listen => listen.Protocols = HttpProtocols.Http2);
    });
    var h2cNote = h2cPort is { } shown ? $", h2c on port {shown}" : "";
    transport = new ExplorerTransportInfo(TcpCoreTransportName, $"http://{stackAddress}:{port} on {interfaceName}{h2cNote}");
}
else
{
    transport = new ExplorerTransportInfo(OsTransportName, "operating-system TCP (development mode)");
}
Console.WriteLine($"Explorer transport: {transport.Mode} — {transport.Endpoint}");

var app = builder.Build();
app.MapExplorer(transport);
await app.RunAsync();

static string RequiredEnvironment(string name) =>
    Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
        ? value
        : throw new InvalidOperationException($"Set {name} to select the TCP.Core interface configuration.");

static IPAddress ParseAddress(string name, string value) =>
    IPAddress.TryParse(value, out var address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
        ? address
        : throw new InvalidOperationException($"{name} must be an IPv4 address.");

static int ReadInteger(string name, int defaultValue) =>
    Environment.GetEnvironmentVariable(name) is not { Length: > 0 } value
        ? defaultValue
        : int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number)
            ? number
            : throw new InvalidOperationException($"{name} must be a whole number.");
