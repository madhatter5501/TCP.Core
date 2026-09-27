using System.Text;

namespace TCP.Transport.Kestrel.Tests;

/// <summary>Raw HTTP/1.1 request bytes, so tests control exactly what crosses TCP.</summary>
internal static class HttpRequests
{
    private const string Host = "explorer.test";

    public static byte[] Get(string path, bool keepAlive = false) => Encoding.ASCII.GetBytes(
        $"GET {path} HTTP/1.1\r\nHost: {Host}\r\nConnection: {Connection(keepAlive)}\r\n\r\n");

    public static byte[] PostHeader(string path, int contentLength, string contentType, bool keepAlive = false) => Encoding.ASCII.GetBytes(
        $"POST {path} HTTP/1.1\r\nHost: {Host}\r\nConnection: {Connection(keepAlive)}\r\nContent-Type: {contentType}\r\nContent-Length: {contentLength}\r\n\r\n");

    public static byte[] Post(string path, byte[] body, string contentType, bool keepAlive = false) =>
        [.. PostHeader(path, body.Length, contentType, keepAlive), .. body];

    private static string Connection(bool keepAlive) => keepAlive ? "keep-alive" : "close";
}
