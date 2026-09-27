using System.Globalization;
using System.Text;

namespace TCP.Transport.Kestrel.Tests;

/// <summary>A parsed HTTP/1.1 response. Supports Content-Length, chunked, and read-until-close bodies.</summary>
internal sealed record HttpResponse(int Status, IReadOnlyDictionary<string, string> Headers, byte[] Body)
{
    private static readonly byte[] HeaderTerminator = [.. "\r\n\r\n"u8];
    private static readonly byte[] LineTerminator = [.. "\r\n"u8];

    public string BodyText => Encoding.UTF8.GetString(Body);

    /// <summary>Parses one complete response from the start of <paramref name="buffer"/>.</summary>
    /// <param name="endOfStream">The peer has closed, so a body without a length ends here.</param>
    public static bool TryParse(ReadOnlySpan<byte> buffer, bool endOfStream, out HttpResponse? response, out int consumed)
    {
        response = null;
        consumed = 0;
        var headerEnd = buffer.IndexOf(HeaderTerminator);
        if (headerEnd < 0) return false;
        var lines = Encoding.ASCII.GetString(buffer[..headerEnd]).Split("\r\n");
        var status = int.Parse(lines[0].Split(' ')[1], CultureInfo.InvariantCulture);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            var colon = line.IndexOf(':');
            headers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
        }

        var bodyStart = headerEnd + HeaderTerminator.Length;
        var remaining = buffer[bodyStart..];
        if (headers.TryGetValue("Content-Length", out var lengthText))
        {
            var length = int.Parse(lengthText, CultureInfo.InvariantCulture);
            if (remaining.Length < length) return false;
            response = new HttpResponse(status, headers, [.. remaining[..length]]);
            consumed = bodyStart + length;
            return true;
        }
        if (headers.TryGetValue("Transfer-Encoding", out var encoding) && encoding.Contains("chunked", StringComparison.OrdinalIgnoreCase))
        {
            var body = new List<byte>();
            var offset = 0;
            while (true)
            {
                var sizeEnd = remaining[offset..].IndexOf(LineTerminator);
                if (sizeEnd < 0) return false;
                var size = int.Parse(Encoding.ASCII.GetString(remaining.Slice(offset, sizeEnd)).Split(';')[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                var dataStart = offset + sizeEnd + LineTerminator.Length;
                if (remaining.Length < dataStart + size + LineTerminator.Length) return false;
                body.AddRange([.. remaining.Slice(dataStart, size)]);
                offset = dataStart + size + LineTerminator.Length;
                if (size == 0) break; // No trailers are expected from Kestrel here.
            }
            response = new HttpResponse(status, headers, [.. body]);
            consumed = bodyStart + offset;
            return true;
        }
        if (!endOfStream) return false;
        response = new HttpResponse(status, headers, [.. remaining]);
        consumed = buffer.Length;
        return true;
    }
}
