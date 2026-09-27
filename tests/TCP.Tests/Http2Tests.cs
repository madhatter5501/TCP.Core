using System.Buffers.Binary;
using TCP.L5_7.Application.Http2;

namespace TCP.Tests;

internal static class Http2Tests
{
    public static int Run()
    {
        var count = 0;

        Test("HTTP/2 frame header round-trips and clears the reserved stream bit", () =>
        {
            var bytes = new Http2Frame(Http2FrameType.Data, Http2FrameFlags.EndStream, 3, new byte[] { 1, 2, 3 }).Serialize();
            Check(bytes.AsSpan(0, Http2Constants.FrameHeaderLength).SequenceEqual(new byte[] { 0, 0, 3, 0, 1, 0, 0, 0, 3 }), "Header layout differs");
            bytes[5] |= 0x80; // Reserved bit: ignored on receipt.
            Check(Http2Frame.TryParse(bytes, Http2Constants.DefaultMaxFrameSize, out var frame, out var consumed) && consumed == bytes.Length, "Frame not decoded");
            Check(frame.StreamId == 3 && frame.HasFlag(Http2FrameFlags.EndStream) && frame.Data.Span.SequenceEqual(new byte[] { 1, 2, 3 }), "Frame fields differ");
            Check(frame.ToString() == "DATA stream 3, 3 B [END_STREAM]", $"Label differs: {frame}");
            Check(!Http2Frame.TryParse(bytes.AsSpan(0, bytes.Length - 1), Http2Constants.DefaultMaxFrameSize, out _, out consumed) && consumed == 0, "Partial frame decoded");
        });
        Test("HTTP/2 padded DATA hides padding but counts it for flow control", () =>
        {
            var frame = Parse(new Http2Frame(Http2FrameType.Data, Http2FrameFlags.Padded, 1, new byte[] { 2, 0xAA, 0xBB, 0, 0 }).Serialize());
            Check(frame.Data.Span.SequenceEqual(new byte[] { 0xAA, 0xBB }) && frame.FlowControlledLength == 5, "Padding handling differs");
            Expect(Http2ErrorCode.ProtocolError, () => Parse(new Http2Frame(Http2FrameType.Data, Http2FrameFlags.Padded, 1, new byte[] { 9, 1 }).Serialize()));
        });
        Test("HTTP/2 SETTINGS, WINDOW_UPDATE and GOAWAY payloads decode", () =>
        {
            var settings = new byte[12];
            BinaryPrimitives.WriteUInt16BigEndian(settings, (ushort)Http2SettingId.InitialWindowSize);
            BinaryPrimitives.WriteUInt32BigEndian(settings.AsSpan(2), 98_304);
            BinaryPrimitives.WriteUInt16BigEndian(settings.AsSpan(6), (ushort)Http2SettingId.MaxFrameSize);
            BinaryPrimitives.WriteUInt32BigEndian(settings.AsSpan(8), 16_384);
            var decoded = Parse(new Http2Frame(Http2FrameType.Settings, Http2FrameFlags.None, 0, settings).Serialize()).Settings;
            Check(decoded.SequenceEqual([new Http2Setting(Http2SettingId.InitialWindowSize, 98_304), new Http2Setting(Http2SettingId.MaxFrameSize, 16_384)]), "Settings differ");
            var update = Parse(new Http2Frame(Http2FrameType.WindowUpdate, Http2FrameFlags.None, 5, new byte[] { 0x80, 0, 0x40, 0 }).Serialize());
            Check(update.WindowSizeIncrement == 0x4000 && update.ToString() == "WINDOW_UPDATE stream 5, +16384 B", $"Window update differs: {update}");
            var goAway = Parse(new Http2Frame(Http2FrameType.GoAway, Http2FrameFlags.None, 0, new byte[] { 0, 0, 0, 7, 0, 0, 0, 0, (byte)'b', (byte)'y', (byte)'e' }).Serialize());
            Check(goAway.LastStreamId == 7 && goAway.ErrorCode == Http2ErrorCode.NoError, "GOAWAY differs");
        });
        Test("HTTP/2 size and stream rules are enforced per frame type", () =>
        {
            Expect(Http2ErrorCode.FrameSizeError, () => Parse(new Http2Frame(Http2FrameType.Settings, Http2FrameFlags.None, 0, new byte[5]).Serialize()));
            Expect(Http2ErrorCode.FrameSizeError, () => Parse(new Http2Frame(Http2FrameType.Settings, Http2FrameFlags.Ack, 0, new byte[6]).Serialize()));
            Expect(Http2ErrorCode.ProtocolError, () => Parse(new Http2Frame(Http2FrameType.Settings, Http2FrameFlags.None, 1, ReadOnlyMemory<byte>.Empty).Serialize()));
            Expect(Http2ErrorCode.ProtocolError, () => Parse(new Http2Frame(Http2FrameType.Data, Http2FrameFlags.None, 0, ReadOnlyMemory<byte>.Empty).Serialize()));
            Expect(Http2ErrorCode.FrameSizeError, () => Parse(new Http2Frame(Http2FrameType.Ping, Http2FrameFlags.None, 0, new byte[7]).Serialize()));
            Expect(Http2ErrorCode.ProtocolError, () => Parse(new Http2Frame(Http2FrameType.WindowUpdate, Http2FrameFlags.None, 1, new byte[4]).Serialize()));
            Expect(Http2ErrorCode.FrameSizeError, () => Parse(new Http2Frame(Http2FrameType.Data, Http2FrameFlags.None, 1,
                new byte[Http2Constants.DefaultMaxFrameSize + 1]).Serialize()));
            var unknown = Parse(new Http2Frame((Http2FrameType)0xEE, Http2FrameFlags.None, 0, new byte[] { 1 }).Serialize());
            Check(unknown.ToString() == "UNKNOWN(0xee) connection, 1 B", $"Unknown frame label differs: {unknown}");
        });
        Test("HTTP/2 reader matches the preface and reassembles frames split at every byte", () =>
        {
            var stream = new List<byte>();
            stream.AddRange(Http2Constants.ClientConnectionPreface);
            stream.AddRange(new Http2Frame(Http2FrameType.Settings, Http2FrameFlags.None, 0, ReadOnlyMemory<byte>.Empty).Serialize());
            stream.AddRange(new Http2Frame(Http2FrameType.Headers, Http2FrameFlags.None, 1, new byte[] { 0x82 }).Serialize());
            stream.AddRange(new Http2Frame(Http2FrameType.Continuation, Http2FrameFlags.EndHeaders, 1, new byte[] { 0x86 }).Serialize());
            stream.AddRange(new Http2Frame(Http2FrameType.Data, Http2FrameFlags.EndStream, 1, new byte[100]).Serialize());
            var reader = new Http2FrameReader(isClientToServer: true);
            var frames = new List<Http2Frame>();
            foreach (var value in stream) frames.AddRange(reader.Append([value]));
            Check(reader.PrefaceComplete && reader.BufferedBytes == 0, "Reader left bytes behind");
            Check(frames.Select(frame => frame.Type).SequenceEqual([Http2FrameType.Settings, Http2FrameType.Headers, Http2FrameType.Continuation, Http2FrameType.Data]), "Frame sequence differs");
            var whole = new Http2FrameReader(isClientToServer: true).Append([.. stream]);
            Check(whole.Count == 4 && whole[3].Data.Length == 100, "Single-chunk decode differs");
        });
        Test("HTTP/2 reader rejects HTTP/1.1, a non-SETTINGS first frame and an interrupted header block", () =>
        {
            Expect(Http2ErrorCode.ProtocolError, () => new Http2FrameReader(isClientToServer: true).Append("GET / HTTP/1.1\r\n"u8));
            Expect(Http2ErrorCode.ProtocolError, () => new Http2FrameReader(isClientToServer: false).Append(
                new Http2Frame(Http2FrameType.Ping, Http2FrameFlags.None, 0, new byte[8]).Serialize()));
            var reader = new Http2FrameReader(isClientToServer: false);
            reader.Append(new Http2Frame(Http2FrameType.Settings, Http2FrameFlags.None, 0, ReadOnlyMemory<byte>.Empty).Serialize());
            reader.Append(new Http2Frame(Http2FrameType.Headers, Http2FrameFlags.None, 1, new byte[] { 0x88 }).Serialize());
            Expect(Http2ErrorCode.ProtocolError, () => reader.Append(new Http2Frame(Http2FrameType.Data, Http2FrameFlags.None, 1, new byte[1]).Serialize()));
        });
        return count;

        void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
        void Test(string name, Action test) { test(); count++; Console.WriteLine("PASS: " + name); }

        static Http2Frame Parse(byte[] bytes)
        {
            if (!Http2Frame.TryParse(bytes, Http2Constants.DefaultMaxFrameSize, out var frame, out _)) throw new Exception("Incomplete frame");
            return frame;
        }

        void Expect(Http2ErrorCode code, Action action)
        {
            try { action(); }
            catch (Http2ProtocolException error) { Check(error.ErrorCode == code, $"Expected {code}, got {error.ErrorCode}: {error.Message}"); return; }
            throw new Exception($"Expected an HTTP/2 {code}");
        }
    }
}
