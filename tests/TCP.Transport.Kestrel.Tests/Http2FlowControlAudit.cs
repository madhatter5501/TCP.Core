using TCP.L5_7.Application.Http2;

namespace TCP.Transport.Kestrel.Tests;

/// <summary>
/// Replays a connection's frames and checks that neither side ever sent more DATA than the peer's
/// flow-control windows allowed (RFC 9113 section 6.9): one window per stream plus one for the connection.
/// </summary>
/// <remarks>
/// The timeline comes from the client: client frames when written, server frames when read. The client could
/// only act on credit it had read, so its checks are exact. The server can only have seen client frames
/// written earlier, so its checks may count a little extra credit, but a violation is never a false alarm.
/// </remarks>
internal static class Http2FlowControlAudit
{
    public sealed record Summary(long ClientDataBytes, long ServerDataBytes, int ClientWindowUpdates, int ServerWindowUpdates,
        long LowestClientWindow, long LowestServerWindow);

    private sealed class Sender
    {
        public long ConnectionWindow = Http2Constants.DefaultInitialWindowSize;
        public long InitialStreamWindow = Http2Constants.DefaultInitialWindowSize; // The receiver's SETTINGS_INITIAL_WINDOW_SIZE.
        public readonly Dictionary<int, long> StreamWindows = [];
        public long DataBytes;
        public long LowestWindow = long.MaxValue;

        public long Stream(int id) => StreamWindows.TryGetValue(id, out var window) ? window : InitialStreamWindow;
    }

    public static Summary Check(IReadOnlyList<Http2WireFrame> frames)
    {
        var client = new Sender();
        var server = new Sender();
        int clientUpdates = 0, serverUpdates = 0;
        foreach (var (fromClient, frame) in frames)
        {
            var self = fromClient ? client : server;
            var peer = fromClient ? server : client; // The side this frame grants credit to.
            switch (frame.Type)
            {
                case Http2FrameType.Settings when !frame.HasFlag(Http2FrameFlags.Ack):
                    foreach (var setting in frame.Settings.Where(setting => setting.Id == Http2SettingId.InitialWindowSize))
                    {
                        // A new initial window adjusts every open stream by the difference (RFC 9113 section 6.9.2).
                        var delta = setting.Value - peer.InitialStreamWindow;
                        foreach (var id in peer.StreamWindows.Keys.ToList()) peer.StreamWindows[id] += delta;
                        peer.InitialStreamWindow = setting.Value;
                    }
                    break;
                case Http2FrameType.WindowUpdate:
                    if (fromClient) clientUpdates++; else serverUpdates++;
                    if (frame.StreamId == 0) peer.ConnectionWindow += frame.WindowSizeIncrement;
                    else peer.StreamWindows[frame.StreamId] = peer.Stream(frame.StreamId) + frame.WindowSizeIncrement;
                    break;
                case Http2FrameType.Data:
                    var length = frame.FlowControlledLength;
                    self.DataBytes += length;
                    self.ConnectionWindow -= length;
                    var streamWindow = self.StreamWindows[frame.StreamId] = self.Stream(frame.StreamId) - length;
                    self.LowestWindow = Math.Min(self.LowestWindow, Math.Min(self.ConnectionWindow, streamWindow));
                    if (self.ConnectionWindow < 0 || streamWindow < 0)
                        throw new InvalidOperationException($"{(fromClient ? "Client" : "Server")} overran flow control with {frame}: " +
                            $"connection window {self.ConnectionWindow}, stream window {streamWindow}.");
                    break;
            }
        }
        return new Summary(client.DataBytes, server.DataBytes, clientUpdates, serverUpdates, client.LowestWindow, server.LowestWindow);
    }
}
