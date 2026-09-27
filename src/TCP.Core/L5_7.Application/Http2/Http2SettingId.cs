namespace TCP.L5_7.Application.Http2;

/// <summary>SETTINGS parameter identifiers (RFC 9113 section 6.5.2).</summary>
public enum Http2SettingId : ushort
{
    /// <summary>Largest HPACK dynamic table the sender's decoder allows; default 4,096 bytes.</summary>
    HeaderTableSize = 0x1,
    /// <summary>0 forbids server push; default 1.</summary>
    EnablePush = 0x2,
    /// <summary>How many streams the peer may open concurrently; default unlimited.</summary>
    MaxConcurrentStreams = 0x3,
    /// <summary>Initial flow-control window for every new stream; default 65,535 bytes. Does not change the connection window.</summary>
    InitialWindowSize = 0x4,
    /// <summary>Largest frame payload the sender will accept; default 16,384 bytes.</summary>
    MaxFrameSize = 0x5,
    /// <summary>Advisory limit on the size of a header list the sender will accept.</summary>
    MaxHeaderListSize = 0x6,
    /// <summary>Extended CONNECT support (RFC 8441), used for WebSockets over HTTP/2.</summary>
    EnableConnectProtocol = 0x8
}
