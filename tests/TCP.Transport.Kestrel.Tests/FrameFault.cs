namespace TCP.Transport.Kestrel.Tests;

/// <summary>A deterministic fault the virtual link applies to one frame.</summary>
internal enum FrameFault
{
    None,
    Drop,
    Duplicate,
    /// <summary>Flip the last byte, which the receiver's TCP checksum must reject.</summary>
    Corrupt,
    /// <summary>Hold the frame and deliver it after the next frame in the same direction.</summary>
    Reorder
}
