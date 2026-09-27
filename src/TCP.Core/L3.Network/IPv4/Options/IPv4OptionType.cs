namespace TCP.L3.Network.IPv4.Options;

/// <summary>IPv4 option type numbers defined by the IPv4 option format.</summary>
/// <remarks>
/// The type octet packs three fields: a "copied" bit (0x80) meaning the option is repeated in every fragment, a
/// 2-bit class, and a 5-bit number. That is why the source routes (copied) have values above 128.
/// </remarks>
public enum IPv4OptionType : byte
{
    /// <summary>Single octet ending the options list; the rest is padding.</summary>
    EndOfList = 0,
    /// <summary>Single padding octet used to align later options.</summary>
    NoOperation = 1,
    /// <summary>Each host or router the datagram visits appends its address.</summary>
    RecordRoute = 7,
    /// <summary>Internet Timestamp: visited hosts append a timestamp, optionally with their address.</summary>
    Timestamp = 68,
    /// <summary>The sender lists hops the datagram must visit in order, with other routers allowed in between. Copied into fragments.</summary>
    LooseSourceRoute = 131,
    /// <summary>The sender lists the exact sequence of hops, with no others allowed. Copied into fragments.</summary>
    StrictSourceRoute = 137
}
