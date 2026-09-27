namespace TCP.L3.Network.IPv4.Fragmentation;

/// <summary>Named bit fields in the IPv4 Flags and Fragment Offset field.</summary>
public static class IPv4FragmentField
{
    /// <summary>Must be zero; datagrams with it set are discarded.</summary>
    public const ushort ReservedFlag = 0x8000;
    /// <summary>DF: never fragment this datagram. Drop it and report "fragmentation needed" instead, which is how path MTU discovery works.</summary>
    public const ushort DontFragmentFlag = 0x4000;
    /// <summary>MF: more fragments follow; clear on the last fragment.</summary>
    public const ushort MoreFragmentsFlag = 0x2000;
    /// <summary>All three flag bits.</summary>
    public const ushort FlagsMask = ReservedFlag | DontFragmentFlag | MoreFragmentsFlag;
    /// <summary>The 13-bit offset of this fragment's data within the original payload, in 8-byte units.</summary>
    public const ushort FragmentOffsetMask = 0x1FFF;
    /// <summary>Non-zero exactly when the datagram is a fragment (MF set or offset non-zero) and needs reassembly.</summary>
    public const ushort ReassemblyMask = MoreFragmentsFlag | FragmentOffsetMask;
    /// <summary>The fragment offset field counts 8-byte units.</summary>
    public const int OffsetUnitLength = 8;
}
