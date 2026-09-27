namespace TCP.L3.Network.Icmp;

/// <summary>Time Exceeded code values used by the IPv4 host.</summary>
public enum IcmpTimeExceededCode : byte
{
    /// <summary>A router decremented TTL to zero; traceroute relies on this.</summary>
    TransitTimeExceeded = 0,
    /// <summary>Not all fragments of a datagram arrived before the reassembly timer expired.</summary>
    FragmentReassemblyTimeExceeded = 1
}
