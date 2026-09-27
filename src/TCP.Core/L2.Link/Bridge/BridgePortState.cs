namespace TCP.L2.Link.Bridge;

/// <summary>
/// A bridge port's 802.1D spanning tree state. A port passes through each middle state for one forward delay so
/// the topology settles before it forwards.
/// </summary>
public enum BridgePortState
{
    /// <summary>Neither forwards nor learns; only listens for BPDUs. Used for redundant links that would form a loop.</summary>
    Blocking,
    /// <summary>Taking part in the spanning tree election, but not yet learning or forwarding.</summary>
    Listening,
    /// <summary>Learning source addresses to avoid flooding later, but still not forwarding.</summary>
    Learning,
    /// <summary>Fully active: learns and forwards frames.</summary>
    Forwarding
}