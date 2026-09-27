namespace TCP.L4.Transport.Tcp.Congestion;

/// <summary>Congestion window algorithms a connection can use; chosen by <see cref="TcpSettings.CongestionControl"/>.</summary>
public enum TcpCongestionAlgorithm
{
    /// <summary>Reno window growth (RFC 5681) with NewReno-style recovery: halve on loss, grow one segment per round trip.</summary>
    NewReno,
    /// <summary>CUBIC (RFC 9438): cut to 70% on loss and regrow along a cubic curve anchored at the pre-loss window.</summary>
    Cubic
}
