using TCP.L4.Transport.Tcp.Segments;

namespace TCP.L4.Transport.Tcp;

/// <summary>
/// A position in TCP's 32-bit sequence space. Arithmetic wraps and comparisons are modulo 2^32
/// (RFC 9293 3.4), which is sound while every window and buffer stays far below 2^31.
/// </summary>
/// <remarks>
/// Every byte and every SYN or FIN occupies one sequence number, and the counter wraps. Plain
/// <see cref="uint"/> comparisons break at the wrap, so the connection's sequence state (SND.UNA,
/// SND.NXT, RCV.NXT and friends) uses this type. It converts implicitly from the raw
/// <see cref="uint"/> fields of <see cref="TcpSegment"/>, so segment values compare correctly without casts.
/// </remarks>
/// <param name="Value">The raw 32-bit value as carried on the wire.</param>
internal readonly record struct SequenceNumber(uint Value)
{
    /// <summary>Treats a raw header field, such as <see cref="TcpSegment.SequenceNumber"/>, as a sequence position.</summary>
    public static implicit operator SequenceNumber(uint value) => new(value);

    /// <summary>The position <paramref name="length"/> sequence numbers later, wrapping past 2^32.</summary>
    public static SequenceNumber operator +(SequenceNumber sequence, uint length) => new(unchecked(sequence.Value + length));

    /// <summary>The position <paramref name="length"/> sequence numbers earlier, wrapping below zero.</summary>
    public static SequenceNumber operator -(SequenceNumber sequence, uint length) => new(unchecked(sequence.Value - length));

    /// <summary>Forward distance from <paramref name="start"/> to <paramref name="end"/>.</summary>
    public static uint operator -(SequenceNumber end, SequenceNumber start) => unchecked(end.Value - start.Value);

    /// <summary>
    /// True when <paramref name="a"/> comes before <paramref name="b"/>: the signed 32-bit distance is
    /// negative. This is the modular "less than" of RFC 9293 3.4.
    /// </summary>
    public static bool operator <(SequenceNumber a, SequenceNumber b) => unchecked((int)(a.Value - b.Value)) < 0;

    /// <summary>True when <paramref name="a"/> comes after <paramref name="b"/>, i.e. <c>b &lt; a</c>.</summary>
    public static bool operator >(SequenceNumber a, SequenceNumber b) => b < a;

    /// <summary>True when <paramref name="a"/> equals or comes before <paramref name="b"/>.</summary>
    public static bool operator <=(SequenceNumber a, SequenceNumber b) => a == b || a < b;

    /// <summary>True when <paramref name="a"/> does not come before <paramref name="b"/>.</summary>
    /// <remarks>Defined as the negation of <c>&lt;</c>, which differs from <c>&gt;</c> or <c>==</c> only at a distance of exactly 2^31.</remarks>
    public static bool operator >=(SequenceNumber a, SequenceNumber b) => !(a < b);

    /// <summary>
    /// True when this lies in the half-open range [start, start + length). Used for window checks,
    /// such as whether an arriving byte falls inside the receive window starting at RCV.NXT.
    /// </summary>
    public bool IsWithin(SequenceNumber start, uint length) => this - start < length;

    /// <summary>The raw value in decimal, as packet captures display it.</summary>
    public override string ToString() => Value.ToString();
}
