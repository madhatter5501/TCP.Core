using System.Buffers.Binary;
using System.Net;

namespace TCP.L3.Network.IPv4.Options;

/// <summary>IPv4 option framing plus Record Route and Internet Timestamp processing.</summary>
/// <remarks>
/// <para>
/// Options sit between the fixed 20-byte IPv4 header and the payload (RFC 791 3.1). They let a datagram
/// collect the route it took (Record Route), collect timestamps along the way (Internet Timestamp), or dictate
/// its own path (Loose and Strict Source Route).
/// </para>
/// <para>
/// <see cref="IPv4Host"/> runs every received datagram, and every datagram it sends, through
/// <see cref="TryProcess"/>. That validates the options and adds this host's entries. The other methods answer
/// the source-route questions the host asks when delivering, replying and fragmenting.
/// </para>
/// </remarks>
public static class IPv4Options
{
    private const int TimestampFlagsFieldOffset = 3;
    private const int RouteOptionMinimumLength = 3;
    private const int TimestampOptionMinimumLength = 4;
    /// <summary>Pointer values are 1-based within the option; the first route entry follows type, length and pointer.</summary>
    private const int FirstRouteEntryPointer = RouteOptionMinimumLength + 1;
    private const int TimestampPointerFirstValid = 5;
    private const int RouteEntryLength = 4;
    private const int TimestampEntryLength = 4;
    private const int TimestampAndAddressEntryLength = 8;
    private const int TimestampFlagMask = 0x0F;
    private const int TimestampOverflowMask = 0xF0;
    private const int TimestampOverflowShift = 4;
    private const int MaximumTimestampOverflow = 15;
    private const int TimestampOnlyFlag = 0;
    private const int TimestampAndAddressFlag = 1;
    private const int PrespecifiedAddressFlag = 3;
    private const byte CopiedOptionMask = 0x80;
    private const int OptionsWordLength = 4;

    /// <summary>
    /// Validates every option and applies this host's part: appends <paramref name="local"/> to a Record Route
    /// and adds an entry to an Internet Timestamp. Unknown options are skipped once their framing checks out.
    /// </summary>
    /// <param name="packet">The datagram whose options to process.</param>
    /// <param name="local">This host's address, recorded into route and timestamp options.</param>
    /// <param name="now">Clock for timestamp entries (milliseconds since midnight UTC).</param>
    /// <param name="processed">The datagram with updated options on success; otherwise the input unchanged.</param>
    /// <param name="errorPointer">On failure, the header offset of the bad octet, for an ICMP Parameter Problem.</param>
    /// <param name="sourceRoute">Whether a Loose or Strict Source Route option is present.</param>
    /// <returns>False when an option is malformed; the datagram must then be rejected.</returns>
    public static bool TryProcess(
        IPv4Packet packet,
        IPAddress local,
        DateTimeOffset now,
        out IPv4Packet processed,
        out byte errorPointer,
        out bool sourceRoute)
    {
        var options = packet.Options.ToArray();
        processed = packet;
        sourceRoute = false;
        errorPointer = 0;

        var reader = new IPv4OptionReader(options);
        while (reader.TryReadNext(out var option))
        {
            if (ProcessOption(options, option, local, now, ref sourceRoute) is { } errorField)
            {
                errorPointer = ToHeaderPointer(errorField);
                return false;
            }
        }
        if (reader.IsMalformed)
        {
            errorPointer = ToHeaderPointer(reader.MalformedFieldIndex);
            return false;
        }

        processed = packet with { Options = options };
        return true;
    }

    /// <summary>Whether the datagram carries a Strict Source Route, which forbids any intermediate hop but the one listed.</summary>
    public static bool HasStrictSourceRoute(IPv4Packet packet)
    {
        var reader = new IPv4OptionReader(packet.Options.Span);
        while (reader.TryReadNext(out var option))
        {
            if (option.Type == IPv4OptionType.StrictSourceRoute) return true;
        }
        return false;
    }

    /// <summary>
    /// Whether a source route still lists hops not yet visited. A host that is not a router cannot forward such
    /// a datagram, so delivering it here would short-cut the route the sender asked for.
    /// </summary>
    public static bool HasIncompleteSourceRoute(IPv4Packet packet)
    {
        var reader = new IPv4OptionReader(packet.Options.Span);
        while (reader.TryReadNext(out var option))
        {
            if (IsSourceRoute(option) && option.Bytes[IPv4Option.PointerFieldOffset] <= option.Length) return true;
        }
        return false;
    }

    /// <summary>
    /// Builds a reply that retraces the request's source route in reverse (RFC 1122 3.2.1.8). The reply goes to
    /// the last recorded hop, and the route lists the remaining hops back to the original sender. A redundant
    /// entry for the sender itself is dropped. Other options are carried over unchanged.
    /// </summary>
    /// <param name="request">The received datagram, already accepted by <see cref="TryProcess"/>.</param>
    /// <param name="reply">The reply to adjust.</param>
    public static IPv4Packet ReverseSourceRoute(IPv4Packet request, IPv4Packet reply)
    {
        var output = new List<byte>();
        var reader = new IPv4OptionReader(request.Options.Span);
        while (reader.TryReadNext(out var option))
        {
            if (IsSourceRoute(option)) reply = AppendReversedRoute(output, option, request.SourceAddress, reply);
            else output.AddRange(option.Bytes);
        }
        PadToWordBoundary(output);
        return reply with { Options = output.ToArray() };
    }

    /// <summary>
    /// The options that every fragment must repeat: those with the "copied" bit set in their type octet
    /// (RFC 791 3.1). The first fragment carries all options; the rest carry only these.
    /// </summary>
    /// <exception cref="ArgumentException">The options are malformed.</exception>
    public static byte[] CopiedOptions(ReadOnlySpan<byte> options)
    {
        var copied = new List<byte>();
        var reader = new IPv4OptionReader(options);
        while (reader.TryReadNext(out var option))
        {
            if ((option.Bytes[0] & CopiedOptionMask) != 0) copied.AddRange(option.Bytes);
        }
        if (reader.IsMalformed) throw new ArgumentException("Malformed IPv4 options.");
        PadToWordBoundary(copied);
        return [.. copied];
    }

    /// <returns>The index of the offending octet within the options area, or null when the option is valid.</returns>
    private static int? ProcessOption(byte[] options, IPv4Option option, IPAddress local, DateTimeOffset now, ref bool sourceRoute) =>
        option.Type switch
        {
            IPv4OptionType.RecordRoute or IPv4OptionType.LooseSourceRoute or IPv4OptionType.StrictSourceRoute =>
                ProcessRouteOption(options, option, local, ref sourceRoute),
            IPv4OptionType.Timestamp => ProcessTimestampOption(options, option, local, now),
            // Unknown and obsolete stream-ID options are ignored after validating their framing.
            _ => null
        };

    /// <summary>
    /// Record Route and the two Source Routes share a layout: type, length, pointer, then 4-byte addresses.
    /// Record Route gets our address at the pointer. Source routes are only noted, and only one is allowed:
    /// forwarding along them is a router's job.
    /// </summary>
    private static int? ProcessRouteOption(byte[] options, IPv4Option option, IPAddress local, ref bool sourceRoute)
    {
        if (option.Length < RouteOptionMinimumLength || (option.Length - RouteOptionMinimumLength) % RouteEntryLength != 0)
            return option.FieldIndex(IPv4Option.LengthFieldOffset);

        var pointerIndex = option.FieldIndex(IPv4Option.PointerFieldOffset);
        var pointer = options[pointerIndex];
        if (pointer < FirstRouteEntryPointer || (pointer - FirstRouteEntryPointer) % RouteEntryLength != 0 || pointer > option.Length + 1)
            return pointerIndex;

        if (IsSourceRoute(option))
        {
            if (sourceRoute) return pointerIndex;
            sourceRoute = true;
        }
        else if (pointer <= option.Length)
        {
            local.GetAddressBytes().CopyTo(options, EntryIndex(option, pointer));
            options[pointerIndex] += RouteEntryLength;
        }
        return null;
    }

    /// <summary>
    /// Internet Timestamp: type, length, pointer, overflow/flags, then entries of a timestamp alone, or an
    /// address and a timestamp. When the option is full, the overflow counter is incremented instead of
    /// adding an entry; a counter that is itself full is an error.
    /// </summary>
    private static int? ProcessTimestampOption(byte[] options, IPv4Option option, IPAddress local, DateTimeOffset now)
    {
        if (option.Length < TimestampOptionMinimumLength) return option.FieldIndex(IPv4Option.LengthFieldOffset);

        var pointerIndex = option.FieldIndex(IPv4Option.PointerFieldOffset);
        var flagsIndex = option.FieldIndex(TimestampFlagsFieldOffset);
        var pointer = options[pointerIndex];
        var flags = options[flagsIndex] & TimestampFlagMask;
        if (flags is not (TimestampOnlyFlag or TimestampAndAddressFlag or PrespecifiedAddressFlag)) return flagsIndex;

        var entryLength = flags == TimestampOnlyFlag ? TimestampEntryLength : TimestampAndAddressEntryLength;
        if (pointer < TimestampPointerFirstValid ||
            (pointer - TimestampPointerFirstValid) % entryLength != 0 ||
            pointer > option.Length + 1)
            return pointerIndex;

        if (pointer + entryLength - 1 > option.Length) return CountTimestampOverflow(options, flagsIndex);
        RecordTimestamp(options, option, pointer, flags, entryLength, local, now);
        return null;
    }

    /// <summary>No room for another entry: bump the 4-bit overflow counter, failing if it is already at 15.</summary>
    private static int? CountTimestampOverflow(byte[] options, int flagsIndex)
    {
        var overflow = (options[flagsIndex] & TimestampOverflowMask) >> TimestampOverflowShift;
        if (overflow == MaximumTimestampOverflow) return flagsIndex;
        options[flagsIndex] += 1 << TimestampOverflowShift;
        return null;
    }

    /// <summary>
    /// Writes our entry at the pointer and advances it. With prespecified addresses, only the host named in the
    /// next slot may fill it, so a slot naming another host is left for that host.
    /// </summary>
    private static void RecordTimestamp(
        byte[] options, IPv4Option option, int pointer, int flags, int entryLength, IPAddress local, DateTimeOffset now)
    {
        var entryIndex = EntryIndex(option, pointer);
        var localBytes = local.GetAddressBytes();
        if (flags == PrespecifiedAddressFlag && !options.AsSpan(entryIndex, IPv4Packet.IPv4AddressLength).SequenceEqual(localBytes)) return;

        if (flags != TimestampOnlyFlag)
        {
            localBytes.CopyTo(options, entryIndex);
            entryIndex += IPv4Packet.IPv4AddressLength;
        }
        var millisecondsSinceMidnight = (uint)now.UtcDateTime.TimeOfDay.TotalMilliseconds;
        BinaryPrimitives.WriteUInt32BigEndian(options.AsSpan(entryIndex, TimestampEntryLength), millisecondsSinceMidnight);
        options[option.FieldIndex(IPv4Option.PointerFieldOffset)] += (byte)entryLength;
    }

    /// <summary>
    /// Appends the reversed form of one source-route option. If the reversed route has no hops left once the
    /// sender's own entry is removed, the option is dropped and the reply goes straight to the sender.
    /// </summary>
    private static IPv4Packet AppendReversedRoute(List<byte> output, IPv4Option option, IPAddress sender, IPv4Packet reply)
    {
        var route = ReadRoute(option);
        route.Reverse();
        while (route.Count > 0 && route[^1].Equals(sender)) route.RemoveAt(route.Count - 1);
        if (route.Count == 0) return reply;

        reply = reply with { DestinationAddress = route[0] };
        route.RemoveAt(0);
        route.Add(sender);
        output.Add(option.Bytes[0]);
        output.Add((byte)(RouteOptionMinimumLength + route.Count * RouteEntryLength));
        output.Add(FirstRouteEntryPointer);
        foreach (var hop in route) output.AddRange(hop.GetAddressBytes());
        return reply;
    }

    /// <summary>Every address slot in a route option, whether or not the pointer has reached it.</summary>
    private static List<IPAddress> ReadRoute(IPv4Option option)
    {
        var route = new List<IPAddress>();
        for (var index = RouteOptionMinimumLength; index < option.Length; index += RouteEntryLength)
            route.Add(new IPAddress(option.Bytes.Slice(index, IPv4Packet.IPv4AddressLength)));
        return route;
    }

    /// <summary>Loose or Strict Source Route: the options that let the sender steer the datagram's path.</summary>
    private static bool IsSourceRoute(IPv4Option option) =>
        option.Type is IPv4OptionType.LooseSourceRoute or IPv4OptionType.StrictSourceRoute;

    /// <summary>Converts a 1-based option pointer into an index within the options area.</summary>
    private static int EntryIndex(IPv4Option option, int pointer) => option.Offset + pointer - 1;

    /// <summary>Converts an index within the options area into an offset from the start of the IPv4 header.</summary>
    private static byte ToHeaderPointer(int optionsIndex) => (byte)(IPv4Packet.MinimumHeaderLength + optionsIndex);

    /// <summary>The header length counts 32-bit words, so the options area is padded with End-of-List octets.</summary>
    private static void PadToWordBoundary(List<byte> options)
    {
        while (options.Count % OptionsWordLength != 0) options.Add((byte)IPv4OptionType.EndOfList);
    }
}
