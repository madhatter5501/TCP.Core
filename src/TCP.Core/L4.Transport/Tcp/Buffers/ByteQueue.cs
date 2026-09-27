namespace TCP.L4.Transport.Tcp.Buffers;

/// <summary>A growable circular byte buffer with bulk enqueue, dequeue and peek.</summary>
/// <remarks>
/// TCP's send and receive buffers are FIFO byte streams. With window scaling they can hold megabytes, so they copy
/// spans in bulk rather than a byte at a time. Storage grows by doubling and never shrinks while in use;
/// <see cref="Clear"/> releases it.
/// </remarks>
internal sealed class ByteQueue
{
    private const int InitialCapacity = 256;

    private byte[] _buffer = [];
    private int _head;

    /// <summary>Bytes currently queued.</summary>
    public int Count { get; private set; }

    /// <summary>Appends <paramref name="bytes"/> at the tail.</summary>
    public void Enqueue(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty) return;
        EnsureCapacity(Count + bytes.Length);
        var tail = (_head + Count) % _buffer.Length;
        var first = Math.Min(bytes.Length, _buffer.Length - tail);
        bytes[..first].CopyTo(_buffer.AsSpan(tail));
        bytes[first..].CopyTo(_buffer);
        Count += bytes.Length;
    }

    /// <summary>Copies up to <paramref name="destination"/>'s length from the head without removing it.</summary>
    /// <returns>Bytes copied.</returns>
    public int Peek(Span<byte> destination)
    {
        var count = Math.Min(destination.Length, Count);
        if (count == 0) return 0;
        var first = Math.Min(count, _buffer.Length - _head);
        _buffer.AsSpan(_head, first).CopyTo(destination);
        _buffer.AsSpan(0, count - first).CopyTo(destination[first..]);
        return count;
    }

    /// <summary>Moves up to <paramref name="destination"/>'s length from the head into it.</summary>
    /// <returns>Bytes moved.</returns>
    public int Dequeue(Span<byte> destination)
    {
        var count = Peek(destination);
        Skip(count);
        return count;
    }

    /// <summary>Removes and returns the next <paramref name="count"/> bytes, or all of them if fewer are queued.</summary>
    public byte[] Dequeue(int count)
    {
        var bytes = new byte[Math.Min(count, Count)];
        Dequeue(bytes);
        return bytes;
    }

    /// <summary>Discards everything and releases the storage.</summary>
    public void Clear()
    {
        _buffer = [];
        _head = 0;
        Count = 0;
    }

    /// <summary>Drops <paramref name="count"/> bytes from the head.</summary>
    private void Skip(int count)
    {
        Count -= count;
        _head = Count == 0 ? 0 : (_head + count) % _buffer.Length;
    }

    /// <summary>Grows the storage by doubling, unwrapping the contents to the start of the new array.</summary>
    private void EnsureCapacity(int required)
    {
        if (required <= _buffer.Length) return;
        var capacity = Math.Max(InitialCapacity, _buffer.Length);
        while (capacity < required) capacity *= 2;
        var grown = new byte[capacity];
        Peek(grown);
        _buffer = grown;
        _head = 0;
    }
}
