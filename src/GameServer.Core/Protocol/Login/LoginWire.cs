using System.Buffers.Binary;
using System.Text;

namespace GameServer.Core.Protocol.Login;

/// <summary>
/// Writes login-connection fields the way the client's stream (send 0x140dfb760) does: integers big-endian through
/// htons/htonl, except where a serializer copies memory as-is (<see cref="RawU32"/>, <see cref="RawU64"/>).
/// </summary>
public sealed class LoginWriter
{
    private readonly List<byte> _b = [];

    public int Length => _b.Count;
    public byte[] ToArray() => [.. _b];

    public LoginWriter U8(byte v) { _b.Add(v); return this; }
    public LoginWriter Bool(bool v) => U8(v ? (byte)1 : (byte)0);
    public LoginWriter U16(ushort v) { _b.Add((byte)(v >> 8)); _b.Add((byte)v); return this; }
    public LoginWriter U32(uint v) { U16((ushort)(v >> 16)); return U16((ushort)v); }

    /// <summary>A 4-byte field copied from memory without htonl (little-endian on the wire).</summary>
    public LoginWriter RawU32(uint v) { Span<byte> s = stackalloc byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(s, v); return Bytes(s); }

    /// <summary>An 8-byte field copied from memory without byte swapping (little-endian on the wire).</summary>
    public LoginWriter RawU64(ulong v) { Span<byte> s = stackalloc byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(s, v); return Bytes(s); }

    public LoginWriter Bytes(ReadOnlySpan<byte> v) { foreach (byte x in v) _b.Add(x); return this; }

    /// <summary>
    /// The client's compressed unsigned int (reader 0x1408719a0, writer pair near 0x1423bac30): the first byte's
    /// leading bits give the length — below 0x80 the value itself (7 bits), 0x80: (b &amp; 0x3f) ++ 1 byte (14 bits),
    /// 0xC0: (b &amp; 0x1f) ++ 2 bytes (21 bits), 0xE0: (b &amp; 0x1f) ++ 3 bytes (29 bits), 0xF0: the full byte
    /// ++ 4 bytes. Used by the 0x15 pair vector's count. Canonical (shortest) form is written.
    /// </summary>
    public LoginWriter VarintU(uint v)
    {
        if (v < 0x80) return U8((byte)v);
        if (v < 0x4000) return U8((byte)(0x80 | (v >> 8))).U8((byte)v);
        if (v < 0x200000) return U8((byte)(0xC0 | (v >> 16))).U8((byte)(v >> 8)).U8((byte)v);
        if (v < 0x20000000) return U8((byte)(0xE0 | (v >> 24))).U8((byte)(v >> 16)).U8((byte)(v >> 8)).U8((byte)v);
        throw new ArgumentOutOfRangeException(nameof(v), "varint too large for the forms in use");
    }

    /// <summary>The signed twin (reader 0x141cfc160): same length tags, the value's sign in the bit below the
    /// tag bits (0x40 / 0x20 / 0x10), sign-extended on read. Used by the 0x15 pair vector's values.</summary>
    public LoginWriter VarintS(int v)
    {
        if (v is >= -64 and < 64) return U8((byte)(v & 0x7f));
        if (v is >= -8192 and < 8192) { int u = v & 0x3fff; return U8((byte)(0x80 | (u >> 8))).U8((byte)u); }
        if (v is >= -1048576 and < 1048576) { int u = v & 0x1fffff; return U8((byte)(0xC0 | (u >> 16))).U8((byte)(u >> 8)).U8((byte)u); }
        int w = v & 0x1fffffff;
        return U8((byte)(0xE0 | (w >> 24))).U8((byte)(w >> 16)).U8((byte)(w >> 8)).U8((byte)w);
    }

    /// <summary>A fixed-size field (digests, ids): exactly <paramref name="size"/> bytes.</summary>
    public LoginWriter Fixed(byte[] v, int size)
    {
        if (v.Length != size) throw new ArgumentException($"field must be {size} bytes, got {v.Length}");
        return Bytes(v);
    }

    /// <summary>u16 length + bytes (client 0x1408402a0 / 0x141fa44f0).</summary>
    public LoginWriter Blob(byte[] v) => U16(checked((ushort)v.Length)).Bytes(v);

    /// <summary>A narrow std::string as u16 length + bytes; the client converts with UTF-8.</summary>
    public LoginWriter Str(string v) => Blob(Encoding.UTF8.GetBytes(v));

    /// <summary>
    /// A wide string in the compact form of client 0x140e0c9b0: u16 count of code points, then per code point either
    /// one byte (&lt; 0x80), 0x80 + the UTF-16 unit little-endian, or 0xC0 + the code point as u32 little-endian.
    /// Lone surrogates go out as 0x80 + U+FFFD, as the client does.
    /// </summary>
    public LoginWriter WStr(string v)
    {
        var cps = new List<int>(v.Length);
        for (int i = 0; i < v.Length; i++)
        {
            char c = v[i];
            if (char.IsHighSurrogate(c) && i + 1 < v.Length && char.IsLowSurrogate(v[i + 1])) cps.Add(char.ConvertToUtf32(c, v[++i]));
            else cps.Add(char.IsSurrogate(c) ? 0xFFFD : c);
        }
        U16(checked((ushort)cps.Count));
        foreach (int cp in cps)
        {
            if (cp < 0x80) U8((byte)cp);
            else if (cp < 0x10000) { U8(0x80); U8((byte)cp); U8((byte)(cp >> 8)); }
            else { U8(0xC0); RawU32((uint)cp); }
        }
        return this;
    }
}

/// <summary>
/// Reads login-connection fields. Like the client's receive stream (0x140dfb630, flag +0x252), running out of data
/// does not throw: <see cref="Short"/> is set and defaults are returned, so the caller can wait for more bytes.
/// Malformed data (bad wide-string markers) throws <see cref="InvalidDataException"/>.
/// </summary>
public ref struct LoginReader(ReadOnlySpan<byte> buf)
{
    private readonly ReadOnlySpan<byte> _buf = buf;

    public int Position { get; private set; }
    public bool Short { get; private set; }

    private ReadOnlySpan<byte> Take(int n)
    {
        if (Short || _buf.Length - Position < n) { Short = true; return default; }
        var s = _buf.Slice(Position, n);
        Position += n;
        return s;
    }

    public byte U8() { var s = Take(1); return Short ? (byte)0 : s[0]; }
    public bool Bool() => U8() != 0;
    public ushort U16() { var s = Take(2); return Short ? (ushort)0 : BinaryPrimitives.ReadUInt16BigEndian(s); }
    public uint U32() { var s = Take(4); return Short ? 0 : BinaryPrimitives.ReadUInt32BigEndian(s); }
    public uint RawU32() { var s = Take(4); return Short ? 0 : BinaryPrimitives.ReadUInt32LittleEndian(s); }
    public ulong RawU64() { var s = Take(8); return Short ? 0 : BinaryPrimitives.ReadUInt64LittleEndian(s); }
    public byte[] Fixed(int n) { var s = Take(n); return Short ? new byte[n] : s.ToArray(); }

    /// <summary>Inverse of <see cref="LoginWriter.VarintU"/> (client reader 0x1408719a0).</summary>
    public uint VarintU()
    {
        uint b = U8();
        if (Short) return 0;
        if (b < 0x80) return b;
        if ((b & 0xC0) == 0x80) { uint v = (b & 0x3F) << 8 | U8(); return Short ? 0 : v; }
        if ((b & 0xE0) == 0xC0) { uint v = (b & 0x1F) << 16 | (uint)U8() << 8 | U8(); return Short ? 0 : v; }
        if ((b & 0xF0) == 0xE0) { uint v = (b & 0x1F) << 24 | (uint)U8() << 16 | (uint)U8() << 8 | U8(); return Short ? 0 : v; }
        uint w = b << 24 | (uint)U8() << 16 | (uint)U8() << 8 | U8();
        return Short ? 0 : w;
    }

    /// <summary>Inverse of <see cref="LoginWriter.VarintS"/> (client reader 0x141cfc160).</summary>
    public int VarintS()
    {
        uint b = U8();
        if (Short) return 0;
        if (b < 0x80) return (b & 0x40) != 0 ? (int)(b | 0xFFFFFF80) : (int)b;
        if ((b & 0xC0) == 0x80) { uint v = (b & 0x3F) << 8 | U8(); return Short ? 0 : (b & 0x20) != 0 ? (int)(v | 0xFFFFC000) : (int)v; }
        if ((b & 0xE0) == 0xC0) { uint v = (b & 0x1F) << 16 | (uint)U8() << 8 | U8(); return Short ? 0 : (b & 0x10) != 0 ? (int)(v | 0xFFE00000) : (int)v; }
        if ((b & 0xF0) == 0xE0) { uint v = (b & 0x1F) << 24 | (uint)U8() << 16 | (uint)U8() << 8 | U8(); return Short ? 0 : (b & 0x08) != 0 ? (int)(v | 0xE0000000) : (int)v; }
        throw new InvalidDataException("bad signed varint tag");
    }
    public byte[] Blob() { int n = U16(); return Short ? [] : Fixed(n); }
    public string Str() => Encoding.UTF8.GetString(Blob());

    /// <summary>Inverse of <see cref="LoginWriter.WStr"/>, with the client's checks from 0x140e0cbe0.</summary>
    public string WStr()
    {
        int count = U16();
        var sb = new StringBuilder(count);
        for (int i = 0; i < count && !Short; i++)
        {
            byte tag = U8();
            if (Short) break;
            if (tag < 0x80) sb.Append((char)tag);
            else if (tag == 0x80)
            {
                var s = Take(2);
                if (Short) break;
                ushort u = BinaryPrimitives.ReadUInt16LittleEndian(s);
                if (u is >= 0xD800 and < 0xE000) throw new InvalidDataException("Protocol violation reading wstring from the network");
                sb.Append((char)u);
            }
            else if (tag == 0xC0)
            {
                uint cp = RawU32();
                if (Short) break;
                if (cp is >= 0xD800 and < 0xDC00)
                {
                    // A high surrogate sent as its own 0xC0 element; the client pairs it with a following 0xC0 low surrogate.
                    int save = Position;
                    if (i + 1 < count && U8() == 0xC0 && RawU32() is uint lo and >= 0xDC00 and < 0xE000 && !Short)
                    {
                        sb.Append((char)cp).Append((char)lo);
                        i++;
                    }
                    else if (Short) break;
                    else { Position = save; sb.Append('�'); }
                }
                else if (cp is >= 0xDC00 and < 0xE000 || cp > 0x10FFFF) sb.Append('�');
                else if (cp < 0x10000) throw new InvalidDataException("Protocol violation reading wstring from the network");
                else sb.Append(char.ConvertFromUtf32((int)cp));
            }
            else throw new InvalidDataException("Protocol violation reading wstring from the network");
        }
        return Short ? "" : sb.ToString();
    }
}
