namespace GameServer.Core.Protocol.Login;

// Login-connection messages after the key exchange. Every message is `u16 id` followed by its fields, with no length
// prefix, so the reader must know each id's layout. Layouts come from the client's serializers (vtable slot 1 writes
// the id and fields, slot 2 reads the fields); see Agents/docs/re/009-login-messages.md for addresses. Field names are ours.
// Where the client's use of a field is unknown, the name says what it is on the wire.

public interface ILoginMessage
{
    ushort MessageId { get; }

    /// <summary>Writes the fields after the id.</summary>
    void WriteFields(LoginWriter w);
}

public static class LoginMessage
{
    public static byte[] Encode(ILoginMessage m)
    {
        var w = new LoginWriter().U16(m.MessageId);
        m.WriteFields(w);
        return w.ToArray();
    }
}

/// <summary>Messages with no fields: S→C 0x01; C→S 0x01, 0x19, 0x21, 0x23, 0x39.</summary>
public sealed record EmptyMessage(ushort MessageId) : ILoginMessage
{
    public void WriteFields(LoginWriter w) { }
}

/// <summary>A u16 followed by a u32 (0.5.5 client class vtable 0x143509F18, read fn 0x14214e460,
/// write fn 0x14214e3e0: u16 at +0x14 read first, then u32 at +0x10): S→C 0x0b, 0x0d, 0x0f,
/// 0x17 (disconnect reason), 0x1e, 0x44. An earlier u16-only model desynced the client on the
/// first delete-character result (0x0d), live 2026-11-04.</summary>
public sealed record U16Message(ushort MessageId, ushort Value, uint Value32 = 0) : ILoginMessage
{
    public void WriteFields(LoginWriter w) => w.U16(Value).U32(Value32);
    internal static U16Message Read(ushort id, ref LoginReader r) => new(id, r.U16(), r.U32());
}

/// <summary>One u32 (class 0x14316c420, 0x140912ff0/0x140913050): S→C 0x1f, 0x20. Also C→S 0x46 (sender 0x140d14690).</summary>
public sealed record U32Message(ushort MessageId, uint Value) : ILoginMessage
{
    public void WriteFields(LoginWriter w) => w.U32(Value);
    internal static U32Message Read(ushort id, ref LoginReader r) => new(id, r.U32());
}

/// <summary>One u8: C→S 0x3a (0x140d08c80), 0x42 (0x142140810).</summary>
public sealed record U8Message(ushort MessageId, byte Value) : ILoginMessage
{
    public void WriteFields(LoginWriter w) => w.U8(Value);
    internal static U8Message Read(ushort id, ref LoginReader r) => new(id, r.U8());
}

/// <summary>One wide string (class 0x1435bf650, 0x141f91850/0x141f918b0): S→C 0x24, 0x25, 0x26, 0x28, 0x29; C→S 0x3f, 0x40.</summary>
public sealed record WStringMessage(ushort MessageId, string Text) : ILoginMessage
{
    public void WriteFields(LoginWriter w) => w.WStr(Text);
    internal static WStringMessage Read(ushort id, ref LoginReader r) => new(id, r.WStr());
}

/// <summary>Wide string + u8 (class 0x1435bfcd8, 0x141f950c0/0x141f95140): C→S 0x0c, 0x2a, 0x2b. The byte is the realm byte | 0x40 for 0x2a/0x2b.</summary>
public sealed record WStringU8Message(ushort MessageId, string Text, byte Value) : ILoginMessage
{
    public void WriteFields(LoginWriter w) => w.WStr(Text).U8(Value);
    internal static WStringU8Message Read(ushort id, ref LoginReader r) => new(id, r.WStr(), r.U8());

}

/// <summary>C→S 0x0c delete character, 0.5.5 layout: the character's name, its list index as the byte,
/// and a trailing u32 (0 in both live captures, 2026-11-04). The u32 is part of the message: dropping it
/// desynchronises the stream, the decoder then meets id 0x0000 and every later message on the connection
/// goes undecoded (a create-character request was lost this way).</summary>
public sealed record DeleteCharacter(ushort MessageId, string Text, byte Value, uint Tail) : ILoginMessage
{
    public void WriteFields(LoginWriter w) => w.WStr(Text).U8(Value).U32(Tail);
    internal static DeleteCharacter Read(ushort id, ref LoginReader r) => new(id, r.WStr(), r.U8(), r.U32());
}

// ---------------------------------------------------------------- server → client

/// <summary>
/// S→C 0x04, client 0.5.5 (factory 0x14214fbe0: vtable 0x143509ed8, object 0x90 bytes; write 0x14214dad0,
/// read 0x14214dbe0; disassembly-verified 2026-11-04): a big-endian u32 (+0x10), a big-endian u16 (+0x14),
/// the account wide string (string object at +0x48), the 32-byte saved-credential digest (+0x16), a RAW
/// (never byte-swapped) u16 at +0x88 — the two flag bytes, in order — and a u16-length blob (vector at +0x68).
/// This differs from the PoE1-era layout (a lone u16 result first): with the old layout the 0.5.5 client's
/// wide-string reader starts four bytes early, lands inside the digest and throws "Protocol violation reading
/// wstring from the network" before the league list is even reached (live 2026-11-04 06:01, after the login
/// itself had already succeeded). Which of the two leading integers the client gates on is not yet pinned
/// down — the result code is written to BOTH (on success both are 0 anyway).
/// </summary>
public sealed record LoginResult(uint Result32, ushort Result, string AccountName, byte[] Digest, byte Flags0, byte Flags1, byte[] Data) : ILoginMessage
{
    public const ushort Id = 0x04;
    public ushort MessageId => Id;

    /// <summary>Builds a result with the code in both leading fields (see the layout note).</summary>
    public static LoginResult Of(ushort result, byte[] digest, byte flags0, byte flags1, byte[] data) =>
        new(result, result, "", digest, flags0, flags1, data);

    public void WriteFields(LoginWriter w) => w.U32(Result32).U16(Result).WStr(AccountName).Fixed(Digest, 32).U8(Flags0).U8(Flags1).Blob(Data);
    internal static LoginResult Read(ushort id, ref LoginReader r) => new(r.U32(), r.U16(), r.WStr(), r.Fixed(32), r.U8(), r.U8(), r.Blob());
}

/// <summary>S→C 0x11 (vtable 0x1435dba88, 0x14219b5a0/0x14219b610): u8 + u16-length blob, parsed by the client into 17 records of 0x80 bytes (0x14213d060).</summary>
public sealed record Blob11(byte Kind, byte[] Data) : ILoginMessage
{
    public const ushort Id = 0x11;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.U8(Kind).Blob(Data);
    internal static Blob11 Read(ushort id, ref LoginReader r) => new(r.U8(), r.Blob());
}

/// <summary>S→C 0x13: the answer to C→S 0x12 (create character). The create screen's listener treats 0 as done
/// ("character_creation_done") and goes back to the character list. When the flag is set the client posts to
/// /api/tracking-conversions/. Client 0.5.5 (vtable 0x143509e98, write 0x14214eb50, read 0x14214ebf0;
/// disassembly-verified 2026-11-04): result u16 (+0x16), the flag byte (+0x14), then a big-endian u32 (+0x10)
/// the PoE1-era layout did not have — its meaning is unknown, sent 0.</summary>
public sealed record CreateCharacterResult(ushort Result, bool Tracking, uint U32) : ILoginMessage
{
    public const ushort Id = 0x13;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.U16(Result).Bool(Tracking).U32(U32);
    internal static CreateCharacterResult Read(ushort id, ref LoginReader r) => new(r.U16(), r.Bool(), r.U32());
}

/// <summary>
/// S→C 0x14 (vtable 0x1435dba08, 0x14219b9c0/0x14219bb20): instance (game server) assignment. AreaHash is looked up in
/// the area table ("Area reported by instance does not exist. Hash was: ").
/// </summary>
public sealed record InstanceInfo(string Host, ushort U16_30, uint U32_34, ushort AreaHash, uint U32_38, byte[] Key64, byte[] Data8, byte U8_86) : ILoginMessage
{
    public const ushort Id = 0x14;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) =>
        w.Str(Host).U16(U16_30).U32(U32_34).U16(AreaHash).U32(U32_38).Fixed(Key64, 64).Fixed(Data8, 8).U8(U8_86);
    internal static InstanceInfo Read(ushort id, ref LoginReader r) =>
        new(r.Str(), r.U16(), r.U32(), r.U16(), r.U32(), r.Fixed(64), r.Fixed(8), r.U8());
}

/// <summary>
/// Element of S→C 0x15, client 0.5.5 (0x58-byte struct; list reader 0x142716700, entry writer 0x142716570;
/// disassembly-verified 2026-11-04). Wire order differs from struct order; names give the struct offset. The
/// PoE1 era had the level at +0x48 and the class at +0x4a as BYTES with a dead-marker byte at +0x49; in 0.5.5
/// both widened to u16 at the same offsets, so the old B49/B4b bytes have no home — the dead marker must live
/// in one of the new bytes (+0x4e/+0x4f/+0x50/+0x51), still unknown; they are sent 0.
/// </summary>
public sealed record ListEntry15(string Name, string Text, byte B4d, byte B51, byte B4c, uint U40, byte B4e,
    ushort U44, ushort U46, ushort Level, ushort Class, byte B4f, byte B50)
{
    internal void Write(LoginWriter w) => w.WStr(Name).WStr(Text)
        .U8(B4d).U8(B51).U8(B4c).U32(U40).U8(B4e).U16(U44).U16(U46).U16(Level).U16(Class).U8(B4f).U8(B50);
    internal static ListEntry15 Read(ref LoginReader r) =>
        new(r.WStr(), r.WStr(), r.U8(), r.U8(), r.U8(), r.U32(), r.U8(), r.U16(), r.U16(), r.U16(), r.U16(), r.U8(), r.U8());
}

/// <summary>One element of 0x15's trailing pair vector: a u16 (big-endian) and a signed compressed int
/// (client 0x141cfc160). The vector itself is a compressed-unsigned-int count (client 0x1408719a0) followed
/// by the elements; the vector reader is 0x1423bacb0, its writer 0x1423bac30.</summary>
public sealed record ListPair15(ushort Key, int Value)
{
    internal void Write(LoginWriter w) => w.U16(Key).VarintS(Value);
    internal static ListPair15 Read(ref LoginReader r) => new(r.U16(), r.VarintS());
}

/// <summary>
/// S→C 0x15, client 0.5.5 (factory 0x14214fbe0: vtable 0x143509f98, object 0x78 bytes; write 0x14214df90,
/// read 0x14214e210; disassembly-verified 2026-11-04): a big-endian u32 (+0x70), the entries as u8 count +
/// elements (vector at +0x10), two bytes (+0x28/+0x29 — same slots as the PoE1 era's selected index and
/// character slots), two big-endian u16 (+0x74/+0x76), a narrow string (+0x30, reader 0x141f4d500), the pair
/// vector (+0x48), and two big-endian u32 (+0x68/+0x6c). Nothing of the PoE1-era tail blob remains. The new
/// scalar fields' meanings are unknown; they are sent 0/empty.
/// </summary>
public sealed record List15(uint Head32, IReadOnlyList<ListEntry15> Entries, byte B28, byte B29,
    ushort U74, ushort U76, string Text30, IReadOnlyList<ListPair15> Pairs, uint Tail68, uint Tail6C) : ILoginMessage
{
    public const ushort Id = 0x15;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w)
    {
        w.U32(Head32).U8(checked((byte)Entries.Count));
        foreach (var e in Entries) e.Write(w);
        w.U8(B28).U8(B29).U16(U74).U16(U76).Str(Text30);
        w.VarintU(checked((uint)Pairs.Count));
        foreach (var p in Pairs) p.Write(w);
        w.U32(Tail68).U32(Tail6C);
    }
    internal static List15 Read(ushort id, ref LoginReader r)
    {
        uint head = r.U32();
        int n = r.U8();
        var list = new List<ListEntry15>(n);
        for (int i = 0; i < n && !r.Short; i++) list.Add(ListEntry15.Read(ref r));
        byte b28 = r.U8(), b29 = r.U8();
        ushort u74 = r.U16(), u76 = r.U16();
        string text = r.Str();
        uint np = r.VarintU();
        var pairs = new List<ListPair15>();
        for (uint i = 0; i < np && !r.Short; i++) pairs.Add(ListPair15.Read(ref r));
        return new(head, list, b28, b29, u74, u76, text, pairs, r.U32(), r.U32());
    }
}

/// <summary>
/// A league: element of S→C 0x1a / 0x1b (0xe8-byte struct, read by 0x1424ed2c0, constructed by 0x1408befd0). Static
/// analysis 2026-10-18 (Agents/docs/protocol/01-login.md §7):
/// <list type="bullet">
/// <item>Name (+0x10, view at +0x00): what C→S 0x12 sends back and what 0x15's league text is compared with.</item>
/// <item>SsfParent (+0x60), HardcoreParent (+0x80), RuthlessParent (+0xa0): a variant names the league it is the SSF /
/// Hardcore / Ruthless form of. The create screen (0x140ccc4a0) shows one card per main league and its Hardcore, Solo
/// Self-Found and Ruthless check boxes switch to the variants found through these links (combinations chain: SSF
/// Hardcore links SsfParent to the Hardcore league).</item>
/// <item>Flags0 (+0xe0): bit 0 private (password box), bit 1 hardcore (confirmation, hardcore banner), bit 4 shown only
/// while +0xc8 is in the future, bit 7 main league (gets a card). Flags1 (+0xe1): bit 1 variant (no card of its own),
/// bit 5 hidden on some platforms, bit 6 ruthless (confirmation). Flags2 (+0xe2): bit 0 counted into login+0xe58.</item>
/// <item>StartStateSet (+0xc0): CharacterStartStateSet row for new characters. C1 (+0xc1): 1 scrolls to the league's card.</item>
/// </list>
/// Description (+0x40, view +0x30): the card text, a ClientStrings-style key when it starts with '#'; empty crashes the
/// client ("invalid string position", 0x140cc8820). The times (+0xd0, +0xd8, +0xc8, little-endian) are unconfirmed;
/// Client 0.5.5 entry reader (0x142716e10, disassembly-verified 2026-11-03): the wire tail after the three raw64s
/// is SIX u8s — flags0/1/2 (+0xe0..0xe2), StartStateSet (+0xc0), C1 (+0xc1) and C2 (+0xc2, meaning unknown, sent 0).
/// There is NO trailing raw32: the older layout (raw32 at +0xc4) writes 3 bytes too many per entry, desyncs every
/// following entry and makes the 0.5.5 client throw "Protocol violation reading wstring from the network" on 0x1b.
/// </summary>
public sealed record LeagueEntry(string Name, string Description, string SsfParent, string HardcoreParent, string RuthlessParent,
    ulong RawD0, ulong RawD8, ulong RawC8, byte Flags0, byte Flags1, byte Flags2, byte StartStateSet, byte C1, byte C2)
{
    public const byte Private = 0x01, Hardcore = 0x02, Timed = 0x10, Main = 0x80;
    public const byte Variant = 0x02, PlatformHidden = 0x20, Ruthless = 0x40;

    internal void Write(LoginWriter w) =>
        w.WStr(Name).WStr(Description).WStr(SsfParent).WStr(HardcoreParent).WStr(RuthlessParent).RawU64(RawD0).RawU64(RawD8).RawU64(RawC8)
         .U8(Flags0).U8(Flags1).U8(Flags2).U8(StartStateSet).U8(C1).U8(C2);
    internal static LeagueEntry Read(ref LoginReader r) =>
        new(r.WStr(), r.WStr(), r.WStr(), r.WStr(), r.WStr(), r.RawU64(), r.RawU64(), r.RawU64(),
            r.U8(), r.U8(), r.U8(), r.U8(), r.U8(), r.U8());

    internal static void WriteList(LoginWriter w, IReadOnlyList<LeagueEntry> list)
    {
        w.U32((uint)list.Count);
        foreach (var e in list) e.Write(w);
    }

    internal static List<LeagueEntry> ReadList(ref LoginReader r)
    {
        uint n = r.U32();
        var list = new List<LeagueEntry>();
        for (uint i = 0; i < n && !r.Short; i++) list.Add(Read(ref r));
        return list;
    }
}

/// <summary>S→C 0x1a (vtable 0x1435db9e8, 0x14219b6d0/0x14219b740): result + the leagues with progress to migrate from,
/// the answer to C→S 0x19 (listener 0x140d17170 at +0x810; a non-zero result shows a "League Migrations" error, an
/// empty list "There are no available leagues to migrate progress from.").</summary>
public sealed record LeaguesWithProgress(ushort Result, IReadOnlyList<LeagueEntry> Leagues) : ILoginMessage
{
    public const ushort Id = 0x1a;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) { w.U16(Result); LeagueEntry.WriteList(w, Leagues); }
    internal static LeaguesWithProgress Read(ushort id, ref LoginReader r) => new(r.U16(), LeagueEntry.ReadList(ref r));
}

/// <summary>
/// S→C 0x1b (vtable 0x1435dba28, 0x14219bd20/0x14219bdb0): the league list (login+0xe88), which the character screen
/// copies (0x140d12590) and the create-character screen offers; with no leagues its Create button stays disabled
/// (0x140cf97a0). ServerTime is a raw little-endian i64 (the client stores it minus _time64). Flags bit 0 → +0x30, bit 1
/// → +0x31 (append to the existing list instead of replacing).
/// </summary>
public sealed record LeagueList(long ServerTime, IReadOnlyList<LeagueEntry> Leagues, bool Flag0, bool Append) : ILoginMessage
{
    public const ushort Id = 0x1b;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w)
    {
        w.RawU64((ulong)ServerTime);
        LeagueEntry.WriteList(w, Leagues);
        w.U8((byte)((Flag0 ? 1 : 0) | (Append ? 2 : 0)));
    }
    internal static LeagueList Read(ushort id, ref LoginReader r)
    {
        long t = (long)r.RawU64();
        var list = LeagueEntry.ReadList(ref r);
        byte f = r.U8();
        return new(t, list, (f & 1) != 0, (f & 2) != 0);
    }
}

/// <summary>S→C 0x3c (vtable 0x1435bf8a8, 0x141f926a0/0x141f92720): two u32; the second is stored at +0xe60.</summary>
public sealed record TwoU32(uint A, uint B) : ILoginMessage
{
    public const ushort Id = 0x3c;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.U32(A).U32(B);
    internal static TwoU32 Read(ushort id, ref LoginReader r) => new(r.U32(), r.U32());
}

/// <summary>S→C 0x3e (vtable 0x1435dba68, 0x141f95fa0/0x14219bef0): u16 + bool.</summary>
public sealed record U16Bool(ushort Value, bool Flag) : ILoginMessage
{
    public const ushort Id = 0x3e;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.U16(Value).Bool(Flag);
    internal static U16Bool Read(ushort id, ref LoginReader r) => new(r.U16(), r.Bool());
}

/// <summary>S→C 0x41 (vtable 0x1435c01b8, 0x141f9f890/0x141f9f920): one narrow string.</summary>
public sealed record StringMessage(string Text) : ILoginMessage
{
    public const ushort Id = 0x41;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.Str(Text);
    internal static StringMessage Read(ushort id, ref LoginReader r) => new(r.Str());
}

/// <summary>S→C 0x43 (vtable 0x1435bf630, 0x141f9f430/0x141f9f4b0): u8 + wide string.</summary>
public sealed record U8WString(byte Value, string Text) : ILoginMessage
{
    public const ushort Id = 0x43;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.U8(Value).WStr(Text);
    internal static U8WString Read(ushort id, ref LoginReader r) => new(r.U8(), r.WStr());
}

/// <summary>S→C 0x47 (vtable 0x1435dbaa8, 0x14219bfe0/0x14219c1c0): u32, u16, then a u8 count of narrow strings.</summary>
public sealed record StringList47(uint A, ushort B, IReadOnlyList<string> Items) : ILoginMessage
{
    public const ushort Id = 0x47;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w)
    {
        w.U32(A).U16(B).U8(checked((byte)Items.Count));
        foreach (var s in Items) w.Str(s);
    }
    internal static StringList47 Read(ushort id, ref LoginReader r)
    {
        uint a = r.U32(); ushort b = r.U16(); int n = r.U8();
        var list = new List<string>(n);
        for (int i = 0; i < n && !r.Short; i++) list.Add(r.Str());
        return new(a, b, list);
    }
}

// ---------------------------------------------------------------- client → server

/// <summary>
/// C→S 0x18: the character screen asking for the character list, answered with S→C 0x15. The PoE1-era message
/// was empty; the 0.5.5 client appends a u32 — four zero bytes on the wire, live 2026-11-04 06:50. Decoded as
/// empty, the stream desynced at that point and every later message on the connection (the create-character
/// 0x12 included) was silently dropped, leaving the client waiting forever. The u32's meaning is unknown;
/// the value is ignored.
/// </summary>
public sealed record CharacterListRequest(uint Value) : ILoginMessage
{
    public const ushort Id = 0x18;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.U32(Value);
    internal static CharacterListRequest Read(ushort id, ref LoginReader r) => new(r.U32());
}

/// <summary>
/// C→S 0x03 (vtable 0x1435d8b88, write 0x14213c660, senders 0x14213ea10 and 0x140d05f70): account login.
/// Version is 2. MachineIdA comes from 0x14213e970 and MachineIdB from 0x14299b130 (32-byte client identifiers),
/// PasswordDigest is 32 bytes (the client hashes passwords with SHA-256 over UTF-16LE, 0x140e23290). Realm is the
/// realm byte (0x143a6002c) | 0x40. Flag94 requests Remember Password; Flag95 means PasswordDigest
/// carries the previously returned LoginResult.Digest saved credential rather than a password hash.
/// </summary>
public sealed record AccountLogin(uint Version, string Account, byte[] MachineIdA, byte[] PasswordDigest, byte[] MachineIdB,
    bool Flag94, bool Flag95, byte Realm, byte B97) : ILoginMessage
{
    public const ushort Id = 0x03;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) =>
        w.U32(Version).Str(Account).Fixed(MachineIdA, 32).Fixed(PasswordDigest, 32).Fixed(MachineIdB, 32)
         .Bool(Flag94).Bool(Flag95).U8(Realm).U8(B97);
    internal static AccountLogin Read(ushort id, ref LoginReader r) =>
        new(r.U32(), r.Str(), r.Fixed(32), r.Fixed(32), r.Fixed(32), r.Bool(), r.Bool(), r.U8(), r.U8());
}

/// <summary>C→S 0x05 (vtable 0x1435d8b30, 0x14213c1c0/0x14213c290, sender 0x14213eda0): login with a binary token.</summary>
public sealed record TokenLogin(byte Realm, byte[] MachineIdB, byte[] MachineIdA, byte B69, byte[] Token) : ILoginMessage
{
    public const ushort Id = 0x05;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.U8(Realm).Fixed(MachineIdB, 32).Fixed(MachineIdA, 32).U8(B69).Blob(Token);
    internal static TokenLogin Read(ushort id, ref LoginReader r) => new(r.U8(), r.Fixed(32), r.Fixed(32), r.U8(), r.Blob());
}

/// <summary>C→S 0x06 / 0x07 (vtable 0x1435d8ae8, 0x14213bf60/0x14213c050, senders 0x14213eba0 / 0x14213ef90): login with a string ticket.</summary>
public sealed record TicketLogin(ushort MessageId, string Ticket, byte Realm, byte[] MachineIdB, byte[] MachineIdA, byte B71) : ILoginMessage
{
    public void WriteFields(LoginWriter w) => w.Str(Ticket).U8(Realm).Fixed(MachineIdB, 32).Fixed(MachineIdA, 32).U8(B71);
    internal static TicketLogin Read(ushort id, ref LoginReader r) => new(id, r.Str(), r.U8(), r.Fixed(32), r.Fixed(32), r.U8());
}

/// <summary>C→S 0x08 (sender 0x140d60410): u32 + 8 raw bytes. Sent through the object at global+0x350, not the login object (+0x358).</summary>
public sealed record U32Raw64(uint A, ulong RawB) : ILoginMessage
{
    public const ushort Id = 0x08;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.U32(A).RawU64(RawB);
    internal static U32Raw64 Read(ushort id, ref LoginReader r) => new(r.U32(), r.RawU64());
}

/// <summary>C→S 0x0a (vtable 0x1435d8aa0, 0x14213c9f0/0x14213ca50, sender 0x140cf3150): two SHA-256 digests of UTF-16LE strings.</summary>
public sealed record TwoDigests(byte[] DigestA, byte[] DigestB) : ILoginMessage
{
    public const ushort Id = 0x0a;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.Fixed(DigestA, 32).Fixed(DigestB, 32);
    internal static TwoDigests Read(ushort id, ref LoginReader r) => new(r.Fixed(32), r.Fixed(32));
}

/// <summary>C→S 0x0e: Play — enter the game with the selected character; the client shows "Contacting
/// Server..." until S→C 0x14 arrives. The PoE1-era message (vtable 0x1435c0898, 0x141f92c90/0x141f92d10,
/// sender 0x1421406f0) was a realm byte and a u32. Client 0.5.5 sends TEN payload bytes (live 2026-11-04
/// 07:38: 06 01, then eight zeros, with one character on the account): read here as a byte, a second byte —
/// 1 with a single character, plausibly the 1-based character index (inferred) — and an opaque eight-byte
/// tail. The five-byte PoE1 reading left the tail unread and desynced the stream right after Play.</summary>
public sealed record PlayRequest(byte Realm, byte Index, byte[] Tail) : ILoginMessage
{
    public const ushort Id = 0x0e;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.U8(Realm).U8(Index).Fixed(Tail, 8);
    internal static PlayRequest Read(ushort id, ref LoginReader r) => new(r.U8(), r.U8(), r.Fixed(8));
}

/// <summary>C→S 0x10: the 0.5.5 client sends this right after a character list that contains a character
/// (live 2026-11-04: ~50 ms after S→C 0x15 with one entry, both at login and after a create; with an empty
/// list it is not sent) — apparently the character screen reporting its selection. Five payload bytes, all
/// zero in every sighting; read here as a u32 and a byte (the split is inferred), the values are ignored and
/// nothing is answered. The PoE1-era codec did not know this id: the stream desynced on it and the create
/// (0x12) and Play (0x0e) that followed were silently dropped.</summary>
public sealed record CharacterSelected(uint Value, byte B) : ILoginMessage
{
    public const ushort Id = 0x10;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.U32(Value).U8(B);
    internal static CharacterSelected Read(ushort id, ref LoginReader r) => new(r.U32(), r.U8());
}

/// <summary>C→S 0x12 (vtable 0x1435d8b10, 0x14213cb50/0x14213cc30, sender 0x142140490, called by the create screen's
/// 0x140cf5ef0): create a character. Name is the name box, League the chosen <see cref="LeagueEntry.Name"/>. The
/// u32s were 0 and S78 the chosen CharacterStartStates.dat Id ("DexDefault" for a Ranger, live 2026-10-18).
/// PasswordDigest is SHA-256 of the UTF-16LE league password (private leagues), or zeros.
/// Client 0.5.5 carries a THIRD u32 before S78 (live captures 2026-11-04, byte-exact both times: 79 bytes for
/// jddij/Allflame/"IntFourDefault", 83 for localtest/Standard with the same start state). Without it the old
/// reader landed on the third u32's zero high half, read S78 as "" — the class fell back to 0 — and left the
/// string and digest tail unread, desyncing the stream so the client's Play (0x0e) was silently dropped.</summary>
public sealed record CreateCharacter(string Name, string League, uint U50, uint U54, uint U58, string S78, byte[] PasswordDigest) : ILoginMessage
{
    public const ushort Id = 0x12;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.WStr(Name).WStr(League).U32(U50).U32(U54).U32(U58).WStr(S78).Fixed(PasswordDigest, 32);
    internal static CreateCharacter Read(ushort id, ref LoginReader r) => new(r.WStr(), r.WStr(), r.U32(), r.U32(), r.U32(), r.WStr(), r.Fixed(32));
}

/// <summary>C→S 0x1c (sender 0x142140a80): two u16; the second defaults to the client's count at +0xe58.</summary>
public sealed record TwoU16(ushort A, ushort B) : ILoginMessage
{
    public const ushort Id = 0x1c;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.U16(A).U16(B);
    internal static TwoU16 Read(ushort id, ref LoginReader r) => new(r.U16(), r.U16());
}

/// <summary>C→S 0x22 (vtable 0x1435d8ac8, 0x14213ce00, sender 0x142140b40): 5 raw bytes decoded from a 10-hex-digit string.</summary>
public sealed record HexCode(byte[] Code) : ILoginMessage
{
    public const ushort Id = 0x22;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.Fixed(Code, 5);
    internal static HexCode Read(ushort id, ref LoginReader r) => new(r.Fixed(5));
}

/// <summary>C→S 0x2c (vtable 0x1435d8a80, 0x14213c4e0/0x14213c5a0, sender 0x140d01a60): Epic (EOS) login: wide string, realm, token blob.</summary>
public sealed record EpicLogin(string Name, byte Realm, byte[] Token) : ILoginMessage
{
    public const ushort Id = 0x2c;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.WStr(Name).U8(Realm).Blob(Token);
    internal static EpicLogin Read(ushort id, ref LoginReader r) => new(r.WStr(), r.U8(), r.Blob());
}

/// <summary>C→S 0x3d (vtable 0x1435d8b68, 0x14213cee0/0x14213cf70, sender 0x142140890): two wide strings + bool.</summary>
public sealed record TwoWStringsBool(string A, string B, bool Flag) : ILoginMessage
{
    public const ushort Id = 0x3d;
    public ushort MessageId => Id;
    public void WriteFields(LoginWriter w) => w.WStr(A).WStr(B).Bool(Flag);
    internal static TwoWStringsBool Read(ushort id, ref LoginReader r) => new(r.WStr(), r.WStr(), r.Bool());
}

public enum LoginDirection { ServerToClient, ClientToServer }

/// <summary>Id → layout tables for both directions and a framing-free stream decoder.</summary>
public static class LoginCodec
{
    private delegate ILoginMessage Reader(ushort id, ref LoginReader r);

    private static ILoginMessage ReadKeyExchange(ushort id, ref LoginReader r) => new KeyExchange(r.Blob(), r.Blob());
    private static ILoginMessage ReadEmpty(ushort id, ref LoginReader r) => new EmptyMessage(id);

    // Mirrors the client's factory 0x14219c350.
    private static readonly Dictionary<ushort, Reader> ServerToClient = new()
    {
        [0x01] = ReadEmpty, [0x02] = ReadKeyExchange, [0x04] = LoginResult.Read,
        [0x0b] = U16Message.Read, [0x0d] = U16Message.Read, [0x0f] = U16Message.Read,
        [0x11] = Blob11.Read, [0x13] = CreateCharacterResult.Read, [0x14] = InstanceInfo.Read, [0x15] = List15.Read,
        [0x17] = U16Message.Read, [0x1a] = LeaguesWithProgress.Read, [0x1b] = LeagueList.Read, [0x1e] = U16Message.Read,
        [0x1f] = U32Message.Read, [0x20] = U32Message.Read,
        [0x24] = WStringMessage.Read, [0x25] = WStringMessage.Read, [0x26] = WStringMessage.Read,
        [0x28] = WStringMessage.Read, [0x29] = WStringMessage.Read,
        [0x3c] = TwoU32.Read, [0x3e] = U16Bool.Read, [0x41] = StringMessage.Read, [0x43] = U8WString.Read,
        [0x44] = U16Message.Read, [0x47] = StringList47.Read,
    };

    // Collected from the client's senders (writes to the login socket at +0xdd0). 0x01 (no fields) was seen live after
    // 0x18 on the character screen (2026-10-16), probably a keepalive; it shares class 0x14316c930 with S→C 0x01.
    private static readonly Dictionary<ushort, Reader> ClientToServer = new()
    {
        [0x01] = ReadEmpty, [0x02] = ReadKeyExchange, [0x03] = AccountLogin.Read, [0x05] = TokenLogin.Read,
        [0x06] = TicketLogin.Read, [0x07] = TicketLogin.Read, [0x08] = U32Raw64.Read, [0x0a] = TwoDigests.Read,
        [0x0c] = DeleteCharacter.Read, [0x0e] = PlayRequest.Read, [0x10] = CharacterSelected.Read, [0x12] = CreateCharacter.Read,
        [0x18] = CharacterListRequest.Read, [0x19] = ReadEmpty, [0x1c] = TwoU16.Read, [0x21] = ReadEmpty, [0x22] = HexCode.Read,
        [0x23] = ReadEmpty, [0x2a] = WStringU8Message.Read, [0x2b] = WStringU8Message.Read, [0x2c] = EpicLogin.Read,
        [0x39] = ReadEmpty, [0x3a] = U8Message.Read, [0x3d] = TwoWStringsBool.Read,
        [0x3f] = WStringMessage.Read, [0x40] = WStringMessage.Read, [0x42] = U8Message.Read, [0x46] = U32Message.Read,
    };

    public static bool IsKnown(LoginDirection dir, ushort id) => Table(dir).ContainsKey(id);

    /// <summary>
    /// Decodes one message from the start of <paramref name="buf"/>. Returns false if more bytes are needed. An unknown
    /// id throws: without a length prefix the rest of the stream cannot be resynchronized.
    /// </summary>
    public static bool TryDecode(LoginDirection dir, ReadOnlySpan<byte> buf, out ILoginMessage? message, out int consumed)
    {
        message = null; consumed = 0;
        var r = new LoginReader(buf);
        ushort id = r.U16();
        if (r.Short) return false;
        if (!Table(dir).TryGetValue(id, out var read))
            throw new InvalidDataException($"unknown {dir} login message 0x{id:x4}");
        var m = read(id, ref r);
        if (r.Short) return false;
        message = m; consumed = r.Position;
        return true;
    }

    private static Dictionary<ushort, Reader> Table(LoginDirection dir) => dir == LoginDirection.ServerToClient ? ServerToClient : ClientToServer;
}
