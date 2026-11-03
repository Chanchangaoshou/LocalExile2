using GameServer.Core.Protocol.Login;

namespace GameServer.Core.Tests;

public class LoginMessageTests
{
    private static byte[] B(int n, byte seed) => Enumerable.Range(0, n).Select(i => (byte)(seed + i)).ToArray();

    private static readonly LeagueEntry Character = new("Exile", "Standard", "Wide ünïcode", "", "😀 astral", 0x0102030405060708,
        0x1122334455667788, 42, 1, 2, 3, 0x14, 0x5a, 0xd1);

    public static readonly (LoginDirection Dir, ILoginMessage Msg)[] Samples =
    [
        (LoginDirection.ServerToClient, new EmptyMessage(0x01)),
        (LoginDirection.ServerToClient, new KeyExchange(B(128, 1), B(56, 9))),
        (LoginDirection.ServerToClient, new LoginResult(0x01020304, 0x0506, "account", B(32, 3), 0x21, 0x01, B(5, 7))),
        (LoginDirection.ServerToClient, new U16Message(0x0b, 0x1234)),
        (LoginDirection.ServerToClient, new U16Message(0x0d, 1)),
        (LoginDirection.ServerToClient, new U16Message(0x0f, 2)),
        (LoginDirection.ServerToClient, new Blob11(3, B(40, 0))),
        (LoginDirection.ServerToClient, new CreateCharacterResult(0xbeef, true, 0x01020304)),
        (LoginDirection.ServerToClient, new InstanceInfo("127.0.0.1", 6112, 0xdeadbeef, 0x4321, 7, B(64, 0x40), B(8, 0x80), 1)),
        (LoginDirection.ServerToClient, new List15(0x01020304, [new("Standard", "desc", 1, 2, 3, 0x01020304, 5, 0x0607, 0x0809, 10, 11, 12, 13),
            new("Hardcore", "", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)], 4, 5, 0x1415, 0x1617, "text", [new(0x1819, -3), new(0x1a1b, 70000)], 0x1c1d1e1f, 0x20212223)),
        (LoginDirection.ServerToClient, new U16Message(0x17, 9)),
        (LoginDirection.ServerToClient, new LeaguesWithProgress(3, [Character])),
        (LoginDirection.ServerToClient, new LeagueList(1_760_000_000, [Character, Character with { Name = "Two" }], true, false)),
        (LoginDirection.ServerToClient, new U16Message(0x1e, 4)),
        (LoginDirection.ServerToClient, new U32Message(0x1f, 0x01020304)),
        (LoginDirection.ServerToClient, new U32Message(0x20, 5)),
        (LoginDirection.ServerToClient, new WStringMessage(0x24, "hello")),
        (LoginDirection.ServerToClient, new WStringMessage(0x25, "")),
        (LoginDirection.ServerToClient, new WStringMessage(0x26, "Ω")),
        (LoginDirection.ServerToClient, new WStringMessage(0x28, "x")),
        (LoginDirection.ServerToClient, new WStringMessage(0x29, "y")),
        (LoginDirection.ServerToClient, new TwoU32(1, 2)),
        (LoginDirection.ServerToClient, new U16Bool(7, false)),
        (LoginDirection.ServerToClient, new StringMessage("utf-8 ✓")),
        (LoginDirection.ServerToClient, new U8WString(1, "message")),
        (LoginDirection.ServerToClient, new U16Message(0x44, 8)),
        (LoginDirection.ServerToClient, new StringList47(1, 2, ["a", "", "ccc"])),

        (LoginDirection.ClientToServer, new EmptyMessage(0x01)),
        (LoginDirection.ClientToServer, new KeyExchange(B(128, 2), [])),
        (LoginDirection.ClientToServer, new AccountLogin(2, "user@example.com", B(32, 1), B(32, 2), B(32, 3), true, true, 0x40, 0)),
        (LoginDirection.ClientToServer, new TokenLogin(0x40, B(32, 1), B(32, 2), 0, B(20, 9))),
        (LoginDirection.ClientToServer, new TicketLogin(0x06, "ticket", 0x40, B(32, 1), B(32, 2), 1)),
        (LoginDirection.ClientToServer, new TicketLogin(0x07, "steam", 0x46, B(32, 1), B(32, 2), 0)),
        (LoginDirection.ClientToServer, new U32Raw64(3, 0xfedcba9876543210)),
        (LoginDirection.ClientToServer, new TwoDigests(B(32, 5), B(32, 6))),
        (LoginDirection.ClientToServer, new WStringU8Message(0x0c, "name", 1)),
        (LoginDirection.ClientToServer, new PlayRequest(6, 1, new byte[8])),
        (LoginDirection.ClientToServer, new CharacterSelected(7, 1)),
        (LoginDirection.ClientToServer, new CreateCharacter("a", "b", 1, 2, 3, "c", B(32, 0))),
        (LoginDirection.ClientToServer, new CharacterListRequest(0x01020304)),
        (LoginDirection.ClientToServer, new EmptyMessage(0x19)),
        (LoginDirection.ClientToServer, new TwoU16(1, 2)),
        (LoginDirection.ClientToServer, new EmptyMessage(0x21)),
        (LoginDirection.ClientToServer, new HexCode(B(5, 0xa0))),
        (LoginDirection.ClientToServer, new EmptyMessage(0x23)),
        (LoginDirection.ClientToServer, new WStringU8Message(0x2a, "x", 0x40)),
        (LoginDirection.ClientToServer, new WStringU8Message(0x2b, "y", 0x40)),
        (LoginDirection.ClientToServer, new EpicLogin("epic", 0x40, B(100, 0))),
        (LoginDirection.ClientToServer, new EmptyMessage(0x39)),
        (LoginDirection.ClientToServer, new U8Message(0x3a, 0)),
        (LoginDirection.ClientToServer, new TwoWStringsBool("a", "b", true)),
        (LoginDirection.ClientToServer, new WStringMessage(0x3f, "q")),
        (LoginDirection.ClientToServer, new WStringMessage(0x40, "r")),
        (LoginDirection.ClientToServer, new U8Message(0x42, 1)),
        (LoginDirection.ClientToServer, new U32Message(0x46, 0)),
    ];

    public static TheoryData<int> SampleIndexes() => [.. Enumerable.Range(0, Samples.Length)];

    [Theory]
    [MemberData(nameof(SampleIndexes))]
    public void Every_message_round_trips_and_needs_all_its_bytes(int index)
    {
        var (dir, msg) = Samples[index];
        byte[] wire = LoginMessage.Encode(msg);

        Assert.True(LoginCodec.TryDecode(dir, wire, out var decoded, out int consumed));
        Assert.Equal(wire.Length, consumed);
        Assert.Equal(msg.MessageId, decoded!.MessageId);
        Assert.Equal(msg.GetType(), decoded.GetType());
        Assert.Equal(wire, LoginMessage.Encode(decoded));

        for (int n = 0; n < wire.Length; n++)
            Assert.False(LoginCodec.TryDecode(dir, wire.AsSpan(0, n), out _, out _), $"decoded from {n} of {wire.Length} bytes");
    }

    [Fact]
    public void Samples_cover_every_known_id()
    {
        foreach (var dir in Enum.GetValues<LoginDirection>())
        {
            var known = Enumerable.Range(0, 0x10000).Where(i => LoginCodec.IsKnown(dir, (ushort)i)).Select(i => (ushort)i);
            var sampled = Samples.Where(s => s.Dir == dir).Select(s => s.Msg.MessageId).Distinct();
            Assert.Equal(known.Order(), sampled.Order());
        }
    }

    [Fact]
    public void Messages_decode_back_to_back_without_framing()
    {
        byte[] stream = [.. LoginMessage.Encode(new U16Message(0x17, 3)), .. LoginMessage.Encode(new StringMessage("x")), 0x00];
        Assert.True(LoginCodec.TryDecode(LoginDirection.ServerToClient, stream, out var a, out int n1));
        Assert.True(LoginCodec.TryDecode(LoginDirection.ServerToClient, stream.AsSpan(n1), out var b, out int n2));
        Assert.Equal(new U16Message(0x17, 3), a);
        Assert.Equal(new StringMessage("x"), b);
        Assert.False(LoginCodec.TryDecode(LoginDirection.ServerToClient, stream.AsSpan(n1 + n2), out _, out _));
    }

    [Fact]
    public void Unknown_id_throws()
    {
        Assert.Throws<InvalidDataException>(() => LoginCodec.TryDecode(LoginDirection.ServerToClient, [0x00, 0x03], out _, out _));
        Assert.Throws<InvalidDataException>(() => LoginCodec.TryDecode(LoginDirection.ClientToServer, [0x00, 0x04], out _, out _));
    }

    [Fact]
    public void Wide_strings_use_the_compact_code_point_encoding()
    {
        // "aé😀": 3 code points; 'a' as one byte, 'é' as 0x80 + LE unit, U+1F600 as 0xC0 + LE u32.
        byte[] wire = LoginMessage.Encode(new WStringMessage(0x24, "aé😀"));
        Assert.Equal("0024" + "0003" + "61" + "80E900" + "C000F60100", Convert.ToHexString(wire));
    }

    [Fact]
    public void Wide_string_reader_rejects_bad_markers_and_pairs_split_surrogates()
    {
        Assert.Throws<InvalidDataException>(() => LoginCodec.TryDecode(LoginDirection.ServerToClient, [0x00, 0x24, 0x00, 0x01, 0x81], out _, out _));
        Assert.Throws<InvalidDataException>(() => LoginCodec.TryDecode(LoginDirection.ServerToClient, [0x00, 0x24, 0x00, 0x01, 0x80, 0x00, 0xD8], out _, out _));

        // U+1F600 sent as two 0xC0 elements (high, low surrogate) counts as two elements.
        byte[] split = [0x00, 0x24, 0x00, 0x02, 0xC0, 0x3D, 0xD8, 0x00, 0x00, 0xC0, 0x00, 0xDE, 0x00, 0x00];
        Assert.True(LoginCodec.TryDecode(LoginDirection.ServerToClient, split, out var m, out int n));
        Assert.Equal("😀", ((WStringMessage)m!).Text);
        Assert.Equal(split.Length, n);
    }

    [Fact]
    public void Account_login_layout_matches_client_serializer()
    {
        var m = new AccountLogin(2, "ab", B(32, 0x10), B(32, 0x30), B(32, 0x50), true, false, 0x40, 7);
        byte[] w = LoginMessage.Encode(m);
        Assert.Equal("0003" + "00000002" + "0002" + "6162", Convert.ToHexString(w, 0, 10));
        Assert.Equal(0x10, w[10]);          // MachineIdA (+0x54) comes before the password digest (+0x34)
        Assert.Equal(0x30, w[42]);
        Assert.Equal(0x50, w[74]);
        Assert.Equal("01004007", Convert.ToHexString(w, 106, 4));
        Assert.Equal(110, w.Length);
    }

    [Fact]
    public void Login_result_layout_matches_055_client()
    {
        // 0.5.5 client 0x04 read 0x14214dbe0: big-endian u32 + u16, wide string, 32-byte digest, two raw
        // flag bytes, blob. (The PoE1-era lone-u16-first layout makes its wstring reader land in the digest.)
        var m = LoginResult.Of(6, B(32, 0xA0), 0x20, 0x00, []);
        Assert.Equal("0004" + "00000006" + "0006" + "0000" + Convert.ToHexString(B(32, 0xA0)) + "2000" + "0000",
            Convert.ToHexString(LoginMessage.Encode(m)));
    }

    [Fact]
    public void Create_character_layout_matches_055_live_capture()
    {
        // Live 0.5.5 wire, 2026-11-04 06:50: name, league, THREE u32 (the PoE1-era reader had two and
        // desynced on the third), the start-state wstring, then the 32-byte digest; 79 bytes in all.
        byte[] wire = Convert.FromHexString("0012" + "0005" + "6A6464696A" + "0008" + "416C6C666C616D65"
            + "00000000" + "00000000" + "00000000" + "000E" + "496E74466F757244656661756C74"
            + "0000000000000000000000000000000000000000000000000000000000000000");
        Assert.True(LoginCodec.TryDecode(LoginDirection.ClientToServer, wire, out var decoded, out int consumed));
        Assert.Equal(wire.Length, consumed);
        var m = Assert.IsType<CreateCharacter>(decoded);
        Assert.Equal("jddij", m.Name);
        Assert.Equal("Allflame", m.League);
        Assert.Equal("IntFourDefault", m.S78);
    }

    [Fact]
    public void Character_list_layout_matches_055_client()
    {
        // 0.5.5 client 0x15 read 0x14214e210: u32, u8 count + entries, two bytes, two big-endian u16,
        // a narrow string, a varint-count pair vector (u16 + signed varint), two u32.
        var m = new List15(0x01020304, [], 5, 24, 0x0607, 0x0809, "ab", [new ListPair15(0x0a0b, -3)], 0x0c0d0e0f, 0x10111213);
        Assert.Equal("0015" + "01020304" + "00" + "05" + "18" + "0607" + "0809" + "0002" + "6162"
            + "01" + "0A0B" + "7D" + "0C0D0E0F" + "10111213", Convert.ToHexString(LoginMessage.Encode(m)));
    }

    [Fact]
    public void Character_list_time_and_raw_fields_are_little_endian()
    {
        var m = new LeagueList(0x0102030405060708, [], false, true);
        Assert.Equal("001B" + "0807060504030201" + "00000000" + "02", Convert.ToHexString(LoginMessage.Encode(m)));
    }
}

public class LoginMessageStreamTests
{
    private static ILoginMessage[] Sequence() =>
    [
        new AccountLogin(2, "user", new byte[32], new byte[32], new byte[32], true, true, 0x40, 0),
        new WStringMessage(0x3f, "hé😀"),
        new CharacterListRequest(3),
        new TwoU16(1, 2),
    ];

    [Fact]
    public void Decodes_messages_fed_one_byte_at_a_time()
    {
        byte[] wire = [.. Sequence().SelectMany(LoginMessage.Encode)];
        var s = new LoginMessageStream(LoginDirection.ClientToServer);
        var got = new List<ILoginMessage>();
        foreach (byte b in wire) got.AddRange(s.Push([b]));
        Assert.Equal(wire, got.SelectMany(LoginMessage.Encode).ToArray());
        Assert.Empty(s.Undecoded);
        Assert.False(s.Desynced);
    }

    [Fact]
    public void Unknown_id_desyncs_and_keeps_the_rest()
    {
        var s = new LoginMessageStream(LoginDirection.ClientToServer);
        var got = s.Push([.. LoginMessage.Encode(new EmptyMessage(0x19)), 0x00, 0x04, 0xaa]);
        Assert.Single(got);
        Assert.True(s.Desynced);
        Assert.Contains("0x0004", s.Error);
        Assert.Equal([0x00, 0x04, 0xaa], s.Undecoded);
        Assert.Empty(s.Push([0x00, 0x19]));
        Assert.Equal(5, s.Undecoded.Count);
    }

    [Fact]
    public void Encrypted_session_decodes_after_handshake()
    {
        using var dsa = System.Security.Cryptography.DSA.Create(1024);
        var prm = dsa.ExportParameters(true);
        static System.Numerics.BigInteger B(byte[] b) => new(b, isUnsigned: true, isBigEndian: true);
        var signing = new DsaKey(B(prm.P!), B(prm.Q!), B(prm.G!), B(prm.Y!), B(prm.X!));
        var clientPriv = LoginGroups.Static.RandomExponent();
        var keys = new LoginServerKeys(signing, LoginGroups.Static.RandomExponent(), LoginGroups.Static.PublicFor(clientPriv));
        var client = new ClientHandshake(clientPriv, keys.ServerStaticPublic, signing with { X = null });
        KeyExchange.TryDecode(client.Hello(), out var hello, out _);
        var (reply, server) = new ServerHandshake(keys).Respond(hello!);
        KeyExchange.TryDecode(reply, out var r, out _);
        var cc = client.Complete(r!);

        byte[] wire = [.. Sequence().SelectMany(LoginMessage.Encode)];
        cc.Send.Process(wire);
        var s = new LoginMessageStream(LoginDirection.ClientToServer);
        var got = new List<ILoginMessage>();
        for (int i = 0; i < wire.Length; i += 7)
        {
            byte[] chunk = wire[i..Math.Min(wire.Length, i + 7)];
            server.Receive.Process(chunk);
            got.AddRange(s.Push(chunk));
        }
        Assert.Equal(4, got.Count);
        Assert.Equal("user", ((AccountLogin)got[0]).Account);
        Assert.Equal("hé😀", ((WStringMessage)got[1]).Text);
    }

    [Fact]
    public void Describe_shows_fields_and_hex()
    {
        Assert.Equal("0x22 HexCode { Code = 0102030405 }", LoginMessageFormat.Describe(new HexCode([1, 2, 3, 4, 5])));
        Assert.Equal("0x47 StringList47 { A = 0x1, B = 0x2, Items = [\"a\", \"b\"] }",
            LoginMessageFormat.Describe(new StringList47(1, 2, ["a", "b"])));
    }
}
