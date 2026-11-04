using System.Numerics;
using GameServer.Core.Protocol.Login;

namespace GameServer.Core.Protocol.Instance;

/// <summary>
/// "HNC", the instance connection's hidden side channel (stream +0xd0). Some message fields are carriers: their bits
/// are fed, LSB first, into a byte accumulator, and every completed byte is decrypted with a second Salsa20 pair and
/// run through a small state machine (0x14299de50): idle while bytes decrypt to 0; otherwise a type byte (0xDA–0xDD),
/// a length byte (not 0) and that many payload bytes form a packet. Any other byte throws "HNC Protocol Violated".
/// The pair is keyed like the main stream, from km' = the 0x14 key XOR a 64-byte table in the client (0x142fe0da0) with
/// six byte swaps (0x14299db60), built when 0x11 arrives.
/// </summary>
public sealed class HncSender
{
    /// <summary>VAs of the 64-byte mask in the clients this server serves, with the SHA-256 of its contents (the mask
    /// itself is read from the local client, not shipped). The mask bytes are identical in both clients — the shared
    /// hash proves it — only the address moved: the 3.29.3b client keeps it at 0x142fe0da0; the PoE2 0.5.5 client at
    /// 0x142f10980, where its pair builder (0x1421c52f0) XORs the 64 key bytes against the table and then applies
    /// exactly the six swaps <see cref="DeriveKey"/> performs (disassembly-verified 2026-11-04).</summary>
    private static readonly long[] MaskVas = [0x142fe0da0, 0x142f10980];
    private const string MaskSha256 = "0e88f29acc9cab88ee400ca78bbfeeeaebc333afb11f1ea9be3fd37aeb7cbc31";

    private static byte[]? _mask;

    private static byte[] Mask => _mask ?? throw new InvalidOperationException(
        "HNC mask not loaded: call HncSender.LoadMask with the client executable (Client/Game.exe).");

    /// <summary>Reads the mask from the client executable (PE file): each known address is tried in turn and the
    /// SHA-256 check decides — a wrong address simply reads unrelated bytes and fails the hash.</summary>
    public static void LoadMask(byte[] clientExe)
    {
        foreach (long va in MaskVas)
        {
            byte[] mask;
            try { mask = PeImage.ReadAtVa(clientExe, va, 64); }
            catch (InvalidDataException) { continue; }
            if (Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(mask)).ToLowerInvariant() == MaskSha256)
            {
                _mask = mask;
                return;
            }
        }
        throw new InvalidDataException("HNC mask not found: the client is not a supported build.");
    }

    /// <summary>Tests only: any 64 bytes (both sides derive with the same mask).</summary>
    public static void UseMaskForTests(byte[] mask) => _mask = mask.Length == 64 ? mask : throw new ArgumentException("64 bytes");

    private readonly Salsa20 _send;

    /// <param name="instanceKey">The 64 key bytes sent in login 0x14.</param>
    public HncSender(ReadOnlySpan<byte> instanceKey) => _send = Pair(instanceKey, isClient: false).Send;

    public static byte[] DeriveKey(ReadOnlySpan<byte> instanceKey)
    {
        if (instanceKey.Length != 64) throw new ArgumentException("instance key must be 64 bytes", nameof(instanceKey));
        byte[] k = new byte[64];
        for (int i = 0; i < 64; i++) k[i] = (byte)(instanceKey[i] ^ Mask[i]);
        foreach (var (a, b) in new[] { (0, 0x15), (4, 2), (0xd, 0x2a), (0x30, 1), (0x1d, 0x1e), (0x32, 0x13) })
            (k[a], k[b]) = (k[b], k[a]);
        return k;
    }

    /// <summary>The HNC Salsa20 pair for one side (the client builds it with isClient = 1).</summary>
    public static ConnectionCiphers Pair(ReadOnlySpan<byte> instanceKey, bool isClient) => new(DeriveKey(instanceKey), isClient);

    /// <summary>
    /// The u32 for a 0x1d pong carrying four idle (zero) HNC bytes. The 0.5.5 reader (0x141f48de0) feeds bits 9..31 and then
    /// bits 0..8 into the accumulator, so the byte stream r (little-endian) is rotr(v, 9) and v = rotl(r, 9).
    /// </summary>
    public uint NextIdleU32()
    {
        Span<byte> b = stackalloc byte[4];
        b.Clear();
        _send.Process(b);
        return BitOperations.RotateLeft(System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(b), 9);
    }

    /// <summary>The HNC bytes the client would see for carrier u32 <paramref name="v"/> of a 0x1d pong (before decryption).</summary>
    public static byte[] CarrierBytes(uint v)
    {
        byte[] r = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(r, BitOperations.RotateRight(v, 9));
        return r;
    }
}
