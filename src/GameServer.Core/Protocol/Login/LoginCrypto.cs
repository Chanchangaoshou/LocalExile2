using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace GameServer.Core.Protocol.Login;

/// <summary>A prime-order subgroup: p = 2q + 1, generator g of order q. Elements encode big-endian, |p| bytes wide.</summary>
public sealed record DhGroup(BigInteger P, BigInteger Q, BigInteger G)
{
    public int ElementLength => (int)((P.GetBitLength() + 7) / 8);

    public BigInteger RandomExponent() => Big.RandomBelow(Q - 1) + 1;

    public BigInteger PublicFor(BigInteger priv) => BigInteger.ModPow(G, priv, P);

    /// <summary>The check Crypto++ does at validation level 3 before agreeing: 1 &lt; y &lt; p-1 and y^q = 1.</summary>
    public bool IsValidElement(BigInteger y) => y > 1 && y < P - 1 && BigInteger.ModPow(y, Q, P).IsOne;

    public byte[] Agree(BigInteger priv, BigInteger otherPublic)
    {
        if (!IsValidElement(otherPublic)) throw new CryptographicException("invalid DH public value");
        return Big.ToFixed(BigInteger.ModPow(otherPublic, priv, P), ElementLength);
    }
}

/// <summary>DSA key (FIPS 186 style). The client verifies the server's ephemeral key with DSA/SHA-1, P1363 r||s signature.</summary>
public sealed record DsaKey(BigInteger P, BigInteger Q, BigInteger G, BigInteger Y, BigInteger? X = null)
{
    public int SignatureHalfLength => (int)((Q.GetBitLength() + 7) / 8);

    public byte[] Sign(ReadOnlySpan<byte> message)
    {
        if (X is not { } x) throw new InvalidOperationException("no private key");
        BigInteger e = Representative(message);
        while (true)
        {
            BigInteger k = Big.RandomBelow(Q - 1) + 1;
            BigInteger r = BigInteger.ModPow(G, k, P) % Q;
            if (r.IsZero) continue;
            BigInteger s = Big.ModInverse(k, Q) * (e + x * r) % Q;
            if (s.IsZero) continue;
            int n = SignatureHalfLength;
            return [.. Big.ToFixed(r, n), .. Big.ToFixed(s, n)];
        }
    }

    public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        int n = SignatureHalfLength;
        if (signature.Length != 2 * n) return false;
        BigInteger r = Big.FromBigEndian(signature[..n]), s = Big.FromBigEndian(signature[n..]);
        if (r.Sign <= 0 || r >= Q || s.Sign <= 0 || s >= Q) return false;
        BigInteger w = Big.ModInverse(s, Q);
        BigInteger u1 = Representative(message) * w % Q, u2 = r * w % Q;
        BigInteger v = BigInteger.ModPow(G, u1, P) * BigInteger.ModPow(Y, u2, P) % P % Q;
        return v == r;
    }

    // SHA-1 is 160 bits, shorter than q, so the digest is used whole (no truncation).
    private BigInteger Representative(ReadOnlySpan<byte> message)
    {
        byte[] h = SHA1.HashData(message);
        BigInteger e = Big.FromBigEndian(h);
        int excess = h.Length * 8 - (int)Q.GetBitLength();
        return excess > 0 ? e >> excess : e;
    }
}

/// <summary>The two Salsa20 streams of one connection, keyed from the 64-byte SHA-512 of the agreed value.</summary>
public sealed class ConnectionCiphers
{
    public Salsa20 Send { get; }
    public Salsa20 Receive { get; }

    /// <param name="isClient">Client sends with IV km[32..40] and receives with km[48..56]; the server is the mirror image
    /// (client 0x140e03a30: cipher A at iv = km + ((flag^1)+2)*16 is used for send, cipher B at km + (flag+2)*16 for recv).</param>
    public ConnectionCiphers(ReadOnlySpan<byte> keyMaterial, bool isClient)
    {
        if (keyMaterial.Length != 64) throw new ArgumentException("key material must be 64 bytes", nameof(keyMaterial));
        ReadOnlySpan<byte> key = keyMaterial[..32], ivC2S = keyMaterial[32..40], ivS2C = keyMaterial[48..56];
        Send = new Salsa20(key, isClient ? ivC2S : ivS2C);
        Receive = new Salsa20(key, isClient ? ivS2C : ivC2S);
    }

    /// <summary>The first 16 bytes of both directions' keystreams for a key material (diagnostics): a client
    /// deserialisation failure exposes its first keystream bytes through the bogus packet id, which identifies
    /// which material the client actually keyed its connection from.</summary>
    public static (string Send, string Receive) Probe(ReadOnlySpan<byte> keyMaterial, bool isClient = false)
    {
        var ciphers = new ConnectionCiphers(keyMaterial, isClient);
        var send = new byte[16]; ciphers.Send.Process(send);
        var receive = new byte[16]; ciphers.Receive.Process(receive);
        return (Convert.ToHexString(send), Convert.ToHexString(receive));
    }
}

/// <summary>Key-material diagnostics for the instance connection: the keystream prefixes of every
/// plausible material the client might key it from, plus candidate opening digests. A deserialisation
/// failure exposes the client's first keystream bytes through the bogus packet id, and the opening
/// carries its digest; comparing both against these lines names the material and the formula.</summary>
public static class KmProbe
{
    public static void Log(string tag, uint ticket, byte[] ticketKey, byte[]? loginKm, Action<string> log)
    {
        Span<byte> tb = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(tb, ticket);
        log($"{tag} raw materials: k={Convert.ToHexString(ticketKey)} l={(loginKm is { Length: 64 } ? Convert.ToHexString(loginKm) : "-")}");
        var mats = new List<(string Name, byte[] Km)> { ("ticket", ticketKey) };
        if (loginKm is { Length: 64 })
        {
            mats.Add(("login", loginKm));
            mats.Add(("s512(k|l)", SHA512.HashData([.. ticketKey, .. loginKm])));
            mats.Add(("s512(l|k)", SHA512.HashData([.. loginKm, .. ticketKey])));
            mats.Add(("s512(l|t)", SHA512.HashData([.. loginKm, .. tb])));
            mats.Add(("hmac(k,l)", HMACSHA512.HashData(ticketKey, loginKm)));
            mats.Add(("hmac(l,k)", HMACSHA512.HashData(loginKm, ticketKey)));
        }
        mats.Add(("s512(k|t)", SHA512.HashData([.. ticketKey, .. tb])));
        foreach (var (name, km) in mats)
        {
            var p = ConnectionCiphers.Probe(km);
            log($"{tag} km probe [{name}]: send {p.Send} recv {p.Receive}");
        }
        string D(byte[] b) => Convert.ToHexString(b[..12]);
        log($"{tag} digest candidates: hmac(k,t) {D(HMACSHA512.HashData(ticketKey, tb))} s512(k|t) {D(SHA512.HashData([.. ticketKey, .. tb]))} s512(t|k) {D(SHA512.HashData([.. tb, .. ticketKey]))}");
        if (loginKm is { Length: 64 })
            log($"{tag} digest candidates: hmac(l,t) {D(HMACSHA512.HashData(loginKm, tb))} s512(l|t) {D(SHA512.HashData([.. loginKm, .. tb]))} s512(t|l) {D(SHA512.HashData([.. tb, .. loginKm]))}");
    }
}

public static class LoginKdf
{
    /// <summary>km = SHA-512(Z_static || Z_ephemeral), the Crypto++ DH2 agreed value (client 0x140e03460).</summary>
    public static byte[] KeyMaterial(ReadOnlySpan<byte> staticAgreed, ReadOnlySpan<byte> ephemeralAgreed) =>
        SHA512.HashData([.. staticAgreed, .. ephemeralAgreed]);
}

internal static class Big
{
    public static BigInteger FromBigEndian(ReadOnlySpan<byte> b) => new(b, isUnsigned: true, isBigEndian: true);

    public static byte[] ToFixed(BigInteger v, int length)
    {
        byte[] raw = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length > length) throw new ArgumentException("value too large for width");
        byte[] r = new byte[length];
        raw.CopyTo(r, length - raw.Length);
        return r;
    }

    public static BigInteger RandomBelow(BigInteger bound)
    {
        int bytes = (int)((bound.GetBitLength() + 7) / 8) + 8; // extra bytes make the modulo bias negligible
        return FromBigEndian(RandomNumberGenerator.GetBytes(bytes)) % bound;
    }

    public static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger g = m, x = 0, x1 = 1, a1 = ((a % m) + m) % m;
        while (!a1.IsZero)
        {
            BigInteger q = g / a1;
            (g, a1) = (a1, g - q * a1);
            (x, x1) = (x1, x - q * x1);
        }
        if (!g.IsOne) throw new ArithmeticException("not invertible");
        return ((x % m) + m) % m;
    }
}
