using System.Collections.Generic;

namespace NetSec.Bench;

/// <summary>
/// The per-block case list, built on one copy of the code (<see cref="IBlockCases"/>), so the same list times the product and the
/// frozen 5c5d4a4 copy in one run. The inputs follow the AO-5 op definitions of the suite (acceptance/groups/algo/AoAlloc.Product.cs):
/// a 1024-byte message (64 AES blocks), zero IV, counter and nonce, GCM with no AAD, HMAC-SHA256 with a 32-byte key on 1024 bytes, and the
/// DUKPT counter 0x0F0F. Each case keeps its last output in <see cref="Sink"/>, so the JIT cannot drop the work.
/// <see cref="AoId"/> names the AO-6 row a case feeds; <see cref="AoAlloc"/> owns the AO-5 rows.
/// </summary>
static class Cases
{
    public const int MessageBytes = 1024;
    public const int UpdateBlocks = 64;
    const int AesBlock = 16, DesBlock = 8, AesBlocks = MessageBytes / AesBlock;

    public static object Sink;

    public static readonly string[] HashNames = { "md5", "sha1", "sha256", "sha512", "sha3-256" };

    public static List<BenchCase> All(IBlockCases code)
    {
        byte[] key16 = Filled(16, 0x10), key24 = Filled(24, 0x20), key32 = Filled(32, 0x30);
        byte[] message = Filled(MessageBytes, 0x40);
        byte[] zero16 = new byte[16], nonce = new byte[12], noAad = new byte[0];
        byte[] block = Filled(16, 0x80), output = new byte[16];

        List<BenchCase> all = new List<BenchCase>
        {
            new BenchCase("aes128.encrypt-block", "block", 1, AesBlock, code.AesEncryptBlock(key16, block, output)),
            new BenchCase("aes128.decrypt-block", "block", 1, AesBlock, code.AesDecryptBlock(key16, block, output)),
            new BenchCase("aes256.encrypt-block", "block", 1, AesBlock, code.AesEncryptBlock(key32, block, output)),
            new BenchCase("aes128.key-setup", "key", 1, 0, code.AesKeySetup(key16)),
            new BenchCase("aes256.key-setup", "key", 1, 0, code.AesKeySetup(key32)),
            new BenchCase("aes128.ecb-encrypt", "block", AesBlocks, MessageBytes, code.Ecb(key16, message)),
            new BenchCase("aes128.cbc-encrypt", "block", AesBlocks, MessageBytes, code.CbcEncrypt(key16, zero16, message)),
            new BenchCase("aes128.cbc-decrypt", "block", AesBlocks, MessageBytes, code.CbcDecrypt(key16, zero16, message)),
            new BenchCase("aes128.ctr", "block", AesBlocks, MessageBytes, code.Ctr(key16, zero16, message)),
            new BenchCase("aes128.gcm-seal", "block", AesBlocks, MessageBytes, code.GcmSeal(key16, nonce, noAad, message)),
            new BenchCase("aes128.gcm-open", "block", AesBlocks, MessageBytes, code.GcmOpen(key16, nonce, noAad, message)),
            new BenchCase("aes128.cmac", "block", AesBlocks, MessageBytes, code.Cmac(key16, message)),
            new BenchCase("tdes.encrypt-block", "block", 1, DesBlock, code.TdesEncryptBlock(key24, block, output)),
            new BenchCase("tdes.decrypt-block", "block", 1, DesBlock, code.TdesDecryptBlock(key24, block, output)),
            new BenchCase("tdes.key-setup", "key", 1, 0, code.TdesKeySetup(key24)),
        };
        foreach (string h in HashNames)
            all.Add(new BenchCase(h + ".update", "block", UpdateBlocks, UpdateBlocks * code.HashBlockSize(h), code.HashUpdate(h, UpdateBlocks)));
        foreach (string h in HashNames)
            all.Add(new BenchCase(h + ".message", "message", 1, MessageBytes, code.Hash(h, message)));
        all.Add(new BenchCase("shake128.absorb-squeeze32", "message", 1, MessageBytes, code.Shake128(message, 32)));
        all.Add(new BenchCase("hmac-sha256", "message", 1, MessageBytes, code.HmacSha256(key32, message)));
        all.Add(new BenchCase("dukpt-aes128.derive-working-key", "derivation", 1, 0, code.DukptDeriveWorkingKey(key16, Ksn)));
        return all;
    }

    /// <summary>The AO-6 row stem each case feeds (acceptance/ao-rows.tsv), and the text of one operation. Cases not listed feed no row.</summary>
    public static readonly Dictionary<string, (string Row, string Op)> AoId = new Dictionary<string, (string, string)>
    {
        ["aes128.encrypt-block"] = ("aes-block", "one 16-byte AES-128 block encrypt"),
        ["aes128.key-setup"] = ("aes-key-setup", "one AES-128 key setup"),
        ["aes128.ecb-encrypt"] = ("aes-ecb", "one 16-byte block of a 1024-byte ECB encrypt"),
        ["aes128.cbc-encrypt"] = ("aes-cbc", "one 16-byte block of a 1024-byte CBC encrypt"),
        ["aes128.ctr"] = ("aes-ctr", "one 16-byte block of a 1024-byte CTR call"),
        ["aes128.gcm-seal"] = ("aes-gcm", "one 16-byte block of a 1024-byte GCM seal, no AAD"),
        ["aes128.cmac"] = ("aes-cmac", "one 16-byte block of a 1024-byte CMAC"),
        ["md5.update"] = ("md5", "one 64-byte block of MD5 Update"),
        ["sha1.update"] = ("sha1", "one 64-byte block of SHA-1 Update"),
        ["sha256.update"] = ("sha256", "one 64-byte block of SHA-256 Update"),
        ["sha512.update"] = ("sha512", "one 128-byte block of SHA-512 Update"),
        ["sha3-256.update"] = ("keccak", "one 136-byte block of SHA3-256 Update (one Keccak-f[1600] permutation)"),
        ["hmac-sha256"] = ("hmac", "one HMAC-SHA256 of 1024 bytes, 32-byte key"),
        ["tdes.encrypt-block"] = ("tdes", "one 8-byte TDES block encrypt"),
        ["dukpt-aes128.derive-working-key"] = ("dukpt-derive", "one AES-128 DUKPT working-key derivation, counter 0x0F0F"),
    };

    /// <summary>KSN: initial key ID 8 bytes, counter 0x0000_0F0F (8 one-bits, so the walk-down runs 8 steps).</summary>
    public static readonly byte[] Ksn = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x00, 0x00, 0x0F, 0x0F };

    public static byte[] Filled(int n, byte start)
    {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte)(start + i);
        return b;
    }
}
