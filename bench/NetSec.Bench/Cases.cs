using System.Collections.Generic;

namespace NetSec.Bench;

/// <summary>
/// The per-block case list of slice S0, built on one copy of the code (<see cref="IBlockCases"/>), so the same list times the product
/// and the frozen 5c5d4a4 copy in one run. Message cases use <see cref="MessageBytes"/> bytes; per-block numbers divide by the blocks in it.
/// Each case keeps its last output in <see cref="Sink"/>, so the JIT cannot drop the work. <see cref="AoId"/> names the AO row a case feeds.
/// </summary>
static class Cases
{
    public const int MessageBytes = 4096;
    const int AesBlock = 16, DesBlock = 8, AesBlocks = MessageBytes / AesBlock;

    public static object Sink;

    public static List<BenchCase> All(IBlockCases code)
    {
        byte[] key16 = Filled(16, 0x10), key24 = Filled(24, 0x20), key32 = Filled(32, 0x30);
        byte[] message = Filled(MessageBytes, 0x40);
        byte[] iv = Filled(16, 0x50), nonce = Filled(12, 0x60), aad = Filled(13, 0x70);
        byte[] block = Filled(16, 0x80), output = new byte[16];

        return new List<BenchCase>
        {
            new BenchCase("aes128.encrypt-block", "block", 1, AesBlock, code.AesEncryptBlock(key16, block, output)),
            new BenchCase("aes128.decrypt-block", "block", 1, AesBlock, code.AesDecryptBlock(key16, block, output)),
            new BenchCase("aes256.encrypt-block", "block", 1, AesBlock, code.AesEncryptBlock(key32, block, output)),
            new BenchCase("aes128.key-setup", "key", 1, 0, code.AesKeySetup(key16)),
            new BenchCase("aes256.key-setup", "key", 1, 0, code.AesKeySetup(key32)),
            new BenchCase("aes128.ecb-encrypt", "block", AesBlocks, MessageBytes, code.Ecb(key16, message)),
            new BenchCase("aes128.cbc-encrypt", "block", AesBlocks, MessageBytes, code.CbcEncrypt(key16, iv, message)),
            new BenchCase("aes128.cbc-decrypt", "block", AesBlocks, MessageBytes, code.CbcDecrypt(key16, iv, message)),
            new BenchCase("aes128.ctr", "block", AesBlocks, MessageBytes, code.Ctr(key16, iv, message)),
            new BenchCase("aes128.gcm-seal", "block", AesBlocks, MessageBytes, code.GcmSeal(key16, nonce, aad, message)),
            new BenchCase("aes128.gcm-open", "block", AesBlocks, MessageBytes, code.GcmOpen(key16, nonce, aad, message)),
            new BenchCase("aes128.cmac", "block", AesBlocks, MessageBytes, code.Cmac(key16, message)),
            new BenchCase("tdes.encrypt-block", "block", 1, DesBlock, code.TdesEncryptBlock(key24, block, output)),
            new BenchCase("tdes.decrypt-block", "block", 1, DesBlock, code.TdesDecryptBlock(key24, block, output)),
            new BenchCase("tdes.key-setup", "key", 1, 0, code.TdesKeySetup(key24)),
            Hash(code, "md5", message),
            Hash(code, "sha1", message),
            Hash(code, "sha256", message),
            Hash(code, "sha512", message),
            Hash(code, "sha3-256", message),
            new BenchCase("shake128.absorb-squeeze32", "block", MessageBytes / 168 + 1, MessageBytes, code.Shake128(message, 32)),
            // HMAC-SHA256 on 4096 bytes: inner hash 64 + 4096 bytes plus padding (66 blocks), outer hash 64 + 32 bytes (2 blocks).
            new BenchCase("hmac-sha256", "block", MessageBytes / 64 + 4, MessageBytes, code.HmacSha256(key32, message)),
            new BenchCase("dukpt-aes128.derive-working-key", "derivation", 1, 0, code.DukptDeriveWorkingKey(key16, Ksn)),
        };
    }

    /// <summary>The AO-5 / AO-6 row stem each case feeds (acceptance/ao-rows.tsv), and the text of one operation. Cases not listed feed no row.</summary>
    public static readonly Dictionary<string, (string Row, string Op)> AoId = new Dictionary<string, (string, string)>
    {
        ["aes128.encrypt-block"] = ("aes-block", "one 16-byte AES-128 block"),
        ["aes128.key-setup"] = ("aes-key-setup", "one AES-128 key setup"),
        ["aes128.ecb-encrypt"] = ("aes-ecb", "one 16-byte block of a 4096-byte ECB message"),
        ["aes128.cbc-encrypt"] = ("aes-cbc", "one 16-byte block of a 4096-byte CBC encrypt"),
        ["aes128.ctr"] = ("aes-ctr", "one 16-byte block of a 4096-byte CTR message"),
        ["aes128.gcm-seal"] = ("aes-gcm", "one 16-byte block of a 4096-byte GCM seal"),
        ["aes128.cmac"] = ("aes-cmac", "one 16-byte block of a 4096-byte CMAC"),
        ["md5"] = ("md5", "one 64-byte block of a 4096-byte MD5"),
        ["sha1"] = ("sha1", "one 64-byte block of a 4096-byte SHA-1"),
        ["sha256"] = ("sha256", "one 64-byte block of a 4096-byte SHA-256"),
        ["sha512"] = ("sha512", "one 128-byte block of a 4096-byte SHA-512"),
        ["sha3-256"] = ("keccak", "one Keccak-f[1600] permutation of a 4096-byte SHA3-256"),
        ["hmac-sha256"] = ("hmac", "one 64-byte block of a 4096-byte HMAC-SHA256"),
        ["tdes.encrypt-block"] = ("tdes", "one 8-byte TDES block"),
        ["dukpt-aes128.derive-working-key"] = ("dukpt-derive", "one AES-128 DUKPT working-key derivation, counter 0x0F0F"),
    };

    /// <summary>KSN: initial key ID 8 bytes, counter 0x0000_0F0F (8 one-bits, so the walk-down runs 8 steps).</summary>
    static readonly byte[] Ksn = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x00, 0x00, 0x0F, 0x0F };

    static BenchCase Hash(IBlockCases code, string name, byte[] message) =>
        new BenchCase(name, "block", MessageBytes / code.HashBlockSize(name) + 1, MessageBytes, code.Hash(name, message));

    static byte[] Filled(int n, byte start)
    {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte)(start + i);
        return b;
    }
}
