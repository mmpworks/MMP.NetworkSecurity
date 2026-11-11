using System;
using System.Collections.Generic;
using NetSec.Crypto;
using NetSec.Dukpt;

namespace NetSec.Bench;

/// <summary>
/// The case list for slice S0: each algorithm the PRD names, through its public product API only, so the same list runs against the
/// net10.0 build and against the CF binaries. Message cases use <see cref="MessageBytes"/> bytes; per-block numbers divide by the blocks in it.
/// Each case keeps its last output in <see cref="Sink"/>, so the JIT cannot drop the work.
/// </summary>
static class Cases
{
    public const int MessageBytes = 4096;
    const int AesBlock = 16, DesBlock = 8;

    public static object Sink;

    public static List<BenchCase> All()
    {
        byte[] key16 = Filled(16, 0x10), key24 = Filled(24, 0x20), key32 = Filled(32, 0x30);
        byte[] message = Filled(MessageBytes, 0x40);
        byte[] iv = Filled(16, 0x50), nonce = Filled(12, 0x60), aad = Filled(13, 0x70);
        byte[] block = Filled(16, 0x80), output = new byte[16];
        AesKey aes128 = new AesKey(key16), aes256 = new AesKey(key32);
        TdesKey tdes = new TdesKey(key24);
        byte[] sealedMessage = Gcm.Seal(aes128, nonce, aad, message);
        byte[] cbcMessage = Modes.CbcEncrypt(aes128, iv, message);
        int aesBlocks = MessageBytes / AesBlock;

        List<BenchCase> all = new List<BenchCase>
        {
            new BenchCase("aes128.encrypt-block", "block", 1, AesBlock, () => aes128.EncryptBlock(block, 0, output, 0)),
            new BenchCase("aes128.decrypt-block", "block", 1, AesBlock, () => aes128.DecryptBlock(block, 0, output, 0)),
            new BenchCase("aes256.encrypt-block", "block", 1, AesBlock, () => aes256.EncryptBlock(block, 0, output, 0)),
            new BenchCase("aes128.key-setup", "key", 1, 0, () => Sink = new AesKey(key16)),
            new BenchCase("aes256.key-setup", "key", 1, 0, () => Sink = new AesKey(key32)),
            new BenchCase("aes128.ecb-encrypt", "block", aesBlocks, MessageBytes, () => Sink = Modes.EcbEncrypt(aes128, message)),
            new BenchCase("aes128.cbc-encrypt", "block", aesBlocks, MessageBytes, () => Sink = Modes.CbcEncrypt(aes128, iv, message)),
            new BenchCase("aes128.cbc-decrypt", "block", aesBlocks, MessageBytes, () => Sink = Modes.CbcDecrypt(aes128, iv, cbcMessage)),
            new BenchCase("aes128.ctr", "block", aesBlocks, MessageBytes, () => Sink = Modes.Ctr(aes128, iv, message)),
            new BenchCase("aes128.gcm-seal", "block", aesBlocks, MessageBytes, () => Sink = Gcm.Seal(aes128, nonce, aad, message)),
            new BenchCase("aes128.gcm-open", "block", aesBlocks, MessageBytes, () => { Gcm.TryOpen(aes128, nonce, aad, sealedMessage, out byte[] plain); Sink = plain; }),
            new BenchCase("aes128.cmac", "block", aesBlocks, MessageBytes, () => Sink = Cmac.Compute(aes128, message)),
            new BenchCase("tdes.encrypt-block", "block", 1, DesBlock, () => tdes.EncryptBlock(block, 0, output, 0)),
            new BenchCase("tdes.decrypt-block", "block", 1, DesBlock, () => tdes.DecryptBlock(block, 0, output, 0)),
            new BenchCase("tdes.key-setup", "key", 1, 0, () => Sink = new TdesKey(key24)),
            Hash("md5", Hashes.Md5, message),
            Hash("sha1", Hashes.Sha1, message),
            Hash("sha256", Hashes.Sha256, message),
            Hash("sha512", Hashes.Sha512, message),
            Hash("sha3-256", Hashes.Sha3_256, message),
            new BenchCase("shake128.absorb-squeeze32", "block", MessageBytes / 168 + 1, MessageBytes, () => Sink = Shake128(message)),
            new BenchCase("hmac-sha256", "block", MessageBytes / 64 + 4, MessageBytes, () => Sink = Hmac.Compute(Hashes.Sha256, key32, message)),
            new BenchCase("dukpt-aes128.derive-working-key", "derivation", 1, 0,
                () => Sink = DukptBank.DeriveWorkingKey(key16, Ksn, DukptKeyUsage.PinEncryption, DukptKeyType.Aes128)),
        };
        return all;
    }

    /// <summary>KSN: initial key ID 8 bytes, counter 0x0000_0F0F (8 one-bits, so the walk-down runs 8 steps).</summary>
    static readonly byte[] Ksn = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x00, 0x00, 0x0F, 0x0F };

    static BenchCase Hash(string id, Func<IHash> make, byte[] message)
    {
        int blockSize = make().BlockSize;
        return new BenchCase(id, "block", MessageBytes / blockSize + 1, MessageBytes, () =>
        {
            IHash h = make();
            h.Update(message, 0, message.Length);
            Sink = h.Finish();
        });
    }

    static byte[] Shake128(byte[] message)
    {
        Shake s = Shake.New128();
        s.Absorb(message, 0, message.Length);
        byte[] o = new byte[32];
        s.Squeeze(o, 0, o.Length);
        return o;
    }

    static byte[] Filled(int n, byte start)
    {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte)(start + i);
        return b;
    }
}
