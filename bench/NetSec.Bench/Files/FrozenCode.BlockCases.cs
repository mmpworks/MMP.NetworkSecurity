using System;
using Acceptance.Frozen.Crypto;
using Acceptance.Frozen.Dukpt;

namespace NetSec.Bench.Files;

/// <summary>The per-block cases on the frozen 5c5d4a4 copy. It began as the same calls as ProductCode.BlockCases.cs, and it stays on the 5c5d4a4 API.</summary>
sealed partial class FrozenCode : IBlockCases
{
    public Action AesEncryptBlock(byte[] key, byte[] input, byte[] output) { AesKey k = new AesKey(key); return () => k.EncryptBlock(input, 0, output, 0); }
    public Action AesDecryptBlock(byte[] key, byte[] input, byte[] output) { AesKey k = new AesKey(key); return () => k.DecryptBlock(input, 0, output, 0); }
    public Action AesKeySetup(byte[] key) => () => Cases.Sink = new AesKey(key);
    public Action Ecb(byte[] key, byte[] message) { AesKey k = new AesKey(key); return () => Cases.Sink = Modes.EcbEncrypt(k, message); }
    public Action CbcEncrypt(byte[] key, byte[] iv, byte[] message) { AesKey k = new AesKey(key); return () => Cases.Sink = Modes.CbcEncrypt(k, iv, message); }

    public Action CbcDecrypt(byte[] key, byte[] iv, byte[] message)
    {
        AesKey k = new AesKey(key);
        byte[] cipher = Modes.CbcEncrypt(k, iv, message);
        return () => Cases.Sink = Modes.CbcDecrypt(k, iv, cipher);
    }

    public Action Ctr(byte[] key, byte[] counter, byte[] message) { AesKey k = new AesKey(key); return () => Cases.Sink = Modes.Ctr(k, counter, message); }
    public Action GcmSeal(byte[] key, byte[] nonce, byte[] aad, byte[] message) { AesKey k = new AesKey(key); return () => Cases.Sink = Gcm.Seal(k, nonce, aad, message); }

    public Action GcmOpen(byte[] key, byte[] nonce, byte[] aad, byte[] message)
    {
        AesKey k = new AesKey(key);
        byte[] sealedBytes = Gcm.Seal(k, nonce, aad, message);
        return () => { Gcm.TryOpen(k, nonce, aad, sealedBytes, out byte[] plain); Cases.Sink = plain; };
    }

    public Action Cmac(byte[] key, byte[] message) { AesKey k = new AesKey(key); return () => Cases.Sink = Acceptance.Frozen.Crypto.Cmac.Compute(k, message); }
    public Action TdesEncryptBlock(byte[] key, byte[] input, byte[] output) { TdesKey k = new TdesKey(key); return () => k.EncryptBlock(input, 0, output, 0); }
    public Action TdesDecryptBlock(byte[] key, byte[] input, byte[] output) { TdesKey k = new TdesKey(key); return () => k.DecryptBlock(input, 0, output, 0); }
    public Action TdesKeySetup(byte[] key) => () => Cases.Sink = new TdesKey(key);

    public Action Hash(string name, byte[] message)
    {
        Func<IHash> make = MakeHash(name);
        return () =>
        {
            IHash h = make();
            h.Update(message, 0, message.Length);
            Cases.Sink = h.Finish();
        };
    }

    public int HashBlockSize(string name) => MakeHash(name)().BlockSize;

    public Action Shake128(byte[] message, int outputBytes) => () =>
    {
        Shake s = Shake.New128();
        s.Absorb(message, 0, message.Length);
        byte[] o = new byte[outputBytes];
        s.Squeeze(o, 0, o.Length);
        Cases.Sink = o;
    };

    public Action HmacSha256(byte[] key, byte[] message) => () => Cases.Sink = Hmac.Compute(Hashes.Sha256, key, message);

    public Action DukptDeriveWorkingKey(byte[] bdk, byte[] ksn) =>
        () => Cases.Sink = DukptBank.DeriveWorkingKey(bdk, ksn, DukptKeyUsage.PinEncryption, DukptKeyType.Aes128);

    static Func<IHash> MakeHash(string name)
    {
        switch (name)
        {
            case "md5": return Hashes.Md5;
            case "sha1": return Hashes.Sha1;
            case "sha256": return Hashes.Sha256;
            case "sha512": return Hashes.Sha512;
            case "sha3-256": return Hashes.Sha3_256;
            default: throw new ArgumentException("BENCH_HASH_UNKNOWN: " + name, nameof(name));
        }
    }
}
