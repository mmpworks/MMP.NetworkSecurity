using System;
using NetSec.Crypto;

namespace NetSec.Bench.Files;

/// <summary>
/// The seam between the AO-9 harness and one copy of the crypto code. The harness holds two: "original" (Echo's frozen 5c5d4a4 copy) and
/// "new" (the product NetSec.Core). Each copy binds its keys once, outside the timer, so a row times the per-call work and nothing else.
/// When a slice changes the product API (for example a GcmKey in S1), only the "new" adapter changes; the harness and the report stay.
/// </summary>
interface ICodeUnderTest
{
    string Name { get; }
    IBoundCode Bind(byte[] aesKey, byte[] hmacKey);

    /// <summary>The small-message row (AO-9 rule 6): one key setup plus one seal of 64 bytes, timed together.</summary>
    byte[] KeySetupAndSeal(byte[] aesKey, byte[] nonce, byte[] aad, byte[] plain64);
}

/// <summary>The per-file operations of AO-9, on keys bound once. Each one returns new bytes, so the harness can compare the two copies.</summary>
interface IBoundCode
{
    byte[] GcmSeal(byte[] nonce, byte[] aad, byte[] plain);
    byte[] GcmOpen(byte[] nonce, byte[] aad, byte[] sealedBytes);
    byte[] CbcEncrypt(byte[] iv, byte[] plain);
    byte[] CbcDecrypt(byte[] iv, byte[] cipher);
    byte[] Ctr(byte[] counter, byte[] data);
    byte[] Sha256(byte[] data);
    byte[] HmacSha256(byte[] data);
}

/// <summary>The product code, NetSec.Core as built today. At S0 it is the 5c5d4a4 code, so original and new must agree to within the noise.</summary>
sealed class ProductCode : ICodeUnderTest
{
    public string Name => "new";

    public IBoundCode Bind(byte[] aesKey, byte[] hmacKey) => new Bound(new AesKey(aesKey), hmacKey);

    public byte[] KeySetupAndSeal(byte[] aesKey, byte[] nonce, byte[] aad, byte[] plain64) => Gcm.Seal(new AesKey(aesKey), nonce, aad, plain64);

    sealed class Bound : IBoundCode
    {
        readonly AesKey _key;
        readonly byte[] _hmacKey;

        public Bound(AesKey key, byte[] hmacKey) { _key = key; _hmacKey = hmacKey; }

        public byte[] GcmSeal(byte[] nonce, byte[] aad, byte[] plain) => Gcm.Seal(_key, nonce, aad, plain);

        public byte[] GcmOpen(byte[] nonce, byte[] aad, byte[] sealedBytes)
        {
            if (!Gcm.TryOpen(_key, nonce, aad, sealedBytes, out byte[] plain)) throw new InvalidOperationException("BENCH_GCM_OPEN_FAILED");
            return plain;
        }

        public byte[] CbcEncrypt(byte[] iv, byte[] plain) => Modes.CbcEncrypt(_key, iv, plain);
        public byte[] CbcDecrypt(byte[] iv, byte[] cipher) => Modes.CbcDecrypt(_key, iv, cipher);
        public byte[] Ctr(byte[] counter, byte[] data) => Modes.Ctr(_key, counter, data);

        public byte[] Sha256(byte[] data)
        {
            IHash h = Hashes.Sha256();
            h.Update(data, 0, data.Length);
            return h.Finish();
        }

        public byte[] HmacSha256(byte[] data) => Hmac.Compute(Hashes.Sha256, _hmacKey, data);
    }
}
