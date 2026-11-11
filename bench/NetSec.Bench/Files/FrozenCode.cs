using System;
using Acceptance.Frozen.Crypto;

namespace NetSec.Bench.Files;

/// <summary>
/// "original" for AO-9: Echo's frozen 5c5d4a4 copy (namespace Acceptance.Frozen), compiled by bench/Frozen for net10.0 and by
/// bench/Frozen.NetCF for the CF run, with the product build settings. Its API is the 5c5d4a4 API, so this adapter stays as it is
/// while the "new" adapter follows the product through the slices.
/// </summary>
sealed partial class FrozenCode : ICodeUnderTest
{
    public string Name => "original";

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
