using System;
using F = Acceptance.Frozen.Crypto;
using FT = Acceptance.Frozen.Tls11;
using FD = Acceptance.Frozen.Dukpt;

namespace Acceptance
{
    /// <summary>A running hash on one side, so the AO checks can feed it in pieces and clone it.</summary>
    public interface IAoHash
    {
        void Update(byte[] b, int off, int n);
        byte[] Finish();
        IAoHash Clone();
    }

    /// <summary>
    /// One implementation of the primitives that AO-2 and AO-4 compare: the frozen 5c5d4a4 reference, the product, or a planted fault in
    /// the self-check. Every member maps to one public product signature. A key object is opaque to the checks.
    /// </summary>
    public abstract class AoSide
    {
        public abstract string Name { get; }

        public abstract object NewAes(byte[] key);
        public abstract void AesEncrypt(object k, byte[] i, int io, byte[] o, int oo);
        public abstract void AesDecrypt(object k, byte[] i, int io, byte[] o, int oo);
        public abstract byte[] Ecb(object k, byte[] data);
        public abstract byte[] Cbc(object k, byte[] iv, byte[] data, bool encrypt);
        public abstract byte[] Ctr(object k, byte[] counter, byte[] data);
        public abstract byte[] GcmSeal(object k, byte[] nonce, byte[] aad, byte[] plain);
        public abstract bool GcmOpen(object k, byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain);
        public abstract byte[] Cmac(object k, byte[] message);
        public abstract bool CmacVerify(object k, byte[] message, byte[] tag);

        public abstract object NewTdes(byte[] key);
        public abstract void TdesEncrypt(object k, byte[] i, int io, byte[] o, int oo);
        public abstract void TdesDecrypt(object k, byte[] i, int io, byte[] o, int oo);

        public abstract IAoHash NewHash(string alg);
        public abstract byte[] Shake(bool is128, byte[] data, int[] squeezeSizes);
        public abstract byte[] Hmac(string alg, byte[] key, byte[] data);
        public abstract bool HmacVerify(string alg, byte[] key, byte[] data, byte[] tag);
        public abstract byte[] HkdfExtract(string alg, byte[] salt, byte[] ikm);
        public abstract byte[] HkdfExpand(string alg, byte[] prk, byte[] info, int n);

        public abstract byte[] PrfDerive(byte[] secret, string label, byte[] seed, int count);
        public abstract byte[] PrfMaster(byte[] premaster, byte[] clientRandom, byte[] serverRandom);
        public abstract byte[][] PrfKeyBlock(byte[] master, byte[] clientRandom, byte[] serverRandom);
        public abstract byte[] PrfFinished(byte[] master, string label, byte[] digest);
        public abstract byte[] PrfMd5Sha1(byte[] data);

        // ---- the AES lesson walk (AO-7); results are dumped field by field with AoDump ----
        public abstract object WalkEncrypt(object k, byte[] block);
        public abstract object WalkDecrypt(object k, byte[] block);
        public abstract object WalkKeyExpansion(object k);
        public abstract object WalkTables(int rconCount);
        public abstract object WalkMixTerms(byte[] before, bool inverse);

        public abstract byte[] PinEncrypt4(byte[] pinKey, string pin, string pan, byte[] random8);
        public abstract bool PinTryDecrypt4(byte[] pinKey, byte[] block, string pan, out string pin);
        public abstract byte[] PinClearField4(string pin, byte[] random8);
        public abstract bool PinTryOpenField4(byte[] pinKey, byte[] block, string pan, out byte[] field);
    }

    /// <summary>The frozen reference: main at 5c5d4a4, namespace moved to Acceptance.Frozen (tools/freeze_ref.py).</summary>
    public class FrozenSide : AoSide
    {
        public override string Name { get { return "frozen-5c5d4a4"; } }

        sealed class H : IAoHash
        {
            readonly F.IHash _h;
            public H(F.IHash h) { _h = h; }
            public void Update(byte[] b, int off, int n) { _h.Update(b, off, n); }
            public byte[] Finish() { return _h.Finish(); }
            public IAoHash Clone() { return new H(_h.Clone()); }
        }

        public static Func<F.IHash> Factory(string alg)
        {
            switch (alg)
            {
                case "md5": return F.Hashes.Md5;
                case "sha1": return F.Hashes.Sha1;
                case "sha256": return F.Hashes.Sha256;
                case "sha384": return F.Hashes.Sha384;
                case "sha512": return F.Hashes.Sha512;
                case "sha3-256": return F.Hashes.Sha3_256;
                case "sha3-512": return F.Hashes.Sha3_512;
                default: throw new ArgumentException("no hash " + alg);
            }
        }

        public override object NewAes(byte[] key) { return new F.AesKey(key); }
        public override void AesEncrypt(object k, byte[] i, int io, byte[] o, int oo) { ((F.AesKey)k).EncryptBlock(i, io, o, oo); }
        public override void AesDecrypt(object k, byte[] i, int io, byte[] o, int oo) { ((F.AesKey)k).DecryptBlock(i, io, o, oo); }
        public override byte[] Ecb(object k, byte[] data) { return F.Modes.EcbEncrypt((F.AesKey)k, data); }
        public override byte[] Cbc(object k, byte[] iv, byte[] data, bool encrypt) { return encrypt ? F.Modes.CbcEncrypt((F.AesKey)k, iv, data) : F.Modes.CbcDecrypt((F.AesKey)k, iv, data); }
        public override byte[] Ctr(object k, byte[] counter, byte[] data) { return F.Modes.Ctr((F.AesKey)k, counter, data); }
        public override byte[] GcmSeal(object k, byte[] nonce, byte[] aad, byte[] plain) { return F.Gcm.Seal((F.AesKey)k, nonce, aad, plain); }
        public override bool GcmOpen(object k, byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain) { return F.Gcm.TryOpen((F.AesKey)k, nonce, aad, sealedBytes, out plain); }
        public override byte[] Cmac(object k, byte[] message) { return F.Cmac.Compute((F.AesKey)k, message); }
        public override bool CmacVerify(object k, byte[] message, byte[] tag) { return F.Cmac.Verify((F.AesKey)k, message, tag); }

        public override object NewTdes(byte[] key) { return new F.TdesKey(key); }
        public override void TdesEncrypt(object k, byte[] i, int io, byte[] o, int oo) { ((F.TdesKey)k).EncryptBlock(i, io, o, oo); }
        public override void TdesDecrypt(object k, byte[] i, int io, byte[] o, int oo) { ((F.TdesKey)k).DecryptBlock(i, io, o, oo); }

        public override IAoHash NewHash(string alg) { return new H(Factory(alg)()); }
        public override byte[] Shake(bool is128, byte[] data, int[] squeezeSizes)
        {
            F.Shake s = is128 ? F.Shake.New128() : F.Shake.New256();
            s.Absorb(data, 0, data == null ? 0 : data.Length);
            return AoSqueeze.All(squeezeSizes, delegate (byte[] b, int off, int n) { s.Squeeze(b, off, n); });
        }
        public override byte[] Hmac(string alg, byte[] key, byte[] data) { return F.Hmac.Compute(Factory(alg), key, data); }
        public override bool HmacVerify(string alg, byte[] key, byte[] data, byte[] tag) { return F.Hmac.Verify(Factory(alg), key, data, tag); }
        public override byte[] HkdfExtract(string alg, byte[] salt, byte[] ikm) { return F.Hkdf.Extract(Factory(alg), salt, ikm); }
        public override byte[] HkdfExpand(string alg, byte[] prk, byte[] info, int n) { return F.Hkdf.Expand(Factory(alg), prk, info, n); }

        public override byte[] PrfDerive(byte[] secret, string label, byte[] seed, int count) { return FT.Tls11Prf.Derive(secret, label, seed, count); }
        public override byte[] PrfMaster(byte[] premaster, byte[] clientRandom, byte[] serverRandom) { return FT.Tls11Prf.MasterSecret(premaster, clientRandom, serverRandom); }
        public override byte[][] PrfKeyBlock(byte[] master, byte[] clientRandom, byte[] serverRandom)
        {
            FT.Tls11KeyBlock b = FT.Tls11Prf.KeyBlock(master, clientRandom, serverRandom);
            return new byte[][] { b.ClientMac, b.ServerMac, b.ClientKey, b.ServerKey };
        }
        public override byte[] PrfFinished(byte[] master, string label, byte[] digest) { return FT.Tls11Prf.FinishedData(master, label, digest); }
        public override byte[] PrfMd5Sha1(byte[] data) { return FT.Tls11Prf.Md5Sha1(data); }

        public override object WalkEncrypt(object k, byte[] block) { return ((F.AesKey)k).WalkEncrypt(block); }
        public override object WalkDecrypt(object k, byte[] block) { return ((F.AesKey)k).WalkDecrypt(block); }
        public override object WalkKeyExpansion(object k) { return ((F.AesKey)k).WalkKeyExpansion(); }
        public override object WalkTables(int rconCount)
        {
            return new object[] { F.AesKey.SubstitutionTable(), F.AesKey.InverseSubstitutionTable(), F.AesKey.ShiftMap(false), F.AesKey.ShiftMap(true),
                                  F.AesKey.RoundConstants(rconCount), F.AesKey.RoundConstantSteps(rconCount) };
        }
        public override object WalkMixTerms(byte[] before, bool inverse) { return F.AesKey.MixTerms(before, inverse); }

        public override byte[] PinEncrypt4(byte[] pinKey, string pin, string pan, byte[] random8) { return FD.PinBlock.EncryptFormat4(pinKey, pin, pan, random8); }
        public override bool PinTryDecrypt4(byte[] pinKey, byte[] block, string pan, out string pin) { return FD.PinBlock.TryDecryptFormat4(pinKey, block, pan, out pin); }
        public override byte[] PinClearField4(string pin, byte[] random8) { return FD.PinBlock.ClearFieldFormat4(pin, random8); }
        public override bool PinTryOpenField4(byte[] pinKey, byte[] block, string pan, out byte[] field) { return FD.PinBlock.TryOpenFieldFormat4(pinKey, block, pan, out field); }
    }

    public delegate void SqueezeStep(byte[] b, int off, int n);

    /// <summary>Squeezes in the given steps into one output array, so a split squeeze can be compared with the reference.</summary>
    public static class AoSqueeze
    {
        public static byte[] All(int[] sizes, SqueezeStep step)
        {
            int total = 0;
            foreach (int s in sizes) total += s;
            byte[] o = new byte[total];
            int off = 0;
            foreach (int s in sizes) { step(o, off, s); off += s; }
            return o;
        }
    }
}
