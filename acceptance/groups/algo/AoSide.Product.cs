using System;
using NetSec.Crypto;
using NetSec.Dukpt;
using NetSec.Tls11;

namespace Acceptance
{
    /// <summary>The one place where the AO clauses touch product code. The members mirror FrozenSide line for line.</summary>
    public sealed class ProductSide : AoSide
    {
        public override string Name { get { return "product"; } }

        sealed class H : IAoHash
        {
            readonly IHash _h;
            public H(IHash h) { _h = h; }
            public void Update(byte[] b, int off, int n) { _h.Update(b, off, n); }
            public byte[] Finish() { return _h.Finish(); }
            public IAoHash Clone() { return new H(_h.Clone()); }
        }

        static Func<IHash> Factory(string alg)
        {
            switch (alg)
            {
                case "md5": return Hashes.Md5;
                case "sha1": return Hashes.Sha1;
                case "sha256": return Hashes.Sha256;
                case "sha384": return Hashes.Sha384;
                case "sha512": return Hashes.Sha512;
                case "sha3-256": return Hashes.Sha3_256;
                case "sha3-512": return Hashes.Sha3_512;
                default: throw new ArgumentException("no hash " + alg);
            }
        }

        public override object NewAes(byte[] key) { return new AesKey(key); }
        public override void AesEncrypt(object k, byte[] i, int io, byte[] o, int oo) { ((AesKey)k).EncryptBlock(i, io, o, oo); }
        public override void AesDecrypt(object k, byte[] i, int io, byte[] o, int oo) { ((AesKey)k).DecryptBlock(i, io, o, oo); }
        public override byte[] Ecb(object k, byte[] data) { return Modes.EcbEncrypt((AesKey)k, data); }
        public override byte[] Cbc(object k, byte[] iv, byte[] data, bool encrypt) { return encrypt ? Modes.CbcEncrypt((AesKey)k, iv, data) : Modes.CbcDecrypt((AesKey)k, iv, data); }
        public override byte[] Ctr(object k, byte[] counter, byte[] data) { return Modes.Ctr((AesKey)k, counter, data); }
        public override byte[] GcmSeal(object k, byte[] nonce, byte[] aad, byte[] plain) { return Gcm.Seal((AesKey)k, nonce, aad, plain); }
        public override bool GcmOpen(object k, byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain) { return Gcm.TryOpen((AesKey)k, nonce, aad, sealedBytes, out plain); }
        public override byte[] Cmac(object k, byte[] message) { return NetSec.Crypto.Cmac.Compute((AesKey)k, message); }
        public override bool CmacVerify(object k, byte[] message, byte[] tag) { return NetSec.Crypto.Cmac.Verify((AesKey)k, message, tag); }

        public override object NewTdes(byte[] key) { return new TdesKey(key); }
        public override void TdesEncrypt(object k, byte[] i, int io, byte[] o, int oo) { ((TdesKey)k).EncryptBlock(i, io, o, oo); }
        public override void TdesDecrypt(object k, byte[] i, int io, byte[] o, int oo) { ((TdesKey)k).DecryptBlock(i, io, o, oo); }

        public override IAoHash NewHash(string alg) { return new H(Factory(alg)()); }
        public override byte[] Shake(bool is128, byte[] data, int[] squeezeSizes)
        {
            NetSec.Crypto.Shake s = is128 ? NetSec.Crypto.Shake.New128() : NetSec.Crypto.Shake.New256();
            s.Absorb(data, 0, data == null ? 0 : data.Length);
            return AoSqueeze.All(squeezeSizes, delegate (byte[] b, int off, int n) { s.Squeeze(b, off, n); });
        }
        public override byte[] Hmac(string alg, byte[] key, byte[] data) { return NetSec.Crypto.Hmac.Compute(Factory(alg), key, data); }
        public override bool HmacVerify(string alg, byte[] key, byte[] data, byte[] tag) { return NetSec.Crypto.Hmac.Verify(Factory(alg), key, data, tag); }
        public override byte[] HkdfExtract(string alg, byte[] salt, byte[] ikm) { return Hkdf.Extract(Factory(alg), salt, ikm); }
        public override byte[] HkdfExpand(string alg, byte[] prk, byte[] info, int n) { return Hkdf.Expand(Factory(alg), prk, info, n); }

        public override byte[] PrfDerive(byte[] secret, string label, byte[] seed, int count) { return Tls11Prf.Derive(secret, label, seed, count); }
        public override byte[] PrfMaster(byte[] premaster, byte[] clientRandom, byte[] serverRandom) { return Tls11Prf.MasterSecret(premaster, clientRandom, serverRandom); }
        public override byte[][] PrfKeyBlock(byte[] master, byte[] clientRandom, byte[] serverRandom)
        {
            Tls11KeyBlock b = Tls11Prf.KeyBlock(master, clientRandom, serverRandom);
            return new byte[][] { b.ClientMac, b.ServerMac, b.ClientKey, b.ServerKey };
        }
        public override byte[] PrfFinished(byte[] master, string label, byte[] digest) { return Tls11Prf.FinishedData(master, label, digest); }
        public override byte[] PrfMd5Sha1(byte[] data) { return Tls11Prf.Md5Sha1(data); }

        public override object WalkEncrypt(object k, byte[] block) { return ((AesKey)k).WalkEncrypt(block); }
        public override object WalkDecrypt(object k, byte[] block) { return ((AesKey)k).WalkDecrypt(block); }
        public override object WalkKeyExpansion(object k) { return ((AesKey)k).WalkKeyExpansion(); }
        public override object WalkTables(int rconCount)
        {
            return new object[] { AesKey.SubstitutionTable(), AesKey.InverseSubstitutionTable(), AesKey.ShiftMap(false), AesKey.ShiftMap(true),
                                  AesKey.RoundConstants(rconCount), AesKey.RoundConstantSteps(rconCount) };
        }
        public override object WalkMixTerms(byte[] before, bool inverse) { return AesKey.MixTerms(before, inverse); }

        public override byte[] PinEncrypt4(byte[] pinKey, string pin, string pan, byte[] random8) { return PinBlock.EncryptFormat4(pinKey, pin, pan, random8); }
        public override bool PinTryDecrypt4(byte[] pinKey, byte[] block, string pan, out string pin) { return PinBlock.TryDecryptFormat4(pinKey, block, pan, out pin); }
        public override byte[] PinClearField4(string pin, byte[] random8) { return PinBlock.ClearFieldFormat4(pin, random8); }
        public override bool PinTryOpenField4(byte[] pinKey, byte[] block, string pan, out byte[] field) { return PinBlock.TryOpenFieldFormat4(pinKey, block, pan, out field); }
    }

    /// <summary>The side under test. The selftest group has its own copy of this class that returns a planted fault.</summary>
    public static class AoSubject
    {
        public static AoSide Make(Ctx c)
        {
            c.RequireProduct();
            ProductSide p = new ProductSide();
            // Load the product here, outside the case loop: a missing DLL then ends the clause by name, never as a million differences.
            p.NewAes(new byte[16]);
            return p;
        }
    }
}
