using System;
using NetSec.Crypto;

namespace Acceptance
{
    /// <summary>
    /// The one place where the primitive clauses touch product code (program-design section 2.3).
    /// Every member maps to one public signature. The clause files call Subject and nothing else,
    /// so the vector logic runs against any implementation, including the BCL stand-in in selftest.
    /// </summary>
    static class Subject
    {
        public const string Name = "NetSec.Core";

        static Func<IHash> HashFactory(string alg)
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
                default: throw new NotRunException("UNKNOWN_ALGORITHM", alg);
            }
        }

        // ---- AES ----
        public static byte[] AesEcb(byte[] key, byte[] data, bool encrypt)
        {
            AesKey k = new AesKey(key);
            if (encrypt) return Modes.EcbEncrypt(k, data);
            // Modes has no ECB decrypt (section 2.3). Decrypt block by block through AesKey.
            byte[] outp = new byte[data.Length];
            for (int i = 0; i < data.Length; i += 16) k.DecryptBlock(data, i, outp, i);
            return outp;
        }

        public static byte[] AesCbc(byte[] key, byte[] iv, byte[] data, bool encrypt)
        {
            AesKey k = new AesKey(key);
            return encrypt ? Modes.CbcEncrypt(k, iv, data) : Modes.CbcDecrypt(k, iv, data);
        }

        public static byte[] AesCtr(byte[] key, byte[] counter, byte[] data) { return Modes.Ctr(new AesKey(key), counter, data); }

        public static byte[] GcmSeal(byte[] key, byte[] nonce, byte[] aad, byte[] plain) { return Gcm.Seal(new AesKey(key), nonce, aad, plain); }

        public static bool GcmOpen(byte[] key, byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain)
        {
            return Gcm.TryOpen(new AesKey(key), nonce, aad, sealedBytes, out plain);
        }

        // ---- hashes ----
        /// <summary>Hash of data. chunk > 0 feeds the hash in pieces of that size, which exercises the buffering.</summary>
        public static byte[] Hash(string alg, byte[] data, int chunk)
        {
            IHash h = HashFactory(alg)();
            if (chunk <= 0) h.Update(data, 0, data.Length);
            else
                for (int off = 0; off < data.Length; off += chunk)
                    h.Update(data, off, Math.Min(chunk, data.Length - off));
            return h.Finish();
        }

        public static byte[] Shake(string alg, byte[] data, int outBytes)
        {
            NetSec.Crypto.Shake s = alg == "shake128" ? NetSec.Crypto.Shake.New128() : NetSec.Crypto.Shake.New256();
            s.Absorb(data, 0, data.Length);
            byte[] o = new byte[outBytes];
            s.Squeeze(o, 0, outBytes);
            return o;
        }

        public static byte[] Hmac(string alg, byte[] key, byte[] data) { return NetSec.Crypto.Hmac.Compute(HashFactory(alg), key, data); }
        public static byte[] Cmac(byte[] key, byte[] msg) { return NetSec.Crypto.Cmac.Compute(new AesKey(key), msg); }
        public static byte[] HkdfExtract(string alg, byte[] salt, byte[] ikm) { return Hkdf.Extract(HashFactory(alg), salt, ikm); }
        public static byte[] HkdfExpand(string alg, byte[] prk, byte[] info, int len) { return Hkdf.Expand(HashFactory(alg), prk, info, len); }

        // ---- curves ----
        public static byte[] X25519(byte[] scalar, byte[] u) { return NetSec.Crypto.X25519.Mult(scalar, u); }
        public static byte[] X25519Base(byte[] scalar) { return NetSec.Crypto.X25519.MultBase(scalar); }
        public static byte[] Ed25519Public(byte[] seed) { return NetSec.Crypto.Ed25519.PublicFrom(seed); }
        public static byte[] Ed25519Sign(byte[] seed, byte[] msg) { return NetSec.Crypto.Ed25519.Sign(seed, msg); }
        public static bool Ed25519Verify(byte[] pub, byte[] msg, byte[] sig) { return NetSec.Crypto.Ed25519.Verify(pub, msg, sig); }

        // ---- TDES ----
        public static byte[] Tdes(byte[] key, byte[] data, bool encrypt)
        {
            TdesKey k = new TdesKey(key);
            byte[] o = new byte[data.Length];
            for (int i = 0; i < data.Length; i += 8)
            {
                if (encrypt) k.EncryptBlock(data, i, o, i); else k.DecryptBlock(data, i, o, i);
            }
            return o;
        }

        // ---- RSA (ASSUMED: BigUInt.FromBytes) ----
        static RsaPublic Pub(byte[] n, byte[] e) { return new RsaPublic(BigUInt.FromBytes(n), BigUInt.FromBytes(e)); }
        static RsaPrivate Priv(byte[] n, byte[] d) { return new RsaPrivate(BigUInt.FromBytes(n), BigUInt.FromBytes(d)); }

        public static byte[] RsaSignSha1(byte[] n, byte[] d, byte[] msg) { return Pkcs1.SignSha1(Priv(n, d), msg); }
        public static bool RsaVerify(string hash, byte[] n, byte[] e, byte[] msg, byte[] sig)
        {
            RsaPublic p = Pub(n, e);
            if (hash == "sha1") return Pkcs1.VerifySha1(p, msg, sig);
            if (hash == "sha256") return Pkcs1.VerifySha256(p, msg, sig);
            throw new NotRunException("UNKNOWN_ALGORITHM", hash);
        }
        public static bool RsaDecrypt(byte[] n, byte[] d, byte[] cipher, out byte[] plain) { return Pkcs1.TryDecryptV15(Priv(n, d), cipher, out plain); }
        public static byte[] RsaEncrypt(byte[] n, byte[] e, byte[] plain, byte[] seed)
        {
            return Pkcs1.EncryptV15(Pub(n, e), new SeededFill(seed), plain);
        }
        public static byte[] RsaRaw(byte[] n, byte[] e, byte[] m) { return Pub(n, e).Raw(m); }

        // ---- DH group 14 ----
        public static byte[] Dh14Public(byte[] x) { return DhGroup14.Public(x); }
        public static byte[] Dh14Shared(byte[] x, byte[] peer) { return DhGroup14.Shared(x, peer); }

        // ---- ML-KEM-768 (used by A2) ----
        public static void MlKemKeyGen(byte[] d, byte[] z, out byte[] ek, out byte[] dk)
        {
            MlKemPair p = MlKem768.KeyGen(d, z);
            ek = p.Ek;
            dk = p.Dk;
        }
        public static void MlKemEncaps(byte[] ek, byte[] m, out byte[] ct, out byte[] ss)
        {
            MlKemSealed s = MlKem768.Encaps(ek, m);
            ct = s.Ciphertext;
            ss = s.SharedSecret;
        }
        public static byte[] MlKemDecaps(byte[] dk, byte[] ct) { return MlKem768.Decaps(dk, ct); }

        /// <summary>Feeds the given bytes, then repeats them. Lets a test replay the padding bytes an encryption uses.</summary>
        sealed class SeededFill : IRandomSource
        {
            readonly byte[] _seed; int _pos;
            public SeededFill(byte[] seed) { _seed = seed; }
            public void Fill(byte[] b, int off, int n)
            {
                for (int i = 0; i < n; i++) { b[off + i] = _seed[_pos % _seed.Length]; _pos++; }
            }
        }
    }
}
