using System;
using System.Security.Cryptography;

namespace Acceptance
{
    /// <summary>
    /// A stand-in "product" built on the .NET 10 BCL. The self-test runs the real A1 clause code against it.
    /// If the clauses pass here, the vectors and the checking code are sound. If one fails here, the vector
    /// file or the checker is wrong, and the product has not been blamed yet.
    /// Primitives the BCL lacks (X25519, Ed25519, RSA private keys from n and d, ML-KEM through this adapter)
    /// throw NotRunException, so those clauses report NOT RUN in the self-test.
    /// </summary>
    static class Subject
    {
        public const string Name = "BCL stand-in";

        /// <summary>When true, every AES output has one bit flipped. Proves that a wrong implementation fails.</summary>
        public static bool Sabotage;

        static NotRunException NoReference(string what) { return new NotRunException("SELFTEST_NO_REFERENCE", what + " has no BCL reference on this runtime"); }

        static HashAlgorithmName Alg(string alg)
        {
            switch (alg)
            {
                case "md5": return HashAlgorithmName.MD5;
                case "sha1": return HashAlgorithmName.SHA1;
                case "sha256": return HashAlgorithmName.SHA256;
                case "sha384": return HashAlgorithmName.SHA384;
                case "sha512": return HashAlgorithmName.SHA512;
                case "sha3-256": if (!SHA3_256.IsSupported) throw NoReference("SHA3-256"); return HashAlgorithmName.SHA3_256;
                case "sha3-512": if (!SHA3_512.IsSupported) throw NoReference("SHA3-512"); return HashAlgorithmName.SHA3_512;
                default: throw new NotRunException("UNKNOWN_ALGORITHM", alg);
            }
        }

        static byte[] Maybe(byte[] r)
        {
            if (Sabotage && r.Length > 0) { r = (byte[])r.Clone(); r[0] ^= 0x01; }
            return r;
        }

        // ---- AES ----
        public static byte[] AesEcb(byte[] key, byte[] data, bool encrypt)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                byte[] r = encrypt ? aes.EncryptEcb(data, PaddingMode.None) : aes.DecryptEcb(data, PaddingMode.None);
                return Maybe(r);
            }
        }

        public static byte[] AesCbc(byte[] key, byte[] iv, byte[] data, bool encrypt)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                return Maybe(encrypt ? aes.EncryptCbc(data, iv, PaddingMode.None) : aes.DecryptCbc(data, iv, PaddingMode.None));
            }
        }

        public static byte[] AesCtr(byte[] key, byte[] counter, byte[] data)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                byte[] ctr = (byte[])counter.Clone();
                byte[] outp = new byte[data.Length];
                for (int off = 0; off < data.Length; off += 16)
                {
                    byte[] ks = aes.EncryptEcb(ctr, PaddingMode.None);
                    int n = Math.Min(16, data.Length - off);
                    for (int i = 0; i < n; i++) outp[off + i] = (byte)(data[off + i] ^ ks[i]);
                    for (int i = 15; i >= 0; i--) { if (++ctr[i] != 0) break; }
                }
                return Maybe(outp);
            }
        }

        public static byte[] GcmSeal(byte[] key, byte[] nonce, byte[] aad, byte[] plain)
        {
            using (AesGcm g = new AesGcm(key, 16))
            {
                byte[] ct = new byte[plain.Length], tag = new byte[16];
                g.Encrypt(nonce, plain, ct, tag, aad);
                return Maybe(Hex.Concat(ct, tag));
            }
        }

        public static bool GcmOpen(byte[] key, byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain)
        {
            plain = null;
            using (AesGcm g = new AesGcm(key, 16))
            {
                int n = sealedBytes.Length - 16;
                byte[] pt = new byte[n];
                try { g.Decrypt(nonce, Hex.Slice(sealedBytes, 0, n), Hex.Slice(sealedBytes, n, 16), pt, aad); }
                catch (CryptographicException) { return false; }
                plain = pt;
                return true;
            }
        }

        // ---- hashes and MACs ----
        public static byte[] Hash(string alg, byte[] data, int chunk)
        {
            using (IncrementalHash h = IncrementalHash.CreateHash(Alg(alg)))
            {
                if (chunk <= 0) h.AppendData(data);
                else
                    for (int off = 0; off < data.Length; off += chunk)
                        h.AppendData(data, off, Math.Min(chunk, data.Length - off));
                return Maybe(h.GetHashAndReset());
            }
        }

        public static byte[] Shake(string alg, byte[] data, int outBytes)
        {
            if (alg == "shake128")
            {
                if (!Shake128.IsSupported) throw NoReference("SHAKE128");
                return Maybe(Shake128.HashData(data, outBytes));
            }
            if (!Shake256.IsSupported) throw NoReference("SHAKE256");
            return Maybe(Shake256.HashData(data, outBytes));
        }

        public static byte[] Hmac(string alg, byte[] key, byte[] data)
        {
            using (IncrementalHash h = IncrementalHash.CreateHMAC(Alg(alg), key))
            {
                h.AppendData(data);
                return Maybe(h.GetHashAndReset());
            }
        }

        public static byte[] Cmac(byte[] key, byte[] msg)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                byte[] l = aes.EncryptEcb(new byte[16], PaddingMode.None);
                byte[] k1 = Dbl(l), k2 = Dbl(k1);
                int blocks = msg.Length == 0 ? 1 : (msg.Length + 15) / 16;
                bool complete = msg.Length != 0 && msg.Length % 16 == 0;
                byte[] last = new byte[16];
                int lastOff = (blocks - 1) * 16;
                int lastLen = msg.Length - lastOff;
                Array.Copy(msg, lastOff, last, 0, lastLen);
                if (!complete) last[lastLen] = 0x80;
                byte[] k = complete ? k1 : k2;
                for (int i = 0; i < 16; i++) last[i] ^= k[i];
                byte[] x = new byte[16];
                for (int b = 0; b < blocks - 1; b++)
                {
                    for (int i = 0; i < 16; i++) x[i] ^= msg[b * 16 + i];
                    x = aes.EncryptEcb(x, PaddingMode.None);
                }
                for (int i = 0; i < 16; i++) x[i] ^= last[i];
                return Maybe(aes.EncryptEcb(x, PaddingMode.None));
            }
        }

        static byte[] Dbl(byte[] b)
        {
            byte[] r = new byte[16];
            int carry = 0;
            for (int i = 15; i >= 0; i--) { int v = (b[i] << 1) | carry; r[i] = (byte)v; carry = (b[i] >> 7) & 1; }
            if ((b[0] & 0x80) != 0) r[15] ^= 0x87;
            return r;
        }

        public static byte[] HkdfExtract(string alg, byte[] salt, byte[] ikm) { return Maybe(HKDF.Extract(Alg(alg), ikm, salt)); }
        public static byte[] HkdfExpand(string alg, byte[] prk, byte[] info, int len) { return Maybe(HKDF.Expand(Alg(alg), prk, len, info)); }

        // ---- no BCL reference on this runtime ----
        public static byte[] X25519(byte[] scalar, byte[] u) { throw NoReference("X25519"); }
        public static byte[] X25519Base(byte[] scalar) { throw NoReference("X25519"); }
        public static byte[] Ed25519Public(byte[] seed) { throw NoReference("Ed25519"); }
        public static byte[] Ed25519Sign(byte[] seed, byte[] msg) { throw NoReference("Ed25519"); }
        public static bool Ed25519Verify(byte[] pub, byte[] msg, byte[] sig) { throw NoReference("Ed25519"); }
        public static byte[] Tdes(byte[] key, byte[] data, bool encrypt) { throw NoReference("TDES with repeated keys (the BCL rejects weak keys)"); }
        public static byte[] RsaSignSha1(byte[] n, byte[] d, byte[] msg) { throw NoReference("RSA from n and d"); }
        public static bool RsaVerify(string hash, byte[] n, byte[] e, byte[] msg, byte[] sig)
        {
            using (RSA rsa = RSA.Create())
            {
                RSAParameters p = new RSAParameters();
                p.Modulus = n; p.Exponent = e;
                rsa.ImportParameters(p);
                return rsa.VerifyData(msg, sig, hash == "sha1" ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
        public static bool RsaDecrypt(byte[] n, byte[] d, byte[] cipher, out byte[] plain) { throw NoReference("RSA from n and d"); }
        public static byte[] RsaEncrypt(byte[] n, byte[] e, byte[] plain, byte[] seed) { throw NoReference("RSA padding with a fixed seed"); }
        public static byte[] RsaRaw(byte[] n, byte[] e, byte[] m) { throw NoReference("RSA raw operation"); }
        public static byte[] Dh14Public(byte[] x) { throw NoReference("DH group 14"); }
        public static byte[] Dh14Shared(byte[] x, byte[] peer) { throw NoReference("DH group 14"); }
        public static void MlKemKeyGen(byte[] d, byte[] z, out byte[] ek, out byte[] dk) { throw NoReference("ML-KEM through this adapter"); }
        public static void MlKemEncaps(byte[] ek, byte[] m, out byte[] ct, out byte[] ss) { throw NoReference("ML-KEM through this adapter"); }
        public static byte[] MlKemDecaps(byte[] dk, byte[] ct) { throw NoReference("ML-KEM through this adapter"); }
    }
}
