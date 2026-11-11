#if NET
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Acceptance
{
    /// <summary>
    /// The second referee of PRD 3.1 rule 2: System.Security.Cryptography on .NET 10. AoDiff runs it on the cases where the frozen
    /// reference threw nothing, because the BCL names its errors in its own way. It never sees an invalid case, so each member may assume
    /// valid input. Algorithms the BCL lacks (CMAC, DUKPT, PIN block, SHAKE, the TLS 1.1 PRF, the walk) are not in Supports.
    /// Every member reads its whole input before it writes, as the reference does, so aliased buffers give the reference result.
    /// </summary>
    public sealed class BclSide : AoSide
    {
        public override string Name { get { return "bcl"; } }

        public static bool Supports(string alg)
        {
            switch (alg)
            {
                case "aes-block": case "aes-ecb": case "aes-cbc": case "aes-ctr": case "aes-gcm": case "tdes-block":
                case "md5": case "sha1": case "sha256": case "sha384": case "sha512": case "hmac": case "hkdf":
                    return true;
                case "sha3-256": return SHA3_256.IsSupported;
                case "sha3-512": return SHA3_512.IsSupported;
                default: return false;
            }
        }

        static HashAlgorithmName HashName(string alg)
        {
            switch (alg)
            {
                case "md5": return HashAlgorithmName.MD5;
                case "sha1": return HashAlgorithmName.SHA1;
                case "sha256": return HashAlgorithmName.SHA256;
                case "sha384": return HashAlgorithmName.SHA384;
                case "sha512": return HashAlgorithmName.SHA512;
                case "sha3-256": return HashAlgorithmName.SHA3_256;
                case "sha3-512": return HashAlgorithmName.SHA3_512;
                default: throw new ArgumentException("no hash " + alg);
            }
        }

        /// <summary>HMAC and HKDF over SHA-3 need the OS; on an OS without it the case would differ by an exception, so the case says so.</summary>
        static void RequireHash(string alg)
        {
            if ((alg == "sha3-256" && !SHA3_256.IsSupported) || (alg == "sha3-512" && !SHA3_512.IsSupported)) throw new AoBclSkip();
        }

        sealed class AesK { public Aes A; public byte[] Key; }

        public override object NewAes(byte[] key) { AesK k = new AesK(); k.A = Aes.Create(); k.A.Key = (byte[])key.Clone(); k.Key = (byte[])key.Clone(); return k; }

        static void Block(byte[] i, int io, byte[] o, int oo, int size, Func<byte[], byte[]> f)
        {
            byte[] inp = new byte[size];
            Buffer.BlockCopy(i, io, inp, 0, size);
            byte[] r = f(inp);
            Buffer.BlockCopy(r, 0, o, oo, size);
        }

        public override void AesEncrypt(object k, byte[] i, int io, byte[] o, int oo) { Block(i, io, o, oo, 16, delegate (byte[] b) { return ((AesK)k).A.EncryptEcb(b, PaddingMode.None); }); }
        public override void AesDecrypt(object k, byte[] i, int io, byte[] o, int oo) { Block(i, io, o, oo, 16, delegate (byte[] b) { return ((AesK)k).A.DecryptEcb(b, PaddingMode.None); }); }
        public override byte[] Ecb(object k, byte[] data) { return ((AesK)k).A.EncryptEcb(data, PaddingMode.None); }
        public override byte[] Cbc(object k, byte[] iv, byte[] data, bool encrypt) { Aes a = ((AesK)k).A; return encrypt ? a.EncryptCbc(data, iv, PaddingMode.None) : a.DecryptCbc(data, iv, PaddingMode.None); }

        public override byte[] Ctr(object k, byte[] counter, byte[] data)
        {
            int blocks = (data.Length + 15) / 16;
            byte[] ctr = (byte[])counter.Clone(), counters = new byte[blocks * 16];
            for (int b = 0; b < blocks; b++)
            {
                Buffer.BlockCopy(ctr, 0, counters, b * 16, 16);
                for (int i = 15; i >= 0; i--) if (++ctr[i] != 0) break;
            }
            byte[] ks = ((AesK)k).A.EncryptEcb(counters, PaddingMode.None), r = new byte[data.Length];
            for (int i = 0; i < r.Length; i++) r[i] = (byte)(data[i] ^ ks[i]);
            return r;
        }

        public override byte[] GcmSeal(object k, byte[] nonce, byte[] aad, byte[] plain)
        {
            using (AesGcm g = new AesGcm(((AesK)k).Key, 16))
            {
                byte[] r = new byte[plain.Length + 16];
                g.Encrypt(nonce, plain, new Span<byte>(r, 0, plain.Length), new Span<byte>(r, plain.Length, 16), aad);
                return r;
            }
        }

        public override bool GcmOpen(object k, byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain)
        {
            plain = null;
            if (sealedBytes.Length < 16) return false;
            using (AesGcm g = new AesGcm(((AesK)k).Key, 16))
            {
                byte[] p = new byte[sealedBytes.Length - 16];
                try { g.Decrypt(nonce, new ReadOnlySpan<byte>(sealedBytes, 0, p.Length), new ReadOnlySpan<byte>(sealedBytes, p.Length, 16), p, aad); }
                catch (AuthenticationTagMismatchException) { return false; }
                plain = p;
                return true;
            }
        }

        public override byte[] Cmac(object k, byte[] message) { throw new NotSupportedException(); }
        public override bool CmacVerify(object k, byte[] message, byte[] tag) { throw new NotSupportedException(); }

        /// <summary>
        /// A 16-byte key is keying option 2 (K1, K2, K1). Windows CNG throws 0xc100000d on a 16-byte key in EncryptEcb (seen 2026-11-11),
        /// so the referee passes the same key as 24 bytes, K1 K2 K1, which SP 800-67 defines as the same cipher.
        /// </summary>
        public override object NewTdes(byte[] key)
        {
            TripleDES t = TripleDES.Create();
            t.Key = key.Length == 16 ? Hex.Concat(key, Hex.Slice(key, 0, 8)) : (byte[])key.Clone();
            return t;
        }
        public override void TdesEncrypt(object k, byte[] i, int io, byte[] o, int oo) { Block(i, io, o, oo, 8, delegate (byte[] b) { return ((TripleDES)k).EncryptEcb(b, PaddingMode.None); }); }
        public override void TdesDecrypt(object k, byte[] i, int io, byte[] o, int oo) { Block(i, io, o, oo, 8, delegate (byte[] b) { return ((TripleDES)k).DecryptEcb(b, PaddingMode.None); }); }

        /// <summary>Collects the bytes and hashes them one-shot at Finish, so Clone is a copy of the bytes so far.</summary>
        sealed class H : IAoHash
        {
            readonly string _alg; readonly List<byte> _all = new List<byte>();
            public H(string alg) { _alg = alg; }
            public void Update(byte[] b, int off, int n) { for (int i = 0; i < n; i++) _all.Add(b[off + i]); }
            public byte[] Finish()
            {
                byte[] d = _all.ToArray();
                switch (_alg)
                {
                    case "md5": return MD5.HashData(d);
                    case "sha1": return SHA1.HashData(d);
                    case "sha256": return SHA256.HashData(d);
                    case "sha384": return SHA384.HashData(d);
                    case "sha512": return SHA512.HashData(d);
                    case "sha3-256": return SHA3_256.HashData(d);
                    default: return SHA3_512.HashData(d);
                }
            }
            public IAoHash Clone() { H c = new H(_alg); c._all.AddRange(_all); return c; }
        }

        public override IAoHash NewHash(string alg) { return new H(alg); }
        public override byte[] Shake(bool is128, byte[] data, int[] squeezeSizes) { throw new NotSupportedException(); }

        public override byte[] Hmac(string alg, byte[] key, byte[] data)
        {
            RequireHash(alg);
            using (IncrementalHash h = IncrementalHash.CreateHMAC(HashName(alg), key)) { h.AppendData(data); return h.GetHashAndReset(); }
        }

        public override bool HmacVerify(string alg, byte[] key, byte[] data, byte[] tag)
        {
            byte[] mac = Hmac(alg, key, data);
            return tag.Length == mac.Length && CryptographicOperations.FixedTimeEquals(mac, tag);
        }

        public override byte[] HkdfExtract(string alg, byte[] salt, byte[] ikm) { RequireHash(alg); return HKDF.Extract(HashName(alg), ikm, salt); }
        /// <summary>The BCL refuses an output length of 0, which RFC 5869 allows; such a case is skipped for this referee, by count.</summary>
        public override byte[] HkdfExpand(string alg, byte[] prk, byte[] info, int n)
        {
            RequireHash(alg);
            if (n == 0) throw new AoBclSkip();
            return HKDF.Expand(HashName(alg), prk, n, info);
        }

        public override byte[] PrfDerive(byte[] secret, string label, byte[] seed, int count) { throw new NotSupportedException(); }
        public override byte[] PrfMaster(byte[] premaster, byte[] clientRandom, byte[] serverRandom) { throw new NotSupportedException(); }
        public override byte[][] PrfKeyBlock(byte[] master, byte[] clientRandom, byte[] serverRandom) { throw new NotSupportedException(); }
        public override byte[] PrfFinished(byte[] master, string label, byte[] digest) { throw new NotSupportedException(); }
        public override byte[] PrfMd5Sha1(byte[] data) { throw new NotSupportedException(); }
        public override object WalkEncrypt(object k, byte[] block) { throw new NotSupportedException(); }
        public override object WalkDecrypt(object k, byte[] block) { throw new NotSupportedException(); }
        public override object WalkKeyExpansion(object k) { throw new NotSupportedException(); }
        public override object WalkTables(int rconCount) { throw new NotSupportedException(); }
        public override object WalkMixTerms(byte[] before, bool inverse) { throw new NotSupportedException(); }
        public override byte[] DukptInitialKey(byte[] bdk, byte[] initialKeyId) { throw new NotSupportedException(); }
        public override byte[] DukptWorkingKey(byte[] bdk, byte[] ksn, int usage, int type) { throw new NotSupportedException(); }
        public override object NewPinPad(byte[] initialKey, byte[] initialKeyId) { throw new NotSupportedException(); }
        public override byte[][] PinPadNext(object pad, int[] usages, int type) { throw new NotSupportedException(); }
        public override byte[][] PinPadHeld(object pad) { throw new NotSupportedException(); }
        public override byte[] PinEncrypt4(byte[] pinKey, string pin, string pan, byte[] random8) { throw new NotSupportedException(); }
        public override bool PinTryDecrypt4(byte[] pinKey, byte[] block, string pan, out string pin) { throw new NotSupportedException(); }
        public override byte[] PinClearField4(string pin, byte[] random8) { throw new NotSupportedException(); }
        public override bool PinTryOpenField4(byte[] pinKey, byte[] block, string pan, out byte[] field) { throw new NotSupportedException(); }
    }

    /// <summary>A case the BCL cannot run on this OS (HMAC or HKDF over SHA-3). AoDiff counts it as skipped, by name.</summary>
    public sealed class AoBclSkip : AoSkipException { }
}
#endif
