using System;
using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>
    /// A1: the primitives pass published vectors, on both builds. Every vector is read from a source
    /// named in acceptance/vectors (file header and "# source:" lines). One clause per primitive per build.
    /// The clauses call Subject only. See Subject.Product.cs for the product mapping.
    /// </summary>
    public static class PrimClauses
    {
        static readonly int[] Chunks = new int[] { 0, 1, 7, 64, 65 };

        // ---------------------------------------------------------------- AES

        [Clause("A1.aes-ecb", PerBuild = true)]
        public static string AesEcb(Ctx c)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors("aes-fips197.nsv", "aes-block"))
            {
                byte[] key = r.Bytes("key"), pt = r.Bytes("plaintext"), ct = r.Bytes("ciphertext");
                t.Compare(r.Where + " encrypt", ct, Subject.AesEcb(key, pt, true));
                t.Compare(r.Where + " decrypt", pt, Subject.AesEcb(key, ct, false));
            }
            foreach (VectorRecord r in c.Vectors("aes-modes-sp800-38a.nsv", "aes-ecb"))
            {
                byte[] key = r.Bytes("key"), pt = r.Bytes("plaintext"), ct = r.Bytes("ciphertext");
                t.Compare(r.Where + " encrypt", ct, Subject.AesEcb(key, pt, true));
                t.Compare(r.Where + " decrypt", pt, Subject.AesEcb(key, ct, false));
            }
            return t.Done();
        }

        [Clause("A1.aes-cbc", PerBuild = true)]
        public static string AesCbc(Ctx c)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors("aes-modes-sp800-38a.nsv", "aes-cbc"))
            {
                byte[] key = r.Bytes("key"), iv = r.Bytes("iv"), pt = r.Bytes("plaintext"), ct = r.Bytes("ciphertext");
                t.Compare(r.Where + " encrypt", ct, Subject.AesCbc(key, iv, pt, true));
                t.Compare(r.Where + " decrypt", pt, Subject.AesCbc(key, iv, ct, false));
            }
            return t.Done();
        }

        [Clause("A1.aes-ctr", PerBuild = true)]
        public static string AesCtr(Ctx c)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors("aes-modes-sp800-38a.nsv", "aes-ctr"))
            {
                byte[] key = r.Bytes("key"), ctr = r.Bytes("iv"), pt = r.Bytes("plaintext"), ct = r.Bytes("ciphertext");
                t.Compare(r.Where + " encrypt", ct, Subject.AesCtr(key, ctr, pt));
                t.Compare(r.Where + " decrypt", pt, Subject.AesCtr(key, ctr, ct));
            }
            return t.Done();
        }

        [Clause("A1.aes-gcm", PerBuild = true)]
        public static string AesGcm(Ctx c)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors("gcm-cavp.nsv", "gcm-seal"))
            {
                byte[] key = r.Bytes("key"), iv = r.Bytes("iv"), aad = r.Bytes("aad"), pt = r.Bytes("plaintext"), ct = r.Bytes("ciphertext"), tag = r.Bytes("tag");
                byte[] sealedBytes = Hex.Concat(ct, tag);
                t.Compare(r.Where + " seal", sealedBytes, Subject.GcmSeal(key, iv, aad, pt));
                byte[] opened;
                bool ok = Subject.GcmOpen(key, iv, aad, sealedBytes, out opened);
                t.Expect(r.Where + " open", ok && Hex.Eq(pt, opened), ok ? "plaintext differs" : "open refused a valid message");
                // Control pair: a one-bit change in the tag must be refused.
                byte[] bad = (byte[])sealedBytes.Clone();
                bad[bad.Length - 1] ^= 0x01;
                byte[] ignored;
                t.Expect(r.Where + " tag flip", !Subject.GcmOpen(key, iv, aad, bad, out ignored), "open accepted a message with a flipped tag bit");
            }
            foreach (VectorRecord r in c.Vectors("gcm-cavp.nsv", "gcm-open-fail"))
            {
                byte[] plain;
                bool ok = Subject.GcmOpen(r.Bytes("key"), r.Bytes("iv"), r.Bytes("aad"), Hex.Concat(r.Bytes("ciphertext"), r.Bytes("tag")), out plain);
                t.Expect(r.Where + " published FAIL case", !ok, "open accepted a message NIST marks FAIL");
            }
            return t.Done();
        }

        // ---------------------------------------------------------------- hashes

        static string HashFile(Ctx c, string alg, string file, string group)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors(file, group))
            {
                byte[] msg = r.Has("msg") ? r.Bytes("msg") : Hex.Decode(r.Str("msg_ascii_hex"));
                byte[] digest = r.Bytes("digest");
                foreach (int chunk in Chunks)
                    t.Compare(r.Where + " chunk " + chunk, digest, Subject.Hash(alg, msg, chunk));
            }
            return t.Done();
        }

        [Clause("A1.sha1", PerBuild = true)] public static string Sha1(Ctx c) { return HashFile(c, "sha1", "sha-cavp.nsv", "sha1"); }
        [Clause("A1.sha256", PerBuild = true)] public static string Sha256(Ctx c) { return HashFile(c, "sha256", "sha-cavp.nsv", "sha256"); }
        [Clause("A1.sha384", PerBuild = true)] public static string Sha384(Ctx c) { return HashFile(c, "sha384", "sha-cavp.nsv", "sha384"); }
        [Clause("A1.sha512", PerBuild = true)] public static string Sha512(Ctx c) { return HashFile(c, "sha512", "sha-cavp.nsv", "sha512"); }
        [Clause("A1.sha3-256", PerBuild = true)] public static string Sha3_256(Ctx c) { return HashFile(c, "sha3-256", "sha3-cavp.nsv", "sha3-256"); }
        [Clause("A1.sha3-512", PerBuild = true)] public static string Sha3_512(Ctx c) { return HashFile(c, "sha3-512", "sha3-cavp.nsv", "sha3-512"); }
        [Clause("A1.md5", PerBuild = true)] public static string Md5(Ctx c) { return HashFile(c, "md5", "md5-rfc1321.nsv", "md5"); }

        static string ShakeFile(Ctx c, string alg)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors("sha3-cavp.nsv", alg))
            {
                byte[] msg = r.Bytes("msg"), expected = r.Bytes("output");
                t.Compare(r.Where, expected, Subject.Shake(alg, msg, expected.Length));
            }
            return t.Done();
        }

        [Clause("A1.shake128", PerBuild = true)] public static string Shake128(Ctx c) { return ShakeFile(c, "shake128"); }
        [Clause("A1.shake256", PerBuild = true)] public static string Shake256(Ctx c) { return ShakeFile(c, "shake256"); }

        // ---------------------------------------------------------------- MAC and KDF

        static string HmacFile(Ctx c, string alg, string file, string group)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors(file, group))
            {
                byte[] key = r.Bytes("key"), data = r.Bytes("data"), expected = r.Bytes("mac");
                byte[] actual = Subject.Hmac(alg, key, data);
                if (r.Has("truncated_prefix_bytes"))
                    t.Compare(r.Where + " (truncated)", expected, Hex.Slice(actual, 0, expected.Length));
                else
                    t.Compare(r.Where, expected, actual);
            }
            return t.Done();
        }

        [Clause("A1.hmac-md5", PerBuild = true)] public static string HmacMd5(Ctx c) { return HmacFile(c, "md5", "hmac-rfc2202.nsv", "hmac-md5"); }
        [Clause("A1.hmac-sha1", PerBuild = true)] public static string HmacSha1(Ctx c) { return HmacFile(c, "sha1", "hmac-rfc2202.nsv", "hmac-sha1"); }
        [Clause("A1.hmac-sha256", PerBuild = true)] public static string HmacSha256(Ctx c) { return HmacFile(c, "sha256", "hmac-rfc4231.nsv", "hmac-sha256"); }
        [Clause("A1.hmac-sha384", PerBuild = true)] public static string HmacSha384(Ctx c) { return HmacFile(c, "sha384", "hmac-rfc4231.nsv", "hmac-sha384"); }
        [Clause("A1.hmac-sha512", PerBuild = true)] public static string HmacSha512(Ctx c) { return HmacFile(c, "sha512", "hmac-rfc4231.nsv", "hmac-sha512"); }

        [Clause("A1.cmac", PerBuild = true)]
        public static string Cmac(Ctx c)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors("cmac-rfc4493.nsv", "cmac-aes128"))
                t.Compare(r.Where, r.Bytes("mac"), Subject.Cmac(r.Bytes("key"), r.Bytes("msg")));
            return t.Done();
        }

        static string HkdfFile(Ctx c, string alg, string group)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors("hkdf-rfc5869.nsv", group))
            {
                byte[] prk = Subject.HkdfExtract(alg, r.Bytes("salt"), r.Bytes("ikm"));
                t.Compare(r.Where + " extract", r.Bytes("prk"), prk);
                t.Compare(r.Where + " expand", r.Bytes("okm"), Subject.HkdfExpand(alg, r.Bytes("prk"), r.Bytes("info"), r.Int("length")));
            }
            return t.Done();
        }

        [Clause("A1.hkdf-sha256", PerBuild = true)] public static string HkdfSha256(Ctx c) { return HkdfFile(c, "sha256", "hkdf-sha256"); }
        [Clause("A1.hkdf-sha1", PerBuild = true)] public static string HkdfSha1(Ctx c) { return HkdfFile(c, "sha1", "hkdf-sha1"); }

        // ---------------------------------------------------------------- curves

        [Clause("A1.x25519", PerBuild = true)]
        public static string X25519(Ctx c)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors("x25519-rfc7748.nsv", "x25519-scalarmult"))
                t.Compare(r.Where, r.Bytes("out"), Subject.X25519(r.Bytes("scalar"), r.Bytes("u")));
            foreach (VectorRecord r in c.Vectors("x25519-rfc7748.nsv", "x25519-iterated"))
            {
                byte[] k = r.Bytes("k_start"), u = r.Bytes("u_start");
                int n = r.Int("iterations");
                for (int i = 0; i < n; i++)
                {
                    byte[] next = Subject.X25519(k, u);
                    u = k;
                    k = next;
                }
                t.Compare(r.Where + " after " + n, r.Bytes("out"), k);
            }
            foreach (VectorRecord r in c.Vectors("x25519-rfc7748.nsv", "x25519-dh"))
            {
                byte[] a = r.Bytes("a"), b = r.Bytes("b");
                byte[] aPub = Subject.X25519Base(a), bPub = Subject.X25519Base(b);
                t.Compare(r.Where + " Alice public", r.Bytes("a_pub"), aPub);
                t.Compare(r.Where + " Bob public", r.Bytes("b_pub"), bPub);
                t.Compare(r.Where + " Alice shared", r.Bytes("k"), Subject.X25519(a, bPub));
                t.Compare(r.Where + " Bob shared", r.Bytes("k"), Subject.X25519(b, aPub));
            }
            return t.Done();
        }

        [Clause("A1.ed25519", PerBuild = true)]
        public static string Ed25519(Ctx c)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors("ed25519-rfc8032.nsv", "ed25519"))
            {
                byte[] seed = r.Bytes("seed"), pub = r.Bytes("public"), msg = r.Bytes("message"), sig = r.Bytes("signature");
                t.Compare(r.Where + " public key", pub, Subject.Ed25519Public(seed));
                t.Compare(r.Where + " signature", sig, Subject.Ed25519Sign(seed, msg));
                t.Expect(r.Where + " verify", Subject.Ed25519Verify(pub, msg, sig), "verify refused a published signature");
                byte[] badSig = (byte[])sig.Clone();
                badSig[10] ^= 0x01;
                t.Expect(r.Where + " flipped signature", !Subject.Ed25519Verify(pub, msg, badSig), "verify accepted a signature with a flipped bit");
                byte[] badMsg = msg.Length == 0 ? new byte[] { 0x00 } : (byte[])msg.Clone();
                if (msg.Length > 0) badMsg[0] ^= 0x01;
                t.Expect(r.Where + " altered message", !Subject.Ed25519Verify(pub, badMsg, sig), "verify accepted a signature over a different message");
            }
            return t.Done();
        }

        // ---------------------------------------------------------------- RSA, TDES, DH

        [Clause("A1.rsa", PerBuild = true)]
        public static string Rsa(Ctx c)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors("rsa-openssl.nsv", "rsa-sign"))
            {
                byte[] n = r.Bytes("n"), e = r.Bytes("e"), d = r.Bytes("d"), msg = r.Bytes("message"), sig = r.Bytes("signature");
                string hash = r.Str("hash");
                t.Expect(r.Where + " verify " + hash, Subject.RsaVerify(hash, n, e, msg, sig), "verify refused an OpenSSL signature");
                byte[] badMsg = (byte[])msg.Clone();
                badMsg[0] ^= 0x01;
                t.Expect(r.Where + " altered message " + hash, !Subject.RsaVerify(hash, n, e, badMsg, sig), "verify accepted a signature over a different message");
                if (hash == "sha1") t.Compare(r.Where + " sign sha1", sig, Subject.RsaSignSha1(n, d, msg));
                byte[] em = Subject.RsaRaw(n, e, sig);
                byte[] stripped = StripZeros(em);
                t.Expect(r.Where + " raw public op yields a type 1 block", stripped.Length == n.Length - 1 && stripped[0] == 0x01,
                         "m^e mod n of a signature is " + stripped.Length + " bytes and starts " + Hex.Short(stripped) + "; PKCS#1 type 1 needs 00 01 ff..");
            }
            foreach (VectorRecord r in c.Vectors("rsa-openssl.nsv", "rsa-decrypt"))
            {
                byte[] n = r.Bytes("n"), e = r.Bytes("e"), d = r.Bytes("d"), ct = r.Bytes("ciphertext"), pt = r.Bytes("plaintext");
                byte[] got;
                bool ok = Subject.RsaDecrypt(n, d, ct, out got);
                t.Expect(r.Where + " decrypt", ok && Hex.Eq(pt, got), ok ? "plaintext differs" : "decrypt refused an OpenSSL ciphertext");
                // Our own encryption must decrypt back (the padding bytes come from the seed, never zero).
                byte[] mine = Subject.RsaEncrypt(n, e, pt, new byte[] { 0x5a, 0xc3, 0x17, 0xe1, 0x99 });
                byte[] back;
                bool ok2 = Subject.RsaDecrypt(n, d, mine, out back);
                t.Expect(r.Where + " encrypt then decrypt", ok2 && Hex.Eq(pt, back), "round trip through our own encrypt failed");
                t.Expect(r.Where + " ciphertext length", mine.Length == n.Length, "ciphertext is " + mine.Length + " bytes, modulus is " + n.Length);
            }
            return t.Done();
        }

        [Clause("A1.tdes", PerBuild = true)]
        public static string Tdes(Ctx c)
        {
            Tally t = new Tally();
            foreach (string g in new string[] { "tdes-ecb-encrypt-kat", "tdes-ecb-encrypt-mmt" })
                foreach (VectorRecord r in c.Vectors("tdes-cavp.nsv", g))
                    t.Compare(r.Where + " encrypt", r.Bytes("ciphertext"), Subject.Tdes(r.Bytes("key"), r.Bytes("plaintext"), true));
            foreach (string g in new string[] { "tdes-ecb-decrypt-kat", "tdes-ecb-decrypt-mmt" })
                foreach (VectorRecord r in c.Vectors("tdes-cavp.nsv", g))
                    t.Compare(r.Where + " decrypt", r.Bytes("plaintext"), Subject.Tdes(r.Bytes("key"), r.Bytes("ciphertext"), false));
            return t.Done();
        }

        [Clause("A1.dh-group14", PerBuild = true)]
        public static string DhGroup14(Ctx c)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors("dh-group14-openssl.nsv", "dh-group14"))
            {
                byte[] x = r.Bytes("x_a"), yA = r.Bytes("y_a"), yB = r.Bytes("y_b"), shared = r.Bytes("shared");
                t.Compare(r.Where + " public value", yA, Subject.Dh14Public(x));
                t.Compare(r.Where + " shared secret", shared, Subject.Dh14Shared(x, yB));
            }
            // Peer value outside [2, p-2] must be refused (program design section 4, item 4). Control first.
            VectorRecord one = c.Vectors("dh-group14-openssl.nsv", "dh-group14")[0];
            byte[] ctlX = one.Bytes("x_a");
            Subject.Dh14Shared(ctlX, one.Bytes("y_b"));
            byte[] p = Hex.Decode(c.Vectors("dh-group14-rfc3526.nsv", "dh-group14-params")[0].Str("p"));
            byte[] pMinus1 = (byte[])p.Clone();
            pMinus1[pMinus1.Length - 1] -= 1;
            foreach (byte[] bad in new byte[][] { new byte[] { 0 }, new byte[] { 1 }, pMinus1 })
            {
                bool refused = false;
                try { Subject.Dh14Shared(ctlX, PadTo(bad, 256)); } catch (Exception) { refused = true; }
                t.Expect("peer value " + Hex.Short(bad), refused, "Shared accepted a peer value of 0, 1 or p-1");
            }
            return t.Done();
        }

        static byte[] StripZeros(byte[] b)
        {
            int i = 0;
            while (i < b.Length - 1 && b[i] == 0) i++;
            return Hex.Slice(b, i, b.Length - i);
        }

        static byte[] PadTo(byte[] b, int n)
        {
            if (b.Length >= n) return b;
            byte[] r = new byte[n];
            Array.Copy(b, 0, r, n - b.Length, b.Length);
            return r;
        }
    }
}
