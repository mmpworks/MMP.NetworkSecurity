using System;
using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>
    /// A2: random inputs against the .NET 10 BCL, reached through the oracle in acceptance/referees/bcl (JSON lines on stdin and stdout).
    /// Both builds use the oracle, so the CF build on net48 reaches MLKem and AesGcm with no skip.
    /// The oracle has no CTR, so CTR is checked through the oracle's ECB: the suite builds the counter blocks.
    /// The input stream is seeded, so a failing round reproduces.
    /// </summary>
    public static class RandomClauses
    {
        const int Rounds = 10000;
        const int KemRounds = 200;

        static void Same(Tally t, string where, byte[] expected, byte[] actual) { t.Compare(where, expected, actual); }

        static byte[] CtrViaOracle(BclOracle o, byte[] key, byte[] counter, byte[] data)
        {
            int blocks = (data.Length + 15) / 16;
            byte[] ctr = (byte[])counter.Clone();
            byte[] counters = new byte[blocks * 16];
            for (int b = 0; b < blocks; b++)
            {
                Array.Copy(ctr, 0, counters, b * 16, 16);
                for (int i = 15; i >= 0; i--) { if (++ctr[i] != 0) break; }
            }
            byte[] ks = blocks == 0 ? new byte[0] : o.Bytes("output", "aes-ecb-encrypt", "key", key, "data", counters, "padding", "none");
            byte[] r = new byte[data.Length];
            for (int i = 0; i < r.Length; i++) r[i] = (byte)(data[i] ^ ks[i]);
            return r;
        }

        [Clause("A2.aes", PerBuild = true)]
        public static string Aes(Ctx c)
        {
            using (BclOracle o = BclOracle.Start(c))
            {
                Rng rng = new Rng(0xA2AE5);
                Tally t = new Tally();
                int[] keyLens = new int[] { 16, 24, 32 };
                for (int i = 0; i < Rounds; i++)
                {
                    byte[] key = rng.Bytes(keyLens[rng.Int(3)]);
                    byte[] data = rng.Bytes(16 * (1 + rng.Int(8)));
                    string where = "round " + i;
                    switch (i % 3)
                    {
                        case 0:
                            Same(t, where + " ecb enc", o.Bytes("output", "aes-ecb-encrypt", "key", key, "data", data, "padding", "none"), Subject.AesEcb(key, data, true));
                            Same(t, where + " ecb dec", o.Bytes("output", "aes-ecb-decrypt", "key", key, "data", data, "padding", "none"), Subject.AesEcb(key, data, false));
                            break;
                        case 1:
                            byte[] iv = rng.Bytes(16);
                            Same(t, where + " cbc enc", o.Bytes("output", "aes-cbc-encrypt", "key", key, "iv", iv, "data", data, "padding", "none"), Subject.AesCbc(key, iv, data, true));
                            Same(t, where + " cbc dec", o.Bytes("output", "aes-cbc-decrypt", "key", key, "iv", iv, "data", data, "padding", "none"), Subject.AesCbc(key, iv, data, false));
                            break;
                        default:
                            byte[] ctr = rng.Bytes(16);
                            if (i % 7 == 0) { for (int k = 8; k < 16; k++) ctr[k] = 0xff; }      // force counter carry
                            byte[] odd = Hex.Slice(data, 0, data.Length - rng.Int(16));
                            Same(t, where + " ctr", CtrViaOracle(o, key, ctr, odd), Subject.AesCtr(key, ctr, odd));
                            break;
                    }
                }
                return t.Done();
            }
        }

        [Clause("A2.hmac", PerBuild = true)]
        public static string Hmac(Ctx c)
        {
            using (BclOracle o = BclOracle.Start(c))
            {
                Rng rng = new Rng(0xA2412AC);
                Tally t = new Tally();
                string[] algs = new string[] { "sha256", "sha384", "sha512" };
                for (int i = 0; i < Rounds; i++)
                {
                    string alg = algs[i % 3];
                    byte[] key = rng.Bytes(rng.Int(200));         // spans the block size, so long keys hash first
                    byte[] data = rng.Bytes(rng.Int(300));
                    Same(t, "round " + i + " " + alg, o.Bytes("mac", "hmac", "alg", alg, "key", key, "data", data), Subject.Hmac(alg, key, data));
                }
                return t.Done();
            }
        }

        [Clause("A2.hkdf", PerBuild = true)]
        public static string Hkdf(Ctx c)
        {
            using (BclOracle o = BclOracle.Start(c))
            {
                Rng rng = new Rng(0xA2D4DF);
                Tally t = new Tally();
                string[] algs = new string[] { "sha256", "sha384", "sha512" };
                for (int i = 0; i < Rounds; i++)
                {
                    string alg = algs[i % 3];
                    byte[] ikm = rng.Bytes(1 + rng.Int(64)), salt = rng.Bytes(rng.Int(64)), info = rng.Bytes(rng.Int(64));
                    int len = 1 + rng.Int(200);
                    byte[] expected = o.Bytes("okm", "hkdf", "alg", alg, "ikm", ikm, "length", len, "salt", salt, "info", info);
                    byte[] prk = Subject.HkdfExtract(alg, salt, ikm);
                    Same(t, "round " + i + " " + alg, expected, Subject.HkdfExpand(alg, prk, info, len));
                }
                return t.Done();
            }
        }

        [Clause("A2.gcm", PerBuild = true)]
        public static string Gcm(Ctx c)
        {
            using (BclOracle o = BclOracle.Start(c))
            {
                Rng rng = new Rng(0xA26C3);
                Tally t = new Tally();
                for (int i = 0; i < Rounds; i++)
                {
                    byte[] key = rng.Bytes(i % 2 == 0 ? 16 : 32), nonce = rng.Bytes(12), aad = rng.Bytes(rng.Int(64)), pt = rng.Bytes(rng.Int(200));
                    string where = "round " + i;
                    byte[] ct = o.Bytes("output", "aes-gcm-encrypt", "key", key, "nonce", nonce, "data", pt, "aad", aad, "tagLength", 16);
                    byte[] tag = o.Bytes("tag", "aes-gcm-encrypt", "key", key, "nonce", nonce, "data", pt, "aad", aad, "tagLength", 16);
                    byte[] expected = Hex.Concat(ct, tag);
                    Same(t, where + " seal", expected, Subject.GcmSeal(key, nonce, aad, pt));
                    byte[] opened;
                    bool ok = Subject.GcmOpen(key, nonce, aad, expected, out opened);
                    t.Expect(where + " open of BCL output", ok && Hex.Eq(pt, opened), "we could not open what the BCL sealed");
                    if (i % 10 == 0)
                    {
                        byte[] bad = (byte[])expected.Clone();
                        bad[rng.Int(bad.Length)] ^= (byte)(1 << rng.Int(8));
                        byte[] ignored;
                        t.Expect(where + " tampered", !Subject.GcmOpen(key, nonce, aad, bad, out ignored), "we opened a tampered message");
                    }
                }
                return t.Done();
            }
        }

        /// <summary>A18, matrix row 29: RSA PKCS#1 v1.5 had no BCL comparison. Signatures and encryption run both ways against the .NET library, on keys the library made. A clause on key format alone would not show this.</summary>
        [Clause("A2.rsa.pkcs1", PerBuild = true)]
        public static string RsaPkcs1(Ctx c)
        {
            const int Keys = 3, RoundsPerKey = 30;
            using (BclOracle o = BclOracle.Start(c))
            {
                Rng rng = new Rng(0xA2A5A);
                Tally t = new Tally();
                for (int k = 0; k < Keys; k++)
                {
                    RsaKeyParts key = RsaKeyParts.Generate(o);
                    byte[] n = key.N;
                    for (int i = 0; i < RoundsPerKey; i++)
                    {
                        string where = "key " + k + " round " + i;
                        byte[] msg = rng.Bytes(1 + i % 64);
                        byte[] bad = (byte[])msg.Clone();
                        bad[0] ^= 0x01;
                        foreach (string hash in new string[] { "sha1", "sha256" })
                        {
                            byte[] sig = key.Call(o, "rsa-sign", "alg", hash, "data", msg);
                            t.Expect(where + " " + hash + " verify a BCL signature", Subject.RsaVerify(hash, n, key.E, msg, sig), "refused a BCL signature");
                            t.Expect(where + " " + hash + " altered message", !Subject.RsaVerify(hash, n, key.E, bad, sig), "accepted a BCL signature on another message");
                        }
                        byte[] ours = Subject.RsaSignSha1(n, key.D, msg);
                        t.Expect(where + " BCL verifies our signature", key.Call(o, "rsa-verify", "alg", "sha1", "data", msg, "signature", ours)[0] == 1, "the BCL refused our SHA-1 signature");
                        byte[] plain = rng.Bytes(1 + i % 100), back;
                        byte[] cipher = key.Call(o, "rsa-encrypt", "data", plain);
                        t.Expect(where + " decrypt BCL ciphertext", Subject.RsaDecrypt(n, key.D, cipher, out back), "refused a BCL ciphertext");
                        t.Compare(where + " BCL ciphertext gives the text", plain, back);
                        t.Compare(where + " BCL decrypts our ciphertext", plain, key.Call(o, "rsa-decrypt", "data", Subject.RsaEncrypt(n, key.E, plain, rng.Bytes(512))));
                    }
                }
                return t.Done();
            }
        }

        /// <summary>One RSA key from the oracle. It keeps every field, because each oracle call imports the whole key.</summary>
        sealed class RsaKeyParts
        {
            public byte[] N, E, D;
            System.Collections.Generic.Dictionary<string, object> _fields;

            public static RsaKeyParts Generate(BclOracle o)
            {
                System.Collections.Generic.Dictionary<string, object> f = o.Request("rsa-keygen", "bits", 2048);
                RsaKeyParts k = new RsaKeyParts();
                k._fields = f;
                k.N = Hex.Decode(MiniJson.Str(f, "n")); k.E = Hex.Decode(MiniJson.Str(f, "e")); k.D = Hex.Decode(MiniJson.Str(f, "d"));
                return k;
            }

            public byte[] Call(BclOracle o, string op, params object[] args)
            {
                System.Collections.Generic.List<object> all = new System.Collections.Generic.List<object>(args);
                foreach (string name in new string[] { "n", "e", "d", "p", "q", "dp", "dq", "qi" }) { all.Add(name); all.Add(Hex.Decode(MiniJson.Str(_fields, name))); }
                return o.Bytes("output", op, all.ToArray());
            }
        }

        [Clause("A2.mlkem768.ours-encaps-bcl-decaps", PerBuild = true)]
        public static string KemOursEncaps(Ctx c)
        {
            using (BclOracle o = BclOracle.Start(c))
            {
                Rng rng = new Rng(0xA24E1);
                Tally t = new Tally();
                for (int i = 0; i < KemRounds; i++)
                {
                    byte[] seed = rng.Bytes(64);
                    byte[] ek = o.Bytes("ek", "mlkem768-keygen", "seed", seed);
                    byte[] dk = o.Bytes("dk", "mlkem768-keygen", "seed", seed);
                    byte[] ct, ss;
                    Subject.MlKemEncaps(ek, rng.Bytes(32), out ct, out ss);
                    t.Expect("round " + i + " sizes", ct.Length == 1088 && ss.Length == 32, "ciphertext " + ct.Length + " bytes, secret " + ss.Length + " bytes");
                    t.Compare("round " + i + " BCL decapsulates our ciphertext", ss, o.Bytes("secret", "mlkem768-decaps", "dk", dk, "ciphertext", ct));
                }
                return t.Done();
            }
        }

        [Clause("A2.mlkem768.bcl-encaps-ours-decaps", PerBuild = true)]
        public static string KemOursDecaps(Ctx c)
        {
            using (BclOracle o = BclOracle.Start(c))
            {
                Rng rng = new Rng(0xA24E2);
                Tally t = new Tally();
                for (int i = 0; i < KemRounds; i++)
                {
                    byte[] ek, dk;
                    Subject.MlKemKeyGen(rng.Bytes(32), rng.Bytes(32), out ek, out dk);
                    t.Expect("round " + i + " key sizes", ek.Length == 1184 && dk.Length == 2400, "ek " + ek.Length + " bytes, dk " + dk.Length + " bytes");
                    Dictionary<string, object> r = o.Request("mlkem768-encaps", "ek", ek);
                    Check.True(r.ContainsKey("ok") && r["ok"] is bool && (bool)r["ok"], "the BCL refused our encapsulation key: " + (MiniJson.Str(r, "error") ?? MiniJson.Str(r, "code")));
                    byte[] ct = Hex.Decode(MiniJson.Str(r, "ciphertext")), theirs = Hex.Decode(MiniJson.Str(r, "secret"));
                    t.Compare("round " + i + " we decapsulate BCL ciphertext", theirs, Subject.MlKemDecaps(dk, ct));
                }
                return t.Done();
            }
        }
    }
}
