using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// The SHA-256 walk (docs/sections-plan.md section 4, slice P6): GET /api/walk/sha256?name=abc|two-block, on FIPS 180-4's published
    /// examples. There is no key, so it stays open with Show keys OFF. The anchors are FIPS 180-4's own definitions, run here: the initial hash
    /// and the 64 round constants are derived from the square and cube roots of the first primes (section 4.2.2 and 5.3.3), and the padding,
    /// the message schedule and every round follow sections 5.1.1 and 6.2.2. .NET's SHA256 checks the digest a second way. The two-block
    /// message is FIPS 180-4's "abcdbcde...nopq", built here from its rule (four letters starting at a, b, c, up to n).
    /// </summary>
    public static class Sha256WalkClauses
    {
        public const string Path = "/api/walk/sha256";

        // ---------------------------------------------------------------- FIPS 180-4, run here

        static BigInteger IntRoot(BigInteger v, int n)
        {
            // Newton's method for the floor of the n-th root, on whole numbers only.
            if (v.IsZero) return 0;
            BigInteger x = BigInteger.One << (int)((v.GetBitLength() + n - 1) / n);
            while (true)
            {
                BigInteger y = ((n - 1) * x + v / BigInteger.Pow(x, n - 1)) / n;
                if (y >= x) return x;
                x = y;
            }
        }

        static List<int> Primes(int count)
        {
            List<int> p = new List<int>();
            for (int c = 2; p.Count < count; c++) { bool prime = true; foreach (int q in p) { if (q * q > c) break; if (c % q == 0) { prime = false; break; } } if (prime) p.Add(c); }
            return p;
        }

        /// <summary>The first 32 bits of the fractional part of the n-th root of p: floor(root(p * 2^(32 n))) mod 2^32.</summary>
        static uint FracRoot(int p, int n) { return (uint)(IntRoot(new BigInteger(p) << (32 * n), n) & uint.MaxValue); }

        /// <summary>Section 5.3.3: H(0) from the square roots of the first 8 primes.</summary>
        public static uint[] H0() { List<int> p = Primes(8); uint[] h = new uint[8]; for (int i = 0; i < 8; i++) h[i] = FracRoot(p[i], 2); return h; }

        /// <summary>Section 4.2.2: K from the cube roots of the first 64 primes.</summary>
        public static uint[] K() { List<int> p = Primes(64); uint[] k = new uint[64]; for (int i = 0; i < 64; i++) k[i] = FracRoot(p[i], 3); return k; }

        static uint Rotr(uint x, int n) { return (x >> n) | (x << (32 - n)); }

        /// <summary>Section 5.1.1: the message, a 1 bit, zeros, and the 64-bit length, in 64-byte blocks.</summary>
        public static List<byte[]> Pad(byte[] msg)
        {
            int total = ((msg.Length + 8) / 64 + 1) * 64;
            byte[] all = new byte[total];
            Array.Copy(msg, all, msg.Length);
            all[msg.Length] = 0x80;
            ulong bits = (ulong)msg.Length * 8;
            for (int i = 0; i < 8; i++) all[total - 1 - i] = (byte)(bits >> (8 * i));
            List<byte[]> blocks = new List<byte[]>();
            for (int o = 0; o < total; o += 64) { byte[] b = new byte[64]; Array.Copy(all, o, b, 0, 64); blocks.Add(b); }
            return blocks;
        }

        public sealed class Round { public uint W, T1, T2; public uint[] State; }

        /// <summary>Section 6.2.2: one block. Returns the 64-word schedule, the state after each round, and H out.</summary>
        public static uint[] Compress(uint[] hIn, byte[] block, out uint[] schedule, out List<Round> rounds)
        {
            uint[] k = K(), w = new uint[64];
            for (int t = 0; t < 16; t++) w[t] = (uint)(block[4 * t] << 24 | block[4 * t + 1] << 16 | block[4 * t + 2] << 8 | block[4 * t + 3]);
            for (int t = 16; t < 64; t++)
            {
                uint s0 = Rotr(w[t - 15], 7) ^ Rotr(w[t - 15], 18) ^ (w[t - 15] >> 3), s1 = Rotr(w[t - 2], 17) ^ Rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
                w[t] = unchecked(s1 + w[t - 7] + s0 + w[t - 16]);
            }
            uint a = hIn[0], b = hIn[1], c = hIn[2], d = hIn[3], e = hIn[4], f = hIn[5], g = hIn[6], h = hIn[7];
            rounds = new List<Round>();
            for (int t = 0; t < 64; t++)
            {
                uint t1 = unchecked(h + (Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25)) + ((e & f) ^ (~e & g)) + k[t] + w[t]);
                uint t2 = unchecked((Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c)));
                h = g; g = f; f = e; e = unchecked(d + t1); d = c; c = b; b = a; a = unchecked(t1 + t2);
                rounds.Add(new Round { W = w[t], T1 = t1, T2 = t2, State = new uint[] { a, b, c, d, e, f, g, h } });
            }
            schedule = w;
            return new uint[] { unchecked(hIn[0] + a), unchecked(hIn[1] + b), unchecked(hIn[2] + c), unchecked(hIn[3] + d), unchecked(hIn[4] + e), unchecked(hIn[5] + f), unchecked(hIn[6] + g), unchecked(hIn[7] + h) };
        }

        /// <summary>FIPS 180-4's two examples: "abc", and the 56 letters made of "abcd", "bcde", ... "nopq".</summary>
        public static byte[] Message(string name)
        {
            if (name == "abc") return Encoding.ASCII.GetBytes("abc");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 14; i++) for (int j = 0; j < 4; j++) sb.Append((char)('a' + i + j));
            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        public static string W8(uint v) { return v.ToString("x8"); }

        static void SameWords(string where, uint[] want, List<object> got)
        {
            Check.True(got != null && got.Count == want.Length, where + ": " + (got == null ? 0 : got.Count) + " words, and FIPS 180-4 gives " + want.Length);
            for (int i = 0; i < want.Length; i++) Check.Equal(where + "[" + i + "]", W8(want[i]), (Convert.ToString(got[i]) ?? "").ToLowerInvariant());
        }

        [Clause("A19.host.sha256-walk-open-and-fips180")]
        public static string WalkOpenAndFips180(Ctx c)
        {
            using (HostProc h = A17.Host(c, "walk-sha256"))
            {
                Reply off = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", false));
                Check.True(off.Ok, "PUT show-keys got " + off);
                int roundsChecked = 0;
                foreach (string name in new string[] { "abc", "two-block" })
                {
                    Reply r = HostHttp.Get(h, Path + "?name=" + name);
                    if (r.Status == 404 && string.IsNullOrEmpty(r.Code)) throw new NotRunException("PRODUCT_MISSING", "the Host has no route " + Path + " yet (slice P6)");
                    Check.True(r.Ok && r.Json != null, "OFF: " + name + " got " + r + ". The walk has no key, so it stays open");
                    Check.True((r.CacheControl ?? "").IndexOf("no-store", StringComparison.OrdinalIgnoreCase) >= 0, name + ": Cache-Control is '" + r.CacheControl + "', and a walk reply carries no-store");
                    byte[] msg = Message(name);
                    string shownMsg = MiniJson.Str(r.Json, "message") ?? "";
                    Check.True(shownMsg == Encoding.ASCII.GetString(msg) || shownMsg.ToLowerInvariant() == Hex.Encode(msg).ToLowerInvariant(), name + ": message is '" + shownMsg + "', and FIPS 180-4's example is '" + Encoding.ASCII.GetString(msg) + "'");
                    string bcl;
                    using (SHA256 sha = SHA256.Create()) bcl = Hex.Encode(sha.ComputeHash(msg)).ToLowerInvariant();
                    Check.Equal(name + ": digest equals .NET's SHA-256 of the message", bcl, (MiniJson.Str(r.Json, "digest") ?? "").ToLowerInvariant());
                    List<byte[]> blocks = Pad(msg);
                    List<object> shown = MiniJson.Arr(r.Json, "blocks") ?? new List<object>();
                    Check.True(shown.Count == blocks.Count, name + ": " + shown.Count + " blocks, and the padded message has " + blocks.Count);
                    uint[] hv = H0();
                    for (int i = 0; i < blocks.Count; i++)
                    {
                        string where = name + " block " + i;
                        Dictionary<string, object> b = MiniJson.AsObject(shown[i]);
                        Check.Equal(where + ": bytes (section 5.1.1 padding)", Hex.Encode(blocks[i]).ToLowerInvariant(), (MiniJson.Str(b, "bytes") ?? "").ToLowerInvariant());
                        SameWords(where + " hIn", hv, MiniJson.Arr(b, "hIn"));
                        uint[] schedule; List<Round> rounds;
                        uint[] hOut = Compress(hv, blocks[i], out schedule, out rounds);
                        SameWords(where + " schedule", schedule, MiniJson.Arr(b, "schedule"));
                        List<object> shownRounds = MiniJson.Arr(b, "rounds") ?? new List<object>();
                        Check.True(shownRounds.Count == 64, where + ": " + shownRounds.Count + " rounds, and SHA-256 has 64");
                        uint[] k = K();
                        for (int t = 0; t < 64; t++)
                        {
                            Dictionary<string, object> row = MiniJson.AsObject(shownRounds[t]);
                            string rw = where + " round " + t;
                            Check.True((int)MiniJson.Num(row, "t", -1) == t, rw + ": t");
                            Check.Equal(rw + ": k (the cube root of prime " + t + ")", W8(k[t]), (MiniJson.Str(row, "k") ?? "").ToLowerInvariant());
                            Check.Equal(rw + ": w", W8(rounds[t].W), (MiniJson.Str(row, "w") ?? "").ToLowerInvariant());
                            Check.Equal(rw + ": t1", W8(rounds[t].T1), (MiniJson.Str(row, "t1") ?? "").ToLowerInvariant());
                            Check.Equal(rw + ": t2", W8(rounds[t].T2), (MiniJson.Str(row, "t2") ?? "").ToLowerInvariant());
                            SameWords(rw + " state", rounds[t].State, MiniJson.Arr(row, "state"));
                            roundsChecked++;
                        }
                        SameWords(where + " hOut", hOut, MiniJson.Arr(b, "hOut"));
                        hv = hOut;
                    }
                    StringBuilder joined = new StringBuilder();
                    foreach (uint v in hv) joined.Append(W8(v));
                    Check.Equal(name + ": the last block's hOut joined is the digest", bcl, joined.ToString());
                }
                Reply bad = HostHttp.Get(h, Path + "?name=nope");
                Check.True(bad.Status == 400 && bad.Code == "WALK_BAD_ARGUMENT", "an unknown name should get 400 WALK_BAD_ARGUMENT, and got " + bad);
                HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", true));
                return "with Show keys OFF both FIPS 180-4 examples answer: the digest equals .NET's, the padding, H(0), every schedule word and all " + roundsChecked + " rounds follow FIPS 180-4 run in the suite, and an unknown name gets 400";
            }
        }
    }
}
