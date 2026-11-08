using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Labs;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// The SHA-256 walk. Referees: FIPS 180-4's published digests, the BCL's SHA256, and a reference written here that derives K and H(0) from their
    /// definitions (FIPS 180-4 sections 4.2.2 and 5.3.3: the fractional parts of cube and square roots of the first primes, by integer roots with no rounding),
    /// pads the message itself, and checks every schedule word and every round. It copies no table from the engine.
    /// </summary>
    public class Sha256WalksTests
    {
        static IEnumerable<int> Primes() { for (int n = 2; ; n++) if (Enumerable.Range(2, Math.Max(0, (int)Math.Sqrt(n) - 1)).All(d => n % d != 0)) yield return n; }

        static BigInteger Root(BigInteger x, int k)
        {
            BigInteger lo = 0, hi = BigInteger.One << (int)(x.ToByteArray().Length * 8 / k + 2);
            while (lo < hi) { BigInteger mid = (lo + hi + 1) / 2; if (BigInteger.Pow(mid, k) <= x) lo = mid; else hi = mid - 1; }
            return lo;
        }

        /// <summary>The first 32 bits of the fractional part of the k-th root of p: floor(root(p * 2^(32k))) mod 2^32.</summary>
        static uint Frac(int p, int k) => (uint)(Root(new BigInteger(p) << (32 * k), k) & uint.MaxValue);

        static readonly uint[] K = Primes().Take(64).Select(p => Frac(p, 3)).ToArray();
        static readonly uint[] H0 = Primes().Take(8).Select(p => Frac(p, 2)).ToArray();

        static uint R(uint x, int n) => (x >> n) | (x << (32 - n));

        [Theory]
        [InlineData("abc", 1, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
        [InlineData("two-block", 2, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")]
        public void Every_block_word_and_round_matches_the_independent_reference(string name, int blocks, string digest)
        {
            Sha256Walk w = Sha256Walks.Fips180(name);
            Assert.Equal(digest, Hex.Encode(w.Digest));
            using (SHA256 bcl = SHA256.Create()) Assert.Equal(digest, Hex.Encode(bcl.ComputeHash(w.Message)));
            Assert.Equal(blocks, w.Blocks.Length);

            // FIPS 180-4 section 5.1.1: the message, 0x80, zeros to 56 mod 64, then the length in bits as 8 big-endian bytes.
            ulong bits = (ulong)w.Message.Length * 8;
            byte[] padded = w.Message.Concat(new byte[] { 0x80 }).Concat(new byte[(119 - w.Message.Length) % 64]).Concat(BitConverter.GetBytes(bits).Reverse()).ToArray();
            Assert.Equal(64 * blocks, padded.Length);

            uint[] h = (uint[])H0.Clone();
            for (int b = 0; b < blocks; b++)
            {
                Sha256WalkBlock block = w.Blocks[b];
                Assert.Equal(Hex.Encode(padded.Skip(64 * b).Take(64).ToArray()), Hex.Encode(block.Bytes));
                Assert.Equal(h, block.HIn);
                uint[] wt = new uint[64];
                for (int t = 0; t < 16; t++) wt[t] = (uint)(padded[64 * b + 4 * t] << 24 | padded[64 * b + 4 * t + 1] << 16 | padded[64 * b + 4 * t + 2] << 8 | padded[64 * b + 4 * t + 3]);
                for (int t = 16; t < 64; t++) wt[t] = (R(wt[t - 2], 17) ^ R(wt[t - 2], 19) ^ (wt[t - 2] >> 10)) + wt[t - 7] + (R(wt[t - 15], 7) ^ R(wt[t - 15], 18) ^ (wt[t - 15] >> 3)) + wt[t - 16];
                Assert.Equal(wt, block.Schedule);

                uint a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
                for (int t = 0; t < 64; t++)
                {
                    uint t1 = hh + (R(e, 6) ^ R(e, 11) ^ R(e, 25)) + ((e & f) ^ (~e & g)) + K[t] + wt[t];
                    uint t2 = (R(a, 2) ^ R(a, 13) ^ R(a, 22)) + ((a & bb) ^ (a & c) ^ (bb & c));
                    hh = g; g = f; f = e; e = d + t1; d = c; c = bb; bb = a; a = t1 + t2;
                    Sha256WalkRound round = block.Rounds[t];
                    Assert.Equal(t, round.T);
                    Assert.Equal(K[t], round.K);
                    Assert.Equal(wt[t], round.W);
                    Assert.Equal(t1, round.T1);
                    Assert.Equal(t2, round.T2);
                    Assert.Equal(new[] { a, bb, c, d, e, f, g, hh }, round.State);
                }
                h = new[] { h[0] + a, h[1] + bb, h[2] + c, h[3] + d, h[4] + e, h[5] + f, h[6] + g, h[7] + hh };
                Assert.Equal(h, block.HOut);
            }
            Assert.Equal(digest, string.Concat(h.Select(x => x.ToString("x8"))));
        }

        [Fact]
        public void An_unknown_name_is_refused_and_the_guard_names_its_code()
        {
            Assert.Throws<ArgumentException>(() => Sha256Walks.Fips180("other"));
            NetSecException e = Assert.Throws<NetSecException>(() => Sha256Walks.Require(false));
            Assert.Equal(ErrorCodes.Sha256WalkDiverged, e.Error.Code);
        }
    }
}
