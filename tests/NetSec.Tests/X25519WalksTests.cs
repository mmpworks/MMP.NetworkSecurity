using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Labs;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// Slice P8's X25519 ladder walk. Two referees: RFC 7748 section 6.1's published values, read from acceptance/vectors/x25519-rfc7748.nsv, and an
    /// independent ladder written here with System.Numerics.BigInteger from RFC 7748 section 5's formulas. That ladder shares no code with Fe25519,
    /// and it checks every row's affine u-coordinates.
    /// </summary>
    public class X25519WalksTests
    {
        static readonly BigInteger P = BigInteger.Pow(2, 255) - 19, A = 486662;

        static Dictionary<string, string> DhVectors()
        {
            string dir = AppContext.BaseDirectory;
            while (dir != null && !File.Exists(Path.Combine(dir, "acceptance", "vectors", "x25519-rfc7748.nsv"))) dir = Path.GetDirectoryName(dir);
            Assert.True(dir != null, "acceptance/vectors/x25519-rfc7748.nsv was not found above the test folder");
            Dictionary<string, string> v = new Dictionary<string, string>();
            bool inDh = false;
            foreach (string raw in File.ReadAllLines(Path.Combine(dir, "acceptance", "vectors", "x25519-rfc7748.nsv")))
            {
                string line = raw.Trim();
                if (line.StartsWith("[")) inDh = line == "[x25519-dh]";
                else if (inDh && line.Contains("=") && !line.StartsWith("#")) v[line.Substring(0, line.IndexOf('=')).Trim()] = line.Substring(line.IndexOf('=') + 1).Trim();
            }
            return v;
        }

        /// <summary>Little-endian bytes to a number, as RFC 7748 decodes u and the scalar.</summary>
        static BigInteger Le(byte[] b) { return new BigInteger(b.Concat(new byte[] { 0 }).ToArray()); }

        static BigInteger Mod(BigInteger x) { BigInteger r = x % P; return r < 0 ? r + P : r; }

        static BigInteger Affine(BigInteger x, BigInteger z) { return Mod(x * BigInteger.ModPow(z, P - 2, P)); }

        /// <summary>
        /// RFC 7748 section 5's x-only formulas, in the order the walk reports: after each bit, R0 is the running multiple and R1 = R0 + u.
        /// Returns the affine (u0, u1) after each bit, top bit first; null marks z = 0.
        /// </summary>
        static List<(BigInteger? U0, BigInteger? U1)> ReferenceLadder(byte[] clamped, BigInteger u)
        {
            BigInteger k = Le(clamped), x0 = 1, z0 = 0, x1 = u, z1 = 1;
            var rows = new List<(BigInteger?, BigInteger?)>();
            for (int i = 254; i >= 0; i--)
            {
                bool one = ((k >> i) & 1) == 1;
                // Differential add of R0 and R1 (their difference is u), and a doubling of the one the bit picks.
                BigInteger ax = Mod(BigInteger.Pow(x0 * x1 - z0 * z1, 2)), az = Mod(u * BigInteger.Pow(x0 * z1 - z0 * x1, 2));
                BigInteger dx0 = one ? x1 : x0, dz0 = one ? z1 : z0;
                BigInteger t = Mod(dx0 * dz0);
                BigInteger dx = Mod(BigInteger.Pow(dx0 * dx0 - dz0 * dz0, 2)), dz = Mod(4 * t * (dx0 * dx0 + A * t + dz0 * dz0));
                if (one) { x0 = ax; z0 = az; x1 = dx; z1 = dz; } else { x0 = dx; z0 = dz; x1 = ax; z1 = az; }
                rows.Add((z0.IsZero ? null : Affine(x0, z0), z1.IsZero ? null : Affine(x1, z1)));
            }
            return rows;
        }

        static void CheckAgainstReference(X25519Walk w)
        {
            Assert.Equal(255, w.Rows.Length);
            Assert.Equal(Enumerable.Range(0, 255).Select(i => 254 - i), w.Rows.Select(r => r.Bit));
            BigInteger u = Le(w.Point) & ((BigInteger.One << 255) - 1);
            var reference = ReferenceLadder(w.Clamped, u);
            for (int i = 0; i < 255; i++)
            {
                X25519LadderRow row = w.Rows[i];
                Assert.Equal(((Le(w.Clamped) >> row.Bit) & 1) == 1, row.IsOne);
                Assert.Equal(reference[i].U0, row.U2 == null ? (BigInteger?)null : Le(row.U2));
                Assert.Equal(reference[i].U1, row.U3 == null ? (BigInteger?)null : Le(row.U3));
            }
            Assert.Equal(reference[254].U0, Le(w.Result));
        }

        [Fact]
        public void Alice_and_Bob_public_values_match_rfc_7748_and_every_row_matches_the_reference_ladder()
        {
            Dictionary<string, string> v = DhVectors();
            X25519Walk alice = X25519Walks.Rfc7748("alice-public"), bob = X25519Walks.Rfc7748("bob-public");
            Assert.Equal(v["a"], Hex.Encode(alice.Scalar));
            Assert.Equal(v["a_pub"], Hex.Encode(alice.Result));
            Assert.Equal(v["b_pub"], Hex.Encode(bob.Result));
            CheckAgainstReference(alice);
            CheckAgainstReference(bob);
        }

        [Fact]
        public void The_shared_secret_matches_rfc_7748_and_every_row_matches_the_reference_ladder()
        {
            Dictionary<string, string> v = DhVectors();
            X25519Walk shared = X25519Walks.Rfc7748("shared");
            Assert.Equal(v["b_pub"], Hex.Encode(shared.Point));
            Assert.Equal(v["k"], Hex.Encode(shared.Result));
            CheckAgainstReference(shared);
        }

        [Fact]
        public void The_clamp_clears_the_low_3_bits_and_bit_255_and_sets_bit_254()
        {
            X25519Walk w = X25519Walks.Rfc7748("alice-public");
            Assert.Equal(0, w.Clamped[0] & 7);
            Assert.Equal(0, w.Clamped[31] & 0x80);
            Assert.Equal(0x40, w.Clamped[31] & 0x40);
            Assert.Equal(w.Scalar.Skip(1).Take(30), w.Clamped.Skip(1).Take(30));
            Assert.True(w.Rows[0].IsOne, "bit 254 is set, so the first step reads a 1");
        }

        [Fact]
        public void An_unknown_step_is_refused_and_the_guard_names_its_code()
        {
            Assert.Throws<ArgumentException>(() => X25519Walks.Rfc7748("carol"));
            NetSecException e = Assert.Throws<NetSecException>(() => X25519Walks.RequireSame(new byte[] { 1 }, new byte[] { 2 }));
            Assert.Equal(ErrorCodes.X25519WalkDiverged, e.Error.Code);
        }
    }
}
