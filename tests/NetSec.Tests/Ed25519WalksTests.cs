using System;
using System.Collections.Generic;
using System.IO;
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
    /// The Ed25519 walk. Two referees: RFC 8032 section 7.1's published values, read from acceptance/vectors/ed25519-rfc8032.nsv, and an
    /// independent reference written here: the BCL's SHA-512 and affine Edwards arithmetic with System.Numerics.BigInteger, from RFC 8032
    /// section 5.1. The reference shares no code with Ge25519, Sc25519 or the engine's hash, and it checks every step the walk shows.
    /// </summary>
    public class Ed25519WalksTests
    {
        static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
        static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
        static readonly BigInteger D = Mod(-121665 * Inv(121666));
        static readonly (BigInteger X, BigInteger Y) B = (Recover(Mod(4 * Inv(5)), 0), Mod(4 * Inv(5)));

        static BigInteger Mod(BigInteger x) { BigInteger r = x % P; return r < 0 ? r + P : r; }
        static BigInteger Inv(BigInteger x) { return BigInteger.ModPow(Mod(x), P - 2, P); }
        static BigInteger Le(byte[] b) { return new BigInteger(b.Concat(new byte[] { 0 }).ToArray()); }

        static byte[] Le32(BigInteger v)
        {
            byte[] raw = v.ToByteArray(), o = new byte[32];
            Array.Copy(raw, o, Math.Min(32, raw.Length));
            return o;
        }

        /// <summary>RFC 8032 section 5.1.3: the x with x^2 = (y^2 - 1) / (d y^2 + 1) and the given parity.</summary>
        static BigInteger Recover(BigInteger y, int sign)
        {
            BigInteger xx = Mod((y * y - 1) * Inv(D * y * y + 1));
            BigInteger x = BigInteger.ModPow(xx, (P + 3) / 8, P);
            if (Mod(x * x - xx) != 0) x = Mod(x * BigInteger.ModPow(2, (P - 1) / 4, P));
            Assert.True(Mod(x * x - xx) == 0, "no square root");
            if ((int)(x % 2) != sign) x = P - x;
            return x;
        }

        /// <summary>Affine addition on -x^2 + y^2 = 1 + d x^2 y^2. The formulas are complete, so they also double.</summary>
        static (BigInteger X, BigInteger Y) Add((BigInteger X, BigInteger Y) a, (BigInteger X, BigInteger Y) b)
        {
            BigInteger t = Mod(D * a.X * b.X * a.Y * b.Y);
            return (Mod((a.X * b.Y + b.X * a.Y) * Inv(1 + t)), Mod((a.Y * b.Y + a.X * b.X) * Inv(1 - t)));
        }

        static (BigInteger X, BigInteger Y) Mul(BigInteger k, (BigInteger X, BigInteger Y) pt)
        {
            (BigInteger X, BigInteger Y) acc = (0, 1);
            for (int i = 255; i >= 0; i--)
            {
                acc = Add(acc, acc);
                if (((k >> i) & 1) == 1) acc = Add(acc, pt);
            }
            return acc;
        }

        static byte[] Encode((BigInteger X, BigInteger Y) pt)
        {
            byte[] o = Le32(pt.Y);
            o[31] |= (byte)((int)(pt.X % 2) << 7);
            return o;
        }

        static byte[] Sha512(params byte[][] parts)
        {
            using SHA512 h = SHA512.Create();
            return h.ComputeHash(parts.SelectMany(x => x).ToArray());
        }

        static Dictionary<string, Dictionary<string, string>> Vectors()
        {
            string dir = AppContext.BaseDirectory;
            while (dir != null && !File.Exists(Path.Combine(dir, "acceptance", "vectors", "ed25519-rfc8032.nsv"))) dir = Path.GetDirectoryName(dir);
            Assert.True(dir != null, "acceptance/vectors/ed25519-rfc8032.nsv was not found above the test folder");
            var tests = new Dictionary<string, Dictionary<string, string>>();
            Dictionary<string, string> cur = null;
            foreach (string raw in File.ReadAllLines(Path.Combine(dir, "acceptance", "vectors", "ed25519-rfc8032.nsv")))
            {
                string line = raw.Trim();
                if (line.StartsWith("#") || !line.Contains("=")) continue;
                string k = line.Substring(0, line.IndexOf('=')).Trim(), v = line.Substring(line.IndexOf('=') + 1).Trim();
                if (k == "test") tests[v] = cur = new Dictionary<string, string>();
                else if (cur != null) cur[k] = v;
            }
            return tests;
        }

        [Theory]
        [InlineData("1")]
        [InlineData("2")]
        [InlineData("3")]
        public void Each_step_matches_rfc_8032_and_the_independent_reference(string test)
        {
            Dictionary<string, string> v = Vectors()["TEST " + test];
            Ed25519Walk w = Ed25519Walks.Rfc8032(test);
            Assert.Equal(v["seed"], Hex.Encode(w.Seed));
            Assert.Equal(v["message"], Hex.Encode(w.Message));
            Assert.Equal(v["public"], Hex.Encode(w.PublicKey));
            Assert.Equal(v["signature"], Hex.Encode(w.Signature));
            Assert.True(w.Valid);

            // Key expansion.
            byte[] expanded = Sha512(w.Seed);
            Assert.Equal(Hex.Encode(expanded), Hex.Encode(w.Expanded));
            byte[] a = expanded.Take(32).ToArray();
            a[0] &= 248; a[31] &= 127; a[31] |= 64;
            Assert.Equal(Hex.Encode(a), Hex.Encode(w.Scalar));
            Assert.Equal(Hex.Encode(expanded.Skip(32).ToArray()), Hex.Encode(w.Prefix));
            var pointA = Mul(Le(a), B);
            Assert.Equal(Hex.Encode(Encode(pointA)), Hex.Encode(w.PublicKey));

            // r, R, h and S.
            BigInteger r = Le(Sha512(w.Prefix, w.Message)) % L;
            Assert.Equal(Hex.Encode(Le32(r)), Hex.Encode(w.R));
            byte[] rEncoded = Encode(Mul(r, B));
            Assert.Equal(Hex.Encode(rEncoded), Hex.Encode(w.RPoint));
            BigInteger h = Le(Sha512(rEncoded, w.PublicKey, w.Message)) % L;
            Assert.Equal(Hex.Encode(Le32(h)), Hex.Encode(w.H));
            Assert.Equal(Hex.Encode(Le32((r + h * Le(a)) % L)), Hex.Encode(w.S));

            // Verify: S*B, h*(-A), and R' = S*B + h*(-A) = R.
            var sB = Mul(Le(w.S), B);
            Assert.Equal(Hex.Encode(Encode(sB)), Hex.Encode(w.SB));
            var minusHA = Mul(h, (Mod(-pointA.X), pointA.Y));
            Assert.Equal(Hex.Encode(Encode(minusHA)), Hex.Encode(w.MinusHA));
            Assert.Equal(Hex.Encode(Encode(Add(sB, minusHA))), Hex.Encode(w.RPrime));
            Assert.Equal(Hex.Encode(w.RPoint), Hex.Encode(w.RPrime));
        }

        [Fact]
        public void An_unknown_test_is_refused_and_the_guard_names_its_code()
        {
            Assert.Throws<ArgumentException>(() => Ed25519Walks.Rfc8032("4"));
            NetSecException e = Assert.Throws<NetSecException>(() => Ed25519Walks.Require(false));
            Assert.Equal(ErrorCodes.Ed25519WalkDiverged, e.Error.Code);
        }
    }
}
