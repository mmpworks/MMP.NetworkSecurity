using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Labs;
using NetSec.TestSupport;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// ECDSA P-256 and its walk (slice P8b). Referees: RFC 6979 section A.2.5's published values; an independent reference written here with the BCL's
    /// HMACSHA256 and SHA256 and affine curve arithmetic in System.Numerics.BigInteger, which checks every RFC 6979 round and every k*G row; and
    /// OpenSSL, which verifies the engine's signatures and signs for the engine to verify.
    /// </summary>
    public class EcdsaWalksTests
    {
        // RFC 6979 section A.2.5, read 2026-11-08 from rfc-editor.org.
        const string Priv = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
        const string Ux = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
        const string Uy = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

        static readonly BigInteger P = Be("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
        static readonly BigInteger N = Be("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        static readonly (BigInteger X, BigInteger Y) G = (Be("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"), Be("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"));

        static BigInteger Be(string hex) => new BigInteger(Hex.Decode("00" + hex).Reverse().ToArray());
        static BigInteger Be(byte[] b) => new BigInteger(b.Reverse().Concat(new byte[] { 0 }).ToArray());
        static BigInteger Mod(BigInteger x) { BigInteger r = x % P; return r < 0 ? r + P : r; }
        static BigInteger Inv(BigInteger x) => BigInteger.ModPow(Mod(x), P - 2, P);

        /// <summary>Affine addition on y^2 = x^3 - 3x + b; null is infinity.</summary>
        static (BigInteger X, BigInteger Y)? Add((BigInteger X, BigInteger Y)? a, (BigInteger X, BigInteger Y)? b)
        {
            if (a == null) return b;
            if (b == null) return a;
            if (a.Value.X == b.Value.X && Mod(a.Value.Y + b.Value.Y) == 0) return null;
            BigInteger l = a.Value.Equals(b.Value) ? Mod((3 * a.Value.X * a.Value.X - 3) * Inv(2 * a.Value.Y)) : Mod((b.Value.Y - a.Value.Y) * Inv(b.Value.X - a.Value.X));
            BigInteger x = Mod(l * l - a.Value.X - b.Value.X);
            return (x, Mod(l * (a.Value.X - x) - a.Value.Y));
        }

        static (BigInteger X, BigInteger Y)? Pt(byte[] x, byte[] y) => x == null ? null : ((BigInteger, BigInteger)?)(Be(x), Be(y));

        [Theory]
        [InlineData("sample", "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60", "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716", "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")]
        [InlineData("test", "d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0", "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367", "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083")]
        public void The_walk_gives_rfc_6979_a25s_key_k_r_and_s(string message, string k, string r, string s)
        {
            EcdsaWalk w = EcdsaWalks.Rfc6979(message);
            Assert.Equal(Priv, Hex.Encode(w.PrivateKey));
            Assert.Equal(Ux, Hex.Encode(w.PublicX));
            Assert.Equal(Uy, Hex.Encode(w.PublicY));
            Assert.Equal(k, Hex.Encode(w.K));
            Assert.Equal(r, Hex.Encode(w.R));
            Assert.Equal(s, Hex.Encode(w.S));
            Assert.True(w.Valid);
        }

        [Theory]
        [InlineData("sample")]
        [InlineData("test")]
        public void Every_rfc_6979_round_and_every_kG_row_match_the_independent_reference(string message)
        {
            EcdsaWalk w = EcdsaWalks.Rfc6979(message);
            byte[] m = Encoding.ASCII.GetBytes(message);
            using SHA256 sha = SHA256.Create();
            byte[] h1 = sha.ComputeHash(m);
            Assert.Equal(Hex.Encode(h1), Hex.Encode(w.Hash));

            // RFC 6979 section 3.2 with the BCL's HMAC-SHA-256.
            byte[] xo = Hex.Decode(Priv), ho = Le32Be(Be(h1) % N);
            byte[] V = Enumerable.Repeat((byte)1, 32).ToArray(), K = new byte[32];
            byte[] Mac(byte[] key, params byte[][] parts) { using HMACSHA256 hm = new HMACSHA256(key); return hm.ComputeHash(parts.SelectMany(p => p).ToArray()); }
            var expected = new System.Collections.Generic.List<(byte[] K, byte[] V)>();
            K = Mac(K, V, new byte[] { 0 }, xo, ho); expected.Add((K, V));
            V = Mac(K, V); expected.Add((K, V));
            K = Mac(K, V, new byte[] { 1 }, xo, ho); expected.Add((K, V));
            V = Mac(K, V); expected.Add((K, V));
            V = Mac(K, V); expected.Add((K, V));
            Assert.Equal(expected.Count, w.Rounds.Length);
            for (int i = 0; i < expected.Count; i++)
            {
                Assert.Equal(Hex.Encode(expected[i].K), Hex.Encode(w.Rounds[i].K));
                Assert.Equal(Hex.Encode(expected[i].V), Hex.Encode(w.Rounds[i].V));
            }
            Assert.True(w.Rounds.Last().Kept);
            Assert.Equal(Hex.Encode(V), Hex.Encode(w.K));

            // k*G, row by row, with the reference's own affine double-and-add: after bit i the running point is (bits of k read so far)*G.
            // Both RFC k values have their top bit set, so k*G has 256 rows.
            BigInteger k = Be(w.K), prefix = 0;
            (BigInteger X, BigInteger Y)? acc = null;
            Assert.Equal(256, w.Bits.Length);
            foreach (EcdsaWalkBit row in w.Bits)
            {
                Assert.Equal(((k >> row.Bit) & 1) == 1, row.IsOne);
                acc = Add(acc, acc);
                Assert.Equal(acc, Pt(row.DoubleX, row.DoubleY));
                prefix = 2 * prefix + (row.IsOne ? 1 : 0);
                if (row.IsOne) { acc = Add(acc, G); Assert.Equal(acc, Pt(row.AddX, row.AddY)); }
                else Assert.Null(row.AddX);
            }
            Assert.Equal(k, prefix);
            Assert.Equal(Mul(k, G), Pt(w.Rx, w.Ry));
            Assert.Equal(Pt(w.Rx, w.Ry), Pt(w.Xx, w.Xy));
        }

        static byte[] Le32Be(BigInteger v)
        {
            byte[] raw = v.ToByteArray().Reverse().SkipWhile(b => b == 0).ToArray();
            return new byte[32 - raw.Length].Concat(raw).ToArray();
        }

        static (BigInteger X, BigInteger Y)? Mul(BigInteger k, (BigInteger X, BigInteger Y) pt)
        {
            (BigInteger X, BigInteger Y)? acc = null;
            for (int i = 255; i >= 0; i--)
            {
                acc = Add(acc, acc);
                if (((k >> i) & 1) == 1) acc = Add(acc, pt);
            }
            return acc;
        }

        [Fact]
        public void Verify_refuses_an_off_curve_key_and_r_or_s_out_of_range()
        {
            BigUInt qx = BigUInt.FromBytes(Hex.Decode(Ux)), qy = BigUInt.FromBytes(Hex.Decode(Uy)), x = BigUInt.FromBytes(Hex.Decode(Priv));
            byte[] m = Encoding.ASCII.GetBytes("sample");
            EcdsaP256.Sign(x, m, out BigUInt r, out BigUInt s);
            Assert.True(EcdsaP256.Verify(qx, qy, m, r, s));
            Assert.False(EcdsaP256.Verify(qx, qy.Add(BigUInt.One), m, r, s));
            Assert.False(P256.IsOnCurve(qx, qy.Add(BigUInt.One)));
            Assert.False(EcdsaP256.Verify(qx, qy, m, BigUInt.Zero, s));
            Assert.False(EcdsaP256.Verify(qx, qy, m, r, P256.N));
            Assert.Throws<ArgumentException>(() => EcdsaP256.Sign(BigUInt.Zero, m, out _, out _));
        }

        static string OpenSsl(string args, string dir)
        {
            ProcessStartInfo start = new ProcessStartInfo("openssl", args) { WorkingDirectory = dir, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            using Process p = Process.Start(start);
            string o = p.StandardOutput.ReadToEnd(), e = p.StandardError.ReadToEnd();
            Assert.True(p.WaitForExit(30000), "openssl hung: " + args);
            return (o + e).Trim();
        }

        static byte[] DerInt(BigUInt v)
        {
            byte[] b = v.ToBigEndian();
            if (b.Length == 0) b = new byte[] { 0 };
            if ((b[0] & 0x80) != 0) b = new byte[] { 0 }.Concat(b).ToArray();
            return new byte[] { 2, (byte)b.Length }.Concat(b).ToArray();
        }

        static byte[] DerSig(BigUInt r, BigUInt s)
        {
            byte[] body = DerInt(r).Concat(DerInt(s)).ToArray();
            return new byte[] { 0x30, (byte)body.Length }.Concat(body).ToArray();
        }

        static (BigUInt R, BigUInt S) ParseSig(byte[] der)
        {
            int at = 2;
            BigUInt Next() { int len = der[at + 1]; byte[] v = der.Skip(at + 2).Take(len).ToArray(); at += 2 + len; return BigUInt.FromBytes(v); }
            return (Next(), Next());
        }

        static string Field(string text, string name)
        {
            Match m = Regex.Match(text, name + @":\s*(?<hex>([0-9a-f]{2}:?\s*)+)", RegexOptions.IgnoreCase);
            return Regex.Replace(m.Groups["hex"].Value, @"[:\s]", "").ToLowerInvariant();
        }

        [Fact]
        public void OpenSsl_and_the_engine_verify_each_others_signatures()
        {
            string dir = Path.Combine(Path.GetTempPath(), "netsec-ecdsa-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                OpenSsl("ecparam -name prime256v1 -genkey -noout -out key.pem", dir);
                OpenSsl("ec -in key.pem -pubout -out pub.pem", dir);
                string text = OpenSsl("ec -in key.pem -text -noout", dir);
                string priv = Field(text, "priv"), pub = Field(text, "pub");
                priv = priv.Length > 64 ? priv.Substring(priv.Length - 64) : priv.PadLeft(64, '0');
                Assert.StartsWith("04", pub);
                BigUInt qx = BigUInt.FromBytes(Hex.Decode(pub.Substring(2, 64))), qy = BigUInt.FromBytes(Hex.Decode(pub.Substring(66, 64)));
                byte[] msg = Encoding.ASCII.GetBytes("a message both sides sign");
                File.WriteAllBytes(Path.Combine(dir, "msg.bin"), msg);

                EcdsaP256.Sign(BigUInt.FromBytes(Hex.Decode(priv)), msg, out BigUInt r, out BigUInt s);
                File.WriteAllBytes(Path.Combine(dir, "engine.sig"), DerSig(r, s));
                Assert.Contains("Verified OK", OpenSsl("dgst -sha256 -verify pub.pem -signature engine.sig msg.bin", dir));

                OpenSsl("dgst -sha256 -sign key.pem -out openssl.sig msg.bin", dir);
                (BigUInt r2, BigUInt s2) = ParseSig(File.ReadAllBytes(Path.Combine(dir, "openssl.sig")));
                Assert.True(EcdsaP256.Verify(qx, qy, msg, r2, s2), "the engine refused OpenSSL's signature");
                Assert.False(EcdsaP256.Verify(qx, qy, Encoding.ASCII.GetBytes("another message"), r2, s2));
            }
            finally
            {
                // The test removes only the fresh folder it made.
                TempTree.Delete(dir);
            }
        }

        [Fact]
        public void An_unknown_message_is_refused_and_the_guard_names_its_code()
        {
            Assert.Throws<ArgumentException>(() => EcdsaWalks.Rfc6979("other"));
            NetSecException e = Assert.Throws<NetSecException>(() => EcdsaWalks.Require(false));
            Assert.Equal(ErrorCodes.EcdsaWalkDiverged, e.Error.Code);
        }
    }
}
