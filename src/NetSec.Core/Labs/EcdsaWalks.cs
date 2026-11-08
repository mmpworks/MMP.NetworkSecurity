using System;
using System.Collections.Generic;
using System.Text;
using NetSec.Crypto;
using NetSec.Errors;

namespace NetSec.Labs
{
    /// <summary>One HMAC round of RFC 6979 section 3.2, with K and V after it. A candidate round names its k and whether it was kept.</summary>
    public sealed class EcdsaWalkRound
    {
        public string Step;
        public byte[] K, V, Candidate;
        public bool Kept;
    }

    /// <summary>One bit of k*G by double-and-add: the affine point after the doubling, and after the addition of G (null on a 0). A null point is infinity.</summary>
    public sealed class EcdsaWalkBit
    {
        public int Bit;
        public bool IsOne;
        public byte[] DoubleX, DoubleY, AddX, AddY;
    }

    /// <summary>One ECDSA P-256 signature and its verification. Values are 32 big-endian bytes, the order RFC 6979 and FIPS 186-5 print.</summary>
    public sealed class EcdsaWalk
    {
        public string Message;
        public byte[] PrivateKey, PublicX, PublicY;

        /// <summary>SHA-256(message), e = that integer mod n, the RFC 6979 rounds, and the k they give.</summary>
        public byte[] Hash, E, K;
        public EcdsaWalkRound[] Rounds;

        /// <summary>k*G, one row per bit from the top, then R = k*G, r = Rx mod n, k^-1 mod n, and s = k^-1 (e + r*x) mod n.</summary>
        public EcdsaWalkBit[] Bits;
        public byte[] Rx, Ry, R, KInverse, S;

        /// <summary>Verify: w = s^-1 mod n, u1 = e*w, u2 = r*w, X = u1*G + u2*Q. The signature holds when X.x mod n equals r.</summary>
        public byte[] W, U1, U2, Xx, Xy;
        public bool Valid;
    }

    /// <summary>
    /// The ECDSA walk on RFC 6979 section A.2.5's P-256 test key, with the messages "sample" and "test" (docs/sections-plan.md, slice P8b). Pure.
    /// Each step comes from the engine through its trace. The signature is compared with EcdsaP256.Sign and the verdict with EcdsaP256.Verify, so a walk
    /// that differs throws ECDSA_WALK_DIVERGED. The key is a public test value, so it stays open with Show keys off.
    /// </summary>
    public static class EcdsaWalks
    {
        // RFC 6979 section A.2.5: the P-256 private key. A public test value.
        const string PrivateKeyHex = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";

        public static readonly string[] Messages = new string[] { "sample", "test" };

        public static EcdsaWalk Rfc6979(string message)
        {
            if (Array.IndexOf(Messages, message) < 0) throw new ArgumentException("message must be sample or test", "message");
            BigUInt x = BigUInt.FromBytes(NetSec.Bytes.Hex.Decode(PrivateKeyHex));
            byte[] m = Encoding.ASCII.GetBytes(message);
            BigUInt qy, qx = EcdsaP256.PublicKey(x, out qy);

            List<int> bits = new List<int>();
            List<bool> ones = new List<bool>();
            List<P256Point> doubled = new List<P256Point>(), added = new List<P256Point>();
            EcdsaTrace signing = new EcdsaTrace();
            signing.KG = delegate(int bit, bool isOne, P256Point afterDouble, P256Point afterAdd)
            {
                bits.Add(bit); ones.Add(isOne); doubled.Add(afterDouble); added.Add(afterAdd);
            };
            BigUInt r, s;
            EcdsaP256.Sign(x, m, out r, out s, signing);
            EcdsaTrace verifying = new EcdsaTrace();
            bool valid = EcdsaP256.Verify(qx, qy, m, r, s, verifying);

            EcdsaWalk w = new EcdsaWalk();
            w.Message = message;
            w.PrivateKey = x.ToBigEndian(32);
            w.PublicX = qx.ToBigEndian(32);
            w.PublicY = qy.ToBigEndian(32);
            w.Hash = signing.Hash;
            w.E = signing.E.ToBigEndian(32);
            w.K = signing.K.ToBigEndian(32);
            w.Rounds = new EcdsaWalkRound[signing.Rounds.Count];
            for (int i = 0; i < w.Rounds.Length; i++)
            {
                Rfc6979Round t = signing.Rounds[i];
                EcdsaWalkRound round = new EcdsaWalkRound();
                round.Step = t.Step; round.K = t.K; round.V = t.V; round.Candidate = t.Candidate; round.Kept = t.Kept;
                w.Rounds[i] = round;
            }
            w.Bits = Rows(bits, ones, doubled, added);
            w.Rx = signing.Rx.ToBigEndian(32); w.Ry = signing.Ry.ToBigEndian(32);
            w.R = r.ToBigEndian(32); w.KInverse = signing.KInverse.ToBigEndian(32); w.S = s.ToBigEndian(32);
            w.W = verifying.W.ToBigEndian(32); w.U1 = verifying.U1.ToBigEndian(32); w.U2 = verifying.U2.ToBigEndian(32);
            w.Xx = verifying.Xx.ToBigEndian(32); w.Xy = verifying.Xy.ToBigEndian(32);
            w.Valid = valid;

            BigUInt r2, s2;
            EcdsaP256.Sign(x, m, out r2, out s2);
            Require(r2.CompareTo(r) == 0 && s2.CompareTo(s) == 0);
            Require(valid && EcdsaP256.Verify(qx, qy, m, r, s));
            EcdsaWalkBit last = w.Bits[w.Bits.Length - 1];
            Require(Same(last.IsOne ? last.AddX : last.DoubleX, w.Rx) && Same(last.IsOne ? last.AddY : last.DoubleY, w.Ry));
            // u1*G + u2*Q equals R as a point, so both coordinates must match; Verify's own x mod n check is weaker (Jared, #289).
            Require(Same(w.Xx, w.Rx) && Same(w.Xy, w.Ry));
            return w;
        }

        /// <summary>
        /// The affine form of every row's points with one inversion (Montgomery's trick): multiply all the Z values together, invert the product once,
        /// then peel each inverse off. One inversion per row would cost about 80 times the whole multiply.
        /// </summary>
        static EcdsaWalkBit[] Rows(List<int> bits, List<bool> ones, List<P256Point> doubled, List<P256Point> added)
        {
            List<P256Point> all = new List<P256Point>();
            for (int i = 0; i < doubled.Count; i++) { all.Add(doubled[i]); all.Add(added[i]); }
            BigUInt[] zInverse = BatchInverse(all);
            EcdsaWalkBit[] rows = new EcdsaWalkBit[bits.Count];
            for (int i = 0; i < rows.Length; i++)
            {
                EcdsaWalkBit row = new EcdsaWalkBit();
                row.Bit = bits[i];
                row.IsOne = ones[i];
                Affine(doubled[i], zInverse[2 * i], out row.DoubleX, out row.DoubleY);
                Affine(added[i], zInverse[2 * i + 1], out row.AddX, out row.AddY);
                rows[i] = row;
            }
            return rows;
        }

        static BigUInt[] BatchInverse(List<P256Point> points)
        {
            BigUInt[] prefix = new BigUInt[points.Count], result = new BigUInt[points.Count];
            BigUInt running = BigUInt.One;
            for (int i = 0; i < points.Count; i++)
            {
                prefix[i] = running;
                if (Usable(points[i])) running = P256.Mul(running, points[i].Z);
            }
            BigUInt inverse = P256.Inverse(running);
            for (int i = points.Count - 1; i >= 0; i--)
            {
                if (!Usable(points[i])) continue;
                result[i] = P256.Mul(inverse, prefix[i]);
                inverse = P256.Mul(inverse, points[i].Z);
            }
            return result;
        }

        static bool Usable(P256Point p) { return p != null && !p.IsInfinity; }

        static void Affine(P256Point p, BigUInt zInverse, out byte[] x, out byte[] y)
        {
            x = null; y = null;
            if (!Usable(p)) return;
            BigUInt zi2 = P256.Mul(zInverse, zInverse);
            x = P256.Mul(p.X, zi2).ToBigEndian(32);
            y = P256.Mul(p.Y, P256.Mul(zi2, zInverse)).ToBigEndian(32);
        }

        static bool Same(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        internal static void Require(bool holds)
        {
            if (!holds) throw new NetSecException(NetSecError.Of(ErrorCodes.EcdsaWalkDiverged, "The walk differs from the real ECDSA path."));
        }
    }
}
