using System;
using NetSec.Bytes;

namespace NetSec.Crypto
{
    /// <summary>A P-256 point in Jacobian coordinates: affine x = X/Z^2, y = Y/Z^3. Z = 0 is the point at infinity. Immutable.</summary>
    public sealed class P256Point
    {
        public readonly BigUInt X, Y, Z;

        public P256Point(BigUInt x, BigUInt y, BigUInt z) { X = x; Y = y; Z = z; }

        public bool IsInfinity { get { return Z.IsZero; } }
    }

    /// <summary>Called after each bit of a scalar multiply with the bit, the point after the doubling, and the point after the addition (null on a 0).</summary>
    internal delegate void P256Step(int bit, bool isOne, P256Point afterDouble, P256Point afterAdd);

    /// <summary>
    /// The NIST P-256 curve, y^2 = x^3 - 3x + b over GF(p) (FIPS 186-5 and SP 800-186), on the engine's BigUInt, so it builds for CF 3.5, which has
    /// no System.Numerics.BigInteger. Jacobian coordinates keep the inversions to one per affine conversion. Built to show the parts, for the ECDSA
    /// walk on RFC 6979's public test keys. Do not copy: double-and-add and BigUInt's division are not constant time, and no handshake offers this curve.
    /// </summary>
    public static class P256
    {
        public static readonly BigUInt P = H("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
        public static readonly BigUInt N = H("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        public static readonly BigUInt B = H("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
        public static readonly BigUInt Gx = H("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
        public static readonly BigUInt Gy = H("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

        static readonly BigUInt Two = BigUInt.FromUInt32(2), Three = BigUInt.FromUInt32(3), Four = BigUInt.FromUInt32(4), Eight = BigUInt.FromUInt32(8);

        public static readonly P256Point Infinity = new P256Point(BigUInt.One, BigUInt.One, BigUInt.Zero);
        public static readonly P256Point G = new P256Point(Gx, Gy, BigUInt.One);

        static BigUInt H(string hex) { return BigUInt.FromBytes(Hex.Decode(hex)); }
        internal static BigUInt Add(BigUInt a, BigUInt b) { return a.Add(b).Mod(P); }
        internal static BigUInt Sub(BigUInt a, BigUInt b) { return a.CompareTo(b) >= 0 ? a.Subtract(b) : a.Add(P).Subtract(b); }
        internal static BigUInt Mul(BigUInt a, BigUInt b) { return a.Multiply(b).Mod(P); }

        /// <summary>The inverse mod p by Fermat's little theorem: a^(p-2).</summary>
        internal static BigUInt Inverse(BigUInt a) { return a.ModPow(P.Subtract(Two), P); }

        /// <summary>True when (x, y) is a point on the curve with both coordinates below p. Verification refuses any other public key.</summary>
        public static bool IsOnCurve(BigUInt x, BigUInt y)
        {
            if (x.CompareTo(P) >= 0 || y.CompareTo(P) >= 0) return false;
            BigUInt right = Add(Sub(Mul(Mul(x, x), x), Mul(Three, x)), B);
            return Mul(y, y).CompareTo(right) == 0;
        }

        /// <summary>Doubling for a = -3 (the "dbl-2001-b" formulas): alpha = 3(X - Z^2)(X + Z^2).</summary>
        public static P256Point Double(P256Point p)
        {
            if (p.IsInfinity || p.Y.IsZero) return Infinity;
            BigUInt delta = Mul(p.Z, p.Z), gamma = Mul(p.Y, p.Y), beta = Mul(p.X, gamma);
            BigUInt alpha = Mul(Three, Mul(Sub(p.X, delta), Add(p.X, delta)));
            BigUInt x3 = Sub(Mul(alpha, alpha), Mul(Eight, beta));
            BigUInt yz = Add(p.Y, p.Z);
            BigUInt z3 = Sub(Sub(Mul(yz, yz), gamma), delta);
            BigUInt y3 = Sub(Mul(alpha, Sub(Mul(Four, beta), x3)), Mul(Eight, Mul(gamma, gamma)));
            return new P256Point(x3, y3, z3);
        }

        /// <summary>Addition of two Jacobian points. Equal inputs double; opposite inputs give infinity.</summary>
        public static P256Point AddPoints(P256Point p, P256Point q)
        {
            if (p.IsInfinity) return q;
            if (q.IsInfinity) return p;
            BigUInt z1z1 = Mul(p.Z, p.Z), z2z2 = Mul(q.Z, q.Z);
            BigUInt u1 = Mul(p.X, z2z2), u2 = Mul(q.X, z1z1);
            BigUInt s1 = Mul(p.Y, Mul(q.Z, z2z2)), s2 = Mul(q.Y, Mul(p.Z, z1z1));
            if (u1.CompareTo(u2) == 0) return s1.CompareTo(s2) == 0 ? Double(p) : Infinity;
            BigUInt h = Sub(u2, u1), r = Sub(s2, s1), hh = Mul(h, h), hhh = Mul(h, hh), u1hh = Mul(u1, hh);
            BigUInt x3 = Sub(Sub(Mul(r, r), hhh), Mul(Two, u1hh));
            BigUInt y3 = Sub(Mul(r, Sub(u1hh, x3)), Mul(s1, hhh));
            return new P256Point(x3, y3, Mul(h, Mul(p.Z, q.Z)));
        }

        public static P256Point Multiply(BigUInt k, P256Point p) { return Multiply(k, p, null); }

        /// <summary>Double-and-add from the top bit of k. The bits are read once, from k's big-endian bytes. Not constant time.</summary>
        internal static P256Point Multiply(BigUInt k, P256Point p, P256Step observe)
        {
            byte[] be = k.ToBigEndian();
            P256Point acc = Infinity;
            for (int i = k.BitLength - 1; i >= 0; i--)
            {
                bool one = ((be[be.Length - 1 - (i >> 3)] >> (i & 7)) & 1) == 1;
                acc = Double(acc);
                P256Point doubled = acc;
                if (one) acc = AddPoints(acc, p);
                if (observe != null) observe(i, one, doubled, one ? acc : null);
            }
            return acc;
        }

        /// <summary>Affine x and y. The point must not be infinity.</summary>
        public static void ToAffine(P256Point p, out BigUInt x, out BigUInt y)
        {
            if (p.IsInfinity) throw new ArgumentException("the point at infinity has no affine coordinates", "p");
            BigUInt zi = Inverse(p.Z), zi2 = Mul(zi, zi);
            x = Mul(p.X, zi2);
            y = Mul(p.Y, Mul(zi2, zi));
        }
    }
}
