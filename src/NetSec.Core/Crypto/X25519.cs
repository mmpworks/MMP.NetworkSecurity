using System;

namespace NetSec.Crypto
{
    /// <summary>
    /// X25519 (RFC 7748). The Montgomery ladder works on u-coordinates only. The caller checks for an all-zero result where
    /// the protocol asks for that check.
    /// Built to show the parts. Do not copy: managed code gives no constant-time guarantee.
    /// </summary>
    public static class X25519
    {
        const int Length = 32;

        static readonly byte[] BasePoint = BuildBasePoint();

        static byte[] BuildBasePoint()
        {
            byte[] point = new byte[Length];
            point[0] = 9;
            return point;
        }

        public static byte[] MultBase(byte[] scalar) { return Mult(scalar, BasePoint); }

        public static byte[] Mult(byte[] scalar, byte[] point)
        {
            if (scalar == null || scalar.Length != Length) throw new ArgumentException("an X25519 scalar has 32 bytes", "scalar");
            if (point == null || point.Length != Length) throw new ArgumentException("an X25519 point has 32 bytes", "point");
            byte[] k = Clamp(scalar);
            long[] u = Fe25519.New();
            Fe25519.Unpack(u, point, 0);

            long[] x2, z2;
            Ladder(k, u, out x2, out z2);

            long[] zInverse = Fe25519.New();
            Fe25519.Invert(zInverse, z2);
            Fe25519.Mul(x2, x2, zInverse);
            byte[] result = new byte[Length];
            Fe25519.Pack(result, 0, x2);
            return result;
        }

        /// <summary>RFC 7748 section 5: clear the low 3 bits and the top bit, and set bit 254.</summary>
        static byte[] Clamp(byte[] scalar)
        {
            byte[] k = new byte[Length];
            Array.Copy(scalar, k, Length);
            k[0] &= 248;
            k[31] &= 127;
            k[31] |= 64;
            return k;
        }

        /// <summary>
        /// One ladder step per scalar bit, top down. The step does one doubling and one addition on the pair
        /// (x2:z2, x3:z3), and the pair always differs by the input point u. The order of operations follows TweetNaCl (public domain).
        /// </summary>
        static void Ladder(byte[] k, long[] u, out long[] x2Out, out long[] z2Out)
        {
            long[] x2 = Fe25519.One(), z2 = Fe25519.New(), x3 = Fe25519.New(), z3 = Fe25519.One();
            Fe25519.Copy(x3, u);
            long[] e = Fe25519.New(), f = Fe25519.New();
            long[] constant121665 = Fe25519.New();
            constant121665[0] = 0xDB41;
            constant121665[1] = 1;
            for (int i = 254; i >= 0; i--)
            {
                int bit = (k[i >> 3] >> (i & 7)) & 1;
                Fe25519.Swap(x2, x3, bit);
                Fe25519.Swap(z2, z3, bit);
                Fe25519.Add(e, x2, z2);
                Fe25519.Sub(x2, x2, z2);
                Fe25519.Add(z2, x3, z3);
                Fe25519.Sub(x3, x3, z3);
                Fe25519.Square(z3, e);
                Fe25519.Square(f, x2);
                Fe25519.Mul(x2, z2, x2);
                Fe25519.Mul(z2, x3, e);
                Fe25519.Add(e, x2, z2);
                Fe25519.Sub(x2, x2, z2);
                Fe25519.Square(x3, x2);
                Fe25519.Sub(z2, z3, f);
                Fe25519.Mul(x2, z2, constant121665);
                Fe25519.Add(x2, x2, z3);
                Fe25519.Mul(z2, z2, x2);
                Fe25519.Mul(x2, z3, f);
                Fe25519.Mul(z3, x3, u);
                Fe25519.Square(x3, e);
                Fe25519.Swap(x2, x3, bit);
                Fe25519.Swap(z2, z3, bit);
            }
            x2Out = x2;
            z2Out = z2;
        }
    }
}
