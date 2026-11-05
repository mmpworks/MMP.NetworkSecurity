namespace NetSec.Crypto
{
    /// <summary>
    /// Points on edwards25519 in extended coordinates: a point is long[4][] holding X, Y, Z, T, where x = X/Z, y = Y/Z and
    /// x*y = T/Z. These formulas cover doubling as well, so one Add serves both. Writes into caller-owned arrays.
    /// Built to show the parts. Do not copy: managed code gives no constant-time guarantee.
    /// </summary>
    internal static class Ge25519
    {
        // Constants of RFC 8032 section 5.1, as 16-bit limbs, low limb first.
        static readonly long[] D = { 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203 };
        static readonly long[] D2 = { 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406 };
        static readonly long[] BaseX = { 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169 };
        static readonly long[] BaseY = { 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666 };
        static readonly long[] SqrtMinusOne = { 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83 };

        public static long[][] NewPoint()
        {
            return new long[][] { Fe25519.New(), Fe25519.New(), Fe25519.New(), Fe25519.New() };
        }

        static long[][] Identity()
        {
            return new long[][] { Fe25519.New(), Fe25519.One(), Fe25519.One(), Fe25519.New() };
        }

        static long[][] BasePoint()
        {
            long[][] q = NewPoint();
            Fe25519.Copy(q[0], BaseX);
            Fe25519.Copy(q[1], BaseY);
            Fe25519.Copy(q[2], Fe25519.One());
            Fe25519.Mul(q[3], BaseX, BaseY);
            return q;
        }

        /// <summary>p = p + q. The formula is the one in RFC 8032 section 5.1.4.</summary>
        public static void Add(long[][] p, long[][] q)
        {
            long[] a = Fe25519.New(), b = Fe25519.New(), c = Fe25519.New(), d = Fe25519.New();
            long[] e = Fe25519.New(), f = Fe25519.New(), g = Fe25519.New(), h = Fe25519.New(), t = Fe25519.New();
            Fe25519.Sub(a, p[1], p[0]);
            Fe25519.Sub(t, q[1], q[0]);
            Fe25519.Mul(a, a, t);
            Fe25519.Add(b, p[0], p[1]);
            Fe25519.Add(t, q[0], q[1]);
            Fe25519.Mul(b, b, t);
            Fe25519.Mul(c, p[3], q[3]);
            Fe25519.Mul(c, c, D2);
            Fe25519.Mul(d, p[2], q[2]);
            Fe25519.Add(d, d, d);
            Fe25519.Sub(e, b, a);
            Fe25519.Sub(f, d, c);
            Fe25519.Add(g, d, c);
            Fe25519.Add(h, b, a);
            Fe25519.Mul(p[0], e, f);
            Fe25519.Mul(p[1], h, g);
            Fe25519.Mul(p[2], g, f);
            Fe25519.Mul(p[3], e, h);
        }

        static void Swap(long[][] p, long[][] q, int bit)
        {
            for (int i = 0; i < 4; i++) Fe25519.Swap(p[i], q[i], bit);
        }

        /// <summary>Writes 32 bytes: y, with the sign of x in the top bit (RFC 8032 section 5.1.2).</summary>
        public static void Pack(byte[] o, int offset, long[][] p)
        {
            long[] zInverse = Fe25519.New(), x = Fe25519.New(), y = Fe25519.New();
            Fe25519.Invert(zInverse, p[2]);
            Fe25519.Mul(x, p[0], zInverse);
            Fe25519.Mul(y, p[1], zInverse);
            Fe25519.Pack(o, offset, y);
            o[offset + 31] ^= (byte)(Fe25519.Parity(x) << 7);
        }

        /// <summary>
        /// Double-and-add from bit 255 down, on a swapped pair so each bit runs the same steps. p = s * q. The array q is
        /// used up as work space.
        /// </summary>
        public static void ScalarMult(long[][] p, long[][] q, byte[] s)
        {
            long[][] start = Identity();
            for (int i = 0; i < 4; i++) Fe25519.Copy(p[i], start[i]);
            for (int i = 255; i >= 0; i--)
            {
                int bit = (s[i >> 3] >> (i & 7)) & 1;
                Swap(p, q, bit);
                Add(q, p);
                Add(p, p);
                Swap(p, q, bit);
            }
        }

        public static void ScalarBase(long[][] p, byte[] s) { ScalarMult(p, BasePoint(), s); }

        /// <summary>
        /// Decodes a public key and negates it, because verification computes S*B + h*(-A). The square root step follows
        /// RFC 8032 section 5.1.3. Returns false when no point has this y, and when x = 0 with the sign bit set. The caller
        /// checks y &lt; p first.
        /// </summary>
        public static bool TryUnpackNegated(long[][] r, byte[] packed, int offset)
        {
            long[] num = Fe25519.New(), den = Fe25519.New(), den2 = Fe25519.New(), den4 = Fe25519.New(), den6 = Fe25519.New();
            long[] t = Fe25519.New(), check = Fe25519.New();
            long[] one = Fe25519.One();
            Fe25519.Copy(r[2], one);
            Fe25519.Unpack(r[1], packed, offset);
            Fe25519.Square(num, r[1]);
            Fe25519.Mul(den, num, D);
            Fe25519.Sub(num, num, r[2]);
            Fe25519.Add(den, r[2], den);
            Fe25519.Square(den2, den);
            Fe25519.Square(den4, den2);
            Fe25519.Mul(den6, den4, den2);
            Fe25519.Mul(t, den6, num);
            Fe25519.Mul(t, t, den);
            Fe25519.Pow2523(t, t);
            Fe25519.Mul(t, t, num);
            Fe25519.Mul(t, t, den);
            Fe25519.Mul(t, t, den);
            Fe25519.Mul(r[0], t, den);

            Fe25519.Square(check, r[0]);
            Fe25519.Mul(check, check, den);
            if (!Fe25519.AreEqual(check, num)) Fe25519.Mul(r[0], r[0], SqrtMinusOne);
            Fe25519.Square(check, r[0]);
            Fe25519.Mul(check, check, den);
            if (!Fe25519.AreEqual(check, num)) return false;

            // Step 4. Zero has no negative, so a set sign bit on x = 0 would be a second encoding of one point.
            int signBit = packed[offset + 31] >> 7;
            if (signBit == 1 && Fe25519.AreEqual(r[0], Fe25519.New())) return false;

            if (Fe25519.Parity(r[0]) == signBit) Fe25519.Sub(r[0], Fe25519.New(), r[0]);
            Fe25519.Mul(r[3], r[0], r[1]);
            return true;
        }
    }
}
