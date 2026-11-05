namespace NetSec.Crypto
{
    /// <summary>
    /// Arithmetic mod p = 2^255 - 19. An element is long[16], 16 bits per limb, little-endian. A limb can hold more than
    /// 16 bits between carries, so a sum needs no carry at once. These methods write into caller-owned arrays, and an
    /// output may be the same array as an input. Layout and formulas follow TweetNaCl (public domain).
    /// Built to show the parts. Do not copy: managed code gives no constant-time guarantee.
    /// </summary>
    internal static class Fe25519
    {
        public const int LimbCount = 16;

        public static long[] New() { return new long[LimbCount]; }

        public static long[] One()
        {
            long[] o = New();
            o[0] = 1;
            return o;
        }

        public static void Copy(long[] o, long[] a)
        {
            for (int i = 0; i < LimbCount; i++) o[i] = a[i];
        }

        public static void Add(long[] o, long[] a, long[] b)
        {
            for (int i = 0; i < LimbCount; i++) o[i] = a[i] + b[i];
        }

        public static void Sub(long[] o, long[] a, long[] b)
        {
            for (int i = 0; i < LimbCount; i++) o[i] = a[i] - b[i];
        }

        /// <summary>Schoolbook product. 2^256 = 38 mod p, so a limb above position 15 folds down, times 38.</summary>
        public static void Mul(long[] o, long[] a, long[] b)
        {
            long[] t = new long[2 * LimbCount - 1];
            for (int i = 0; i < LimbCount; i++)
                for (int j = 0; j < LimbCount; j++)
                    t[i + j] += a[i] * b[j];
            for (int i = 0; i < LimbCount - 1; i++) t[i] += 38 * t[i + LimbCount];
            for (int i = 0; i < LimbCount; i++) o[i] = t[i];
            Carry(o);
            Carry(o);
        }

        public static void Square(long[] o, long[] a) { Mul(o, a, a); }

        /// <summary>Moves each limb's overflow up one limb. The overflow of the top limb wraps to limb 0, times 38.</summary>
        static void Carry(long[] o)
        {
            for (int i = 0; i < LimbCount; i++)
            {
                o[i] += 1L << 16;
                long c = o[i] >> 16;
                if (i < LimbCount - 1) o[i + 1] += c - 1;
                else o[0] += 38 * (c - 1);
                o[i] -= c << 16;
            }
        }

        /// <summary>Swaps p and q when bit is 1, with a mask and no branch on the bit.</summary>
        public static void Swap(long[] p, long[] q, int bit)
        {
            long mask = ~((long)bit - 1);
            for (int i = 0; i < LimbCount; i++)
            {
                long t = mask & (p[i] ^ q[i]);
                p[i] ^= t;
                q[i] ^= t;
            }
        }

        /// <summary>Writes the canonical 32-byte form: fully carried, then with p subtracted while the value is at least p.</summary>
        public static void Pack(byte[] o, int offset, long[] n)
        {
            long[] t = New();
            long[] m = New();
            Copy(t, n);
            Carry(t);
            Carry(t);
            Carry(t);
            for (int pass = 0; pass < 2; pass++)
            {
                m[0] = t[0] - 0xffed;
                for (int i = 1; i < 15; i++)
                {
                    m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                    m[i - 1] &= 0xffff;
                }
                m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
                int borrow = (int)((m[15] >> 16) & 1);
                m[14] &= 0xffff;
                Swap(t, m, 1 - borrow);
            }
            for (int i = 0; i < LimbCount; i++)
            {
                o[offset + 2 * i] = (byte)t[i];
                o[offset + 2 * i + 1] = (byte)(t[i] >> 8);
            }
        }

        /// <summary>Reads 32 little-endian bytes and ignores the top bit, as RFC 7748 section 5 says.</summary>
        public static void Unpack(long[] o, byte[] n, int offset)
        {
            for (int i = 0; i < LimbCount; i++)
                o[i] = n[offset + 2 * i] + ((long)n[offset + 2 * i + 1] << 8);
            o[15] &= 0x7fff;
        }

        /// <summary>a^(p-2), which is 1/a mod p by Fermat's little theorem. The exponent's bits are all 1 except at 2 and 4.</summary>
        public static void Invert(long[] o, long[] a)
        {
            long[] c = New();
            Copy(c, a);
            for (int bit = 253; bit >= 0; bit--)
            {
                Square(c, c);
                if (bit != 2 && bit != 4) Mul(c, c, a);
            }
            Copy(o, c);
        }

        /// <summary>a^((p-5)/8), the core of the square root step in RFC 8032 section 5.1.3.</summary>
        public static void Pow2523(long[] o, long[] a)
        {
            long[] c = New();
            Copy(c, a);
            for (int bit = 250; bit >= 0; bit--)
            {
                Square(c, c);
                if (bit != 1) Mul(c, c, a);
            }
            Copy(o, c);
        }

        /// <summary>The low bit of the canonical form. Ed25519 calls this the sign of x.</summary>
        public static int Parity(long[] a)
        {
            byte[] packed = new byte[32];
            Pack(packed, 0, a);
            return packed[0] & 1;
        }

        public static bool AreEqual(long[] a, long[] b)
        {
            byte[] x = new byte[32];
            byte[] y = new byte[32];
            Pack(x, 0, a);
            Pack(y, 0, b);
            int difference = 0;
            for (int i = 0; i < 32; i++) difference |= x[i] ^ y[i];
            return difference == 0;
        }
    }
}
