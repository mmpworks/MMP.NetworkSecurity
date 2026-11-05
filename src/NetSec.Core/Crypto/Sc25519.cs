namespace NetSec.Crypto
{
    /// <summary>
    /// Scalars mod the group order L = 2^252 + 27742317777372353535851937790883648493. A wide value is long[64], one byte per
    /// limb, with room for overflow. The reduction follows TweetNaCl (public domain).
    /// </summary>
    internal static class Sc25519
    {
        // L, little-endian. Bytes 16 to 30 are zero.
        static readonly long[] L =
        {
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
        };

        /// <summary>
        /// How it works: 2^252 = -c mod L, with c = L - 2^252, a value of about 125 bits. So each high byte folds down by
        /// subtracting its value times L at the matching position. The last two loops remove what is left of the top
        /// nibble and turn the limbs back into bytes. The input array is used up. The output is r[offset..offset+31].
        /// </summary>
        public static void ModL(byte[] r, int offset, long[] x)
        {
            long carry;
            for (int i = 63; i >= 32; i--)
            {
                carry = 0;
                int j;
                for (j = i - 32; j < i - 12; j++)
                {
                    x[j] += carry - 16 * x[i] * L[j - (i - 32)];
                    carry = (x[j] + 128) >> 8;
                    x[j] -= carry << 8;
                }
                x[j] += carry;
                x[i] = 0;
            }
            carry = 0;
            for (int j = 0; j < 32; j++)
            {
                x[j] += carry - (x[31] >> 4) * L[j];
                carry = x[j] >> 8;
                x[j] &= 255;
            }
            for (int j = 0; j < 32; j++) x[j] -= carry * L[j];
            for (int i = 0; i < 32; i++)
            {
                x[i + 1] += x[i] >> 8;
                r[offset + i] = (byte)(x[i] & 255);
            }
        }

        /// <summary>Reduces a 64-byte hash to a 32-byte scalar.</summary>
        public static byte[] Reduce(byte[] wide)
        {
            long[] x = new long[64];
            for (int i = 0; i < 64; i++) x[i] = wide[i];
            byte[] scalar = new byte[32];
            ModL(scalar, 0, x);
            return scalar;
        }

        /// <summary>(r + h*a) mod L, written at o[offset..offset+31]. This is the S half of an Ed25519 signature.</summary>
        public static void MulAdd(byte[] o, int offset, byte[] r, byte[] h, byte[] a)
        {
            long[] x = new long[64];
            for (int i = 0; i < 32; i++) x[i] = r[i];
            for (int i = 0; i < 32; i++)
                for (int j = 0; j < 32; j++)
                    x[i + j] += (long)h[i] * a[j];
            ModL(o, offset, x);
        }

        /// <summary>RFC 8032 section 5.1.7 requires S &lt; L. Without this check one signature has a second valid form.</summary>
        public static bool IsCanonical(byte[] s, int offset)
        {
            for (int i = 31; i >= 0; i--)
            {
                if (s[offset + i] < L[i]) return true;
                if (s[offset + i] > L[i]) return false;
            }
            return false;
        }
    }
}
