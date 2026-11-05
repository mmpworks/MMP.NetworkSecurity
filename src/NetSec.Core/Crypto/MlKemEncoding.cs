namespace NetSec.Crypto
{
    /// <summary>FIPS 203 section 4.2.1: Compress, Decompress, ByteEncode, ByteDecode. One coefficient takes d bits, low bit first.</summary>
    internal static class MlKemEncoding
    {
        /// <summary>Rounds x * 2^d / q to the nearest whole number, mod 2^d.</summary>
        public static int[] Compress(int d, int[] f)
        {
            int[] o = new int[Poly.N];
            int half = Poly.Q / 2;
            int mask = (1 << d) - 1;
            for (int i = 0; i < Poly.N; i++) o[i] = (((f[i] << d) + half) / Poly.Q) & mask;
            return o;
        }

        /// <summary>Rounds y * q / 2^d to the nearest whole number. The round trip loses low bits, which makes the ciphertext smaller.</summary>
        public static int[] Decompress(int d, int[] f)
        {
            int[] o = new int[Poly.N];
            int half = 1 << (d - 1);
            for (int i = 0; i < Poly.N; i++) o[i] = (f[i] * Poly.Q + half) >> d;
            return o;
        }

        /// <summary>FIPS 203 algorithm 5. Writes 32*d bytes at o[offset].</summary>
        public static void ByteEncode(int d, int[] f, byte[] o, int offset)
        {
            int position = offset * 8;
            for (int i = 0; i < Poly.N; i++)
            {
                for (int bit = 0; bit < d; bit++)
                {
                    if (((f[i] >> bit) & 1) != 0) o[position >> 3] |= (byte)(1 << (position & 7));
                    position++;
                }
            }
        }

        /// <summary>FIPS 203 algorithm 6. Reads 32*d bytes at b[offset]. With d = 12 a value at or above q reduces mod q.</summary>
        public static int[] ByteDecode(int d, byte[] b, int offset)
        {
            int[] f = new int[Poly.N];
            int position = offset * 8;
            for (int i = 0; i < Poly.N; i++)
            {
                int value = 0;
                for (int bit = 0; bit < d; bit++)
                {
                    value |= ((b[position >> 3] >> (position & 7)) & 1) << bit;
                    position++;
                }
                f[i] = d == 12 ? value % Poly.Q : value;
            }
            return f;
        }
    }
}
