namespace NetSec.Crypto
{
    /// <summary>
    /// Multiplication in the GCM field, SP 800-38D, by Shoup's 4-bit table method. A value is four uint words, big-endian, and bit 0 of the
    /// standard is the top bit of the first word (rule 7.1.4: no long in a 32-bit loop). Each key builds a table of the 16 products i H,
    /// one 4-bit i at a time; a multiply then takes the value 4 bits at a time from its last byte, shifting right and folding the 4 bits
    /// that fall off back in with the reduction table.
    /// The table lookups use secret indexes, which can leak through a CPU cache, like the AES tables. Lesson 11 measures timing.
    /// </summary>
    static class Gf128
    {
        /// <summary>Entry i: the xor, over the set bits b of i, of 0xE100 shifted right by 3 - b (the reduction of 4 bits that fall off).</summary>
        internal static readonly ushort[] Reduce4 =
        {
            0x0000, 0x1C20, 0x3840, 0x2460, 0x7080, 0x6CA0, 0x48C0, 0x54E0, 0xE100, 0xFD20, 0xD940, 0xC560, 0x9180, 0x8DA0, 0xA9C0, 0xB5E0,
        };

        /// <summary>The 16 products i H, as 64 words: entry i in words 4i to 4i + 3. Entry 8 is H, because the top bit of a nibble is x^0.</summary>
        public static uint[] Table(uint h0, uint h1, uint h2, uint h3)
        {
            uint[] t = new uint[64];
            Set(t, 8, h0, h1, h2, h3);
            for (int i = 4; i > 0; i >>= 1)
            {
                Halve(ref h0, ref h1, ref h2, ref h3);   // each step multiplies by x
                Set(t, i, h0, h1, h2, h3);
            }
            for (int i = 2; i < 16; i <<= 1)
                for (int j = 1; j < i; j++)
                    Set(t, i + j, t[4 * i] ^ t[4 * j], t[4 * i + 1] ^ t[4 * j + 1], t[4 * i + 2] ^ t[4 * j + 2], t[4 * i + 3] ^ t[4 * j + 3]);
            return t;
        }

        static void Set(uint[] t, int i, uint w0, uint w1, uint w2, uint w3)
        {
            t[4 * i] = w0; t[4 * i + 1] = w1; t[4 * i + 2] = w2; t[4 * i + 3] = w3;
        }

        /// <summary>Times x: shift right one bit, and fold the bit that fell off back in as 0xE1 at the top (a mask, no branch on H).</summary>
        static void Halve(ref uint v0, ref uint v1, ref uint v2, ref uint v3)
        {
            uint fold = 0xE1000000u & (0u - (v3 & 1u));
            v3 = (v3 >> 1) | (v2 << 31);
            v2 = (v2 >> 1) | (v1 << 31);
            v1 = (v1 >> 1) | (v0 << 31);
            v0 = (v0 >> 1) ^ fold;
        }

        /// <summary>
        /// y = y H, with t the table of H. Reads the 16 bytes of y from the last to the first, low nibble then high: each nibble shifts
        /// the running product right by 4 bits (folding back the 4 bits that fall off) and adds the table entry of that nibble. The words
        /// go last to first and each word's bytes low to high by shifts, so no byte index is computed.
        /// </summary>
        public static void Multiply(uint[] t, ref uint y0, ref uint y1, ref uint y2, ref uint y3)
        {
            uint z0 = 0, z1 = 0, z2 = 0, z3 = 0;
            Fold(t, y3, ref z0, ref z1, ref z2, ref z3);
            Fold(t, y2, ref z0, ref z1, ref z2, ref z3);
            Fold(t, y1, ref z0, ref z1, ref z2, ref z3);
            Fold(t, y0, ref z0, ref z1, ref z2, ref z3);
            y0 = z0; y1 = z1; y2 = z2; y3 = z3;
        }

        /// <summary>The 8 nibble steps of one word of y: bytes low to high, each low nibble then high nibble.</summary>
        static void Fold(uint[] t, uint word, ref uint z0, ref uint z1, ref uint z2, ref uint z3)
        {
            ushort[] r = Reduce4;
            for (int shift = 0; shift < 32; shift += 4)
            {
                uint fall = z3 & 0xF;
                z3 = (z3 >> 4) | (z2 << 28);
                z2 = (z2 >> 4) | (z1 << 28);
                z1 = (z1 >> 4) | (z0 << 28);
                z0 = (z0 >> 4) ^ ((uint)r[fall] << 16);
                int at = (int)((word >> shift) & 0xF) << 2;
                z0 ^= t[at]; z1 ^= t[at + 1]; z2 ^= t[at + 2]; z3 ^= t[at + 3];
            }
        }
    }
}
