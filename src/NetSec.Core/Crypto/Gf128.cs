namespace NetSec.Crypto
{
    /// <summary>
    /// Multiplication in the GCM field, SP 800-38D, by Shoup's table method. A value is four uint words, big-endian, and bit 0 of the
    /// standard is the top bit of the first word (rule 7.1.4: no long in a 32-bit loop). Each key builds a table of the products i H;
    /// a multiply then takes the value one table index at a time from its last byte, shifting right and folding the bits that fall off
    /// back in with the reduction table.
    /// Two widths, one interface: the CF build (NETCF) uses 4-bit indexes, 16 products, 256 bytes per key, because memory on CE is the
    /// goal there and CLR 2.0 GCM already meets the 5x target with it; the net10 build uses 8-bit indexes, 256 products, 4 KB per key,
    /// which halves the steps of a block. Each build compiles one width, and its tests and AO rows run that width.
    /// The table lookups use secret indexes, which can leak through a CPU cache, like the AES tables. Lesson 11 measures timing.
    /// </summary>
    static class Gf128
    {
        /// <summary>Entry i: the xor, over the set bits b of i, of 0xE100 shifted right by 3 - b (the reduction of 4 bits that fall off).</summary>
        internal static readonly ushort[] Reduce4 =
        {
            0x0000, 0x1C20, 0x3840, 0x2460, 0x7080, 0x6CA0, 0x48C0, 0x54E0, 0xE100, 0xFD20, 0xD940, 0xC560, 0x9180, 0x8DA0, 0xA9C0, 0xB5E0,
        };

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
        /// The products i H for every index of the build's width, 4 words each. The top bit of an index is x^0, so entry 2^(w-1) is H
        /// and each lower power of two is the one above it times x; every other entry is the xor of the powers of two in it.
        /// </summary>
        public static uint[] Table(uint h0, uint h1, uint h2, uint h3)
        {
            int entries = Width == 8 ? 256 : 16;
            uint[] t = new uint[4 * entries];
            int top = entries >> 1;
            Set(t, top, h0, h1, h2, h3);
            for (int i = top >> 1; i > 0; i >>= 1)
            {
                Halve(ref h0, ref h1, ref h2, ref h3);
                Set(t, i, h0, h1, h2, h3);
            }
            for (int i = 2; i < entries; i <<= 1)
                for (int j = 1; j < i; j++)
                    Set(t, i + j, t[4 * i] ^ t[4 * j], t[4 * i + 1] ^ t[4 * j + 1], t[4 * i + 2] ^ t[4 * j + 2], t[4 * i + 3] ^ t[4 * j + 3]);
            return t;
        }

        static void Set(uint[] t, int i, uint w0, uint w1, uint w2, uint w3)
        {
            t[4 * i] = w0; t[4 * i + 1] = w1; t[4 * i + 2] = w2; t[4 * i + 3] = w3;
        }

        /// <summary>
        /// y = y H, with t the table of H. Reads the 16 bytes of y from the last to the first. Each index shifts the running product
        /// right by the width (folding back the bits that fall off) and adds the table entry of that index. The words go last to first
        /// and each word low to high by shifts, so no byte index is computed.
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

#if NETCF
        const int Width = 4;

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
#else
        const int Width = 8;

        /// <summary>
        /// Entry i: the reduction of 8 bits that fall off, the xor over the set bits b of i of 0xE1000 shifted right by 7 - b. It equals two
        /// 4-bit steps, Reduce4[i &amp; 15] ^ (Reduce4[i &gt;&gt; 4] &lt;&lt; 4), and it folds in at bit 12 of the top word.
        /// </summary>
        internal static readonly uint[] Reduce8 =
        {
            0x00000, 0x01C20, 0x03840, 0x02460, 0x07080, 0x06CA0, 0x048C0, 0x054E0, 0x0E100, 0x0FD20, 0x0D940, 0x0C560,
            0x09180, 0x08DA0, 0x0A9C0, 0x0B5E0, 0x1C200, 0x1DE20, 0x1FA40, 0x1E660, 0x1B280, 0x1AEA0, 0x18AC0, 0x196E0,
            0x12300, 0x13F20, 0x11B40, 0x10760, 0x15380, 0x14FA0, 0x16BC0, 0x177E0, 0x38400, 0x39820, 0x3BC40, 0x3A060,
            0x3F480, 0x3E8A0, 0x3CCC0, 0x3D0E0, 0x36500, 0x37920, 0x35D40, 0x34160, 0x31580, 0x309A0, 0x32DC0, 0x331E0,
            0x24600, 0x25A20, 0x27E40, 0x26260, 0x23680, 0x22AA0, 0x20EC0, 0x212E0, 0x2A700, 0x2BB20, 0x29F40, 0x28360,
            0x2D780, 0x2CBA0, 0x2EFC0, 0x2F3E0, 0x70800, 0x71420, 0x73040, 0x72C60, 0x77880, 0x764A0, 0x740C0, 0x75CE0,
            0x7E900, 0x7F520, 0x7D140, 0x7CD60, 0x79980, 0x785A0, 0x7A1C0, 0x7BDE0, 0x6CA00, 0x6D620, 0x6F240, 0x6EE60,
            0x6BA80, 0x6A6A0, 0x682C0, 0x69EE0, 0x62B00, 0x63720, 0x61340, 0x60F60, 0x65B80, 0x647A0, 0x663C0, 0x67FE0,
            0x48C00, 0x49020, 0x4B440, 0x4A860, 0x4FC80, 0x4E0A0, 0x4C4C0, 0x4D8E0, 0x46D00, 0x47120, 0x45540, 0x44960,
            0x41D80, 0x401A0, 0x425C0, 0x439E0, 0x54E00, 0x55220, 0x57640, 0x56A60, 0x53E80, 0x522A0, 0x506C0, 0x51AE0,
            0x5AF00, 0x5B320, 0x59740, 0x58B60, 0x5DF80, 0x5C3A0, 0x5E7C0, 0x5FBE0, 0xE1000, 0xE0C20, 0xE2840, 0xE3460,
            0xE6080, 0xE7CA0, 0xE58C0, 0xE44E0, 0xEF100, 0xEED20, 0xEC940, 0xED560, 0xE8180, 0xE9DA0, 0xEB9C0, 0xEA5E0,
            0xFD200, 0xFCE20, 0xFEA40, 0xFF660, 0xFA280, 0xFBEA0, 0xF9AC0, 0xF86E0, 0xF3300, 0xF2F20, 0xF0B40, 0xF1760,
            0xF4380, 0xF5FA0, 0xF7BC0, 0xF67E0, 0xD9400, 0xD8820, 0xDAC40, 0xDB060, 0xDE480, 0xDF8A0, 0xDDCC0, 0xDC0E0,
            0xD7500, 0xD6920, 0xD4D40, 0xD5160, 0xD0580, 0xD19A0, 0xD3DC0, 0xD21E0, 0xC5600, 0xC4A20, 0xC6E40, 0xC7260,
            0xC2680, 0xC3AA0, 0xC1EC0, 0xC02E0, 0xCB700, 0xCAB20, 0xC8F40, 0xC9360, 0xCC780, 0xCDBA0, 0xCFFC0, 0xCE3E0,
            0x91800, 0x90420, 0x92040, 0x93C60, 0x96880, 0x974A0, 0x950C0, 0x94CE0, 0x9F900, 0x9E520, 0x9C140, 0x9DD60,
            0x98980, 0x995A0, 0x9B1C0, 0x9ADE0, 0x8DA00, 0x8C620, 0x8E240, 0x8FE60, 0x8AA80, 0x8B6A0, 0x892C0, 0x88EE0,
            0x83B00, 0x82720, 0x80340, 0x81F60, 0x84B80, 0x857A0, 0x873C0, 0x86FE0, 0xA9C00, 0xA8020, 0xAA440, 0xAB860,
            0xAEC80, 0xAF0A0, 0xAD4C0, 0xAC8E0, 0xA7D00, 0xA6120, 0xA4540, 0xA5960, 0xA0D80, 0xA11A0, 0xA35C0, 0xA29E0,
            0xB5E00, 0xB4220, 0xB6640, 0xB7A60, 0xB2E80, 0xB32A0, 0xB16C0, 0xB0AE0, 0xBBF00, 0xBA320, 0xB8740, 0xB9B60,
            0xBCF80, 0xBD3A0, 0xBF7C0, 0xBEBE0,
        };

        /// <summary>The 4 byte steps of one word of y, low byte to high.</summary>
        static void Fold(uint[] t, uint word, ref uint z0, ref uint z1, ref uint z2, ref uint z3)
        {
            uint[] r = Reduce8;
            for (int shift = 0; shift < 32; shift += 8)
            {
                uint fall = z3 & 0xFF;
                z3 = (z3 >> 8) | (z2 << 24);
                z2 = (z2 >> 8) | (z1 << 24);
                z1 = (z1 >> 8) | (z0 << 24);
                z0 = (z0 >> 8) ^ (r[fall] << 12);
                int at = (int)((word >> shift) & 0xFF) << 2;
                z0 ^= t[at]; z1 ^= t[at + 1]; z2 ^= t[at + 2]; z3 ^= t[at + 3];
            }
        }
#endif
    }
}
