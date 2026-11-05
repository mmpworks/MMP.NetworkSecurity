namespace NetSec.Crypto
{
    /// <summary>
    /// Multiplication in the GCM field, SP 800-38D algorithm 1. A value is two ulongs, big-endian, and bit 0 of the
    /// standard is the top bit of Hi. The masks replace branches, so this source has no branch on the bits of H or X.
    /// This is managed code, and the JIT and the CPU give no constant-time guarantee. Lesson 11 measures that.
    /// </summary>
    static class Gf128
    {
        const ulong Reduction = 0xE100000000000000;

        public static void Multiply(ulong xHi, ulong xLo, ulong hHi, ulong hLo, out ulong zHi, out ulong zLo)
        {
            zHi = 0;
            zLo = 0;
            ulong vHi = hHi, vLo = hLo;
            for (int i = 0; i < 128; i++)
            {
                ulong bit = (i < 64 ? xHi >> (63 - i) : xLo >> (127 - i)) & 1;
                ulong take = 0UL - bit;
                zHi ^= vHi & take;
                zLo ^= vLo & take;

                ulong reduce = 0UL - (vLo & 1);
                vLo = (vLo >> 1) | (vHi << 63);
                vHi = (vHi >> 1) ^ (Reduction & reduce);
            }
        }
    }
}
