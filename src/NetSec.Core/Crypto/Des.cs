namespace NetSec.Crypto
{
    /// <summary>The key schedule's steps, for the walk: PC-1's 56 bits, then C and D after each round's shift, and each 48-bit round key.</summary>
    internal sealed class DesScheduleTrace
    {
        public ulong Chosen;
        public uint[] C = new uint[16], D = new uint[16];
    }

    /// <summary>One S-box lookup: the 6 bits in, the row (outer bits) and column (inner 4 bits) they pick, and the 4 bits out.</summary>
    internal sealed class DesBoxTrace
    {
        public int Six, Row, Column, Out;
    }

    /// <summary>One round of the Feistel network: the halves in, E(R), E(R) xor K, the 8 S-box lookups, their 32 bits, P of those (f), and the halves out.</summary>
    internal sealed class DesRoundTrace
    {
        public uint LeftIn, RightIn, BoxesOut, F, LeftOut, RightOut;
        public ulong Expanded, Mixed, RoundKey;
        public DesBoxTrace[] Boxes = new DesBoxTrace[8];
    }

    /// <summary>A whole block: IP's output, the 16 rounds, the swapped halves R16 L16 before FP, and FP's output.</summary>
    internal sealed class DesRunTrace
    {
        public ulong Permuted, PreOutput, Output;
        public DesRoundTrace[] Rounds = new DesRoundTrace[16];
    }

    /// <summary>
    /// The DES block cipher, FIPS 46-3, for use inside TdesKey. Table entries number the bits from 1 at the
    /// most significant end, as the standard prints them. A 64-bit block is one ulong.
    /// </summary>
    static class Des
    {
        static readonly int[] InitialPermutation =
        {
            58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
        };

        static readonly int[] FinalPermutation =
        {
            40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
        };

        static readonly int[] Expansion =
        {
            32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
            12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
            22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
        };

        static readonly int[] RoundPermutation =
        {
            16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
        };

        static readonly int[] KeyChoice1 =
        {
            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
        };

        static readonly int[] KeyChoice2 =
        {
            14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
        };

        static readonly int[] KeyShifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        // Eight S-boxes, each 4 rows of 16.
        static readonly int[][] Boxes =
        {
            new int[]
            {
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
            },
            new int[]
            {
                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
            },
            new int[]
            {
                10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
            },
            new int[]
            {
                7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
            },
            new int[]
            {
                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
            },
            new int[]
            {
                12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
            },
            new int[]
            {
                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
            },
            new int[]
            {
                13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
            },
        };

        /// <summary>The 16 round keys of one 8-byte DES key. Each round key is 48 bits in a ulong. The parity bits go unused.</summary>
        public static ulong[] Schedule(byte[] key, int off) { return Schedule(key, off, null); }

        internal static ulong[] Schedule(byte[] key, int off, DesScheduleTrace trace)
        {
            ulong chosen = Permute(Endian.LoadBe64(key, off), 64, KeyChoice1);
            if (trace != null) trace.Chosen = chosen;
            uint c = (uint)(chosen >> 28) & 0x0fffffff;
            uint d = (uint)chosen & 0x0fffffff;

            ulong[] roundKeys = new ulong[16];
            for (int round = 0; round < 16; round++)
            {
                c = Rotl28(c, KeyShifts[round]);
                d = Rotl28(d, KeyShifts[round]);
                roundKeys[round] = Permute(((ulong)c << 28) | d, 56, KeyChoice2);
                if (trace != null) { trace.C[round] = c; trace.D[round] = d; }
            }
            return roundKeys;
        }

        public static ulong Encrypt(ulong block, ulong[] roundKeys) { return Run(block, roundKeys, false, null); }
        public static ulong Decrypt(ulong block, ulong[] roundKeys) { return Run(block, roundKeys, true, null); }
        internal static ulong Encrypt(ulong block, ulong[] roundKeys, DesRunTrace trace) { return Run(block, roundKeys, false, trace); }

        /// <summary>The Feistel network: 16 rounds of (L, R) to (R, L xor f(R, key)). Decryption is the same with the round keys reversed.</summary>
        static ulong Run(ulong block, ulong[] roundKeys, bool reverse, DesRunTrace trace)
        {
            ulong permuted = Permute(block, 64, InitialPermutation);
            uint left = (uint)(permuted >> 32);
            uint right = (uint)permuted;
            for (int round = 0; round < 16; round++)
            {
                DesRoundTrace r = trace == null ? null : new DesRoundTrace();
                if (r != null) { r.LeftIn = left; r.RightIn = right; r.RoundKey = roundKeys[reverse ? 15 - round : round]; }
                uint next = left ^ Feistel(right, roundKeys[reverse ? 15 - round : round], r);
                left = right;
                right = next;
                if (r != null) { r.LeftOut = left; r.RightOut = right; trace.Rounds[round] = r; }
            }
            ulong preOutput = ((ulong)right << 32) | left;
            ulong output = Permute(preOutput, 64, FinalPermutation);
            if (trace != null) { trace.Permuted = permuted; trace.PreOutput = preOutput; trace.Output = output; }
            return output;
        }

        /// <summary>f: expand 32 bits to 48, xor the round key, turn each 6 bits into 4 through an S-box, then permute.</summary>
        static uint Feistel(uint right, ulong roundKey, DesRoundTrace trace)
        {
            ulong expanded = Permute(right, 32, Expansion);
            ulong mixed = expanded ^ roundKey;
            ulong output = 0;
            for (int box = 0; box < 8; box++)
            {
                int six = (int)(mixed >> (42 - 6 * box)) & 63;
                int row = ((six >> 4) & 2) | (six & 1);
                int column = (six >> 1) & 15;
                output = (output << 4) | (uint)Boxes[box][row * 16 + column];
                if (trace != null)
                {
                    DesBoxTrace b = new DesBoxTrace();
                    b.Six = six; b.Row = row; b.Column = column; b.Out = Boxes[box][row * 16 + column];
                    trace.Boxes[box] = b;
                }
            }
            uint f = (uint)Permute(output, 32, RoundPermutation);
            if (trace != null) { trace.Expanded = expanded; trace.Mixed = mixed; trace.BoxesOut = (uint)output; trace.F = f; }
            return f;
        }

        /// <summary>Output bit k is input bit table[k], counted from the top of the inputBits-wide value.</summary>
        static ulong Permute(ulong input, int inputBits, int[] table)
        {
            ulong output = 0;
            for (int k = 0; k < table.Length; k++)
                output = (output << 1) | ((input >> (inputBits - table[k])) & 1);
            return output;
        }

        static uint Rotl28(uint v, int n) { return ((v << n) | (v >> (28 - n))) & 0x0fffffff; }
    }
}
