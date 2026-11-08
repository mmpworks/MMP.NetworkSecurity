using System;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;

namespace NetSec.Labs
{
    /// <summary>One S-box lookup: the 6 bits in, the row (bits 1 and 6) and column (bits 2 to 5) they pick, and the 4 bits out.</summary>
    public sealed class DesWalkBox
    {
        public int Six, Row, Column, Out;
    }

    /// <summary>
    /// One Feistel round: (L, R) becomes (R, L xor f(R, K)). f expands R from 32 to 48 bits, xors the round key, sends each 6 bits through
    /// its S-box to 4 bits, and permutes the 32 bits (P).
    /// </summary>
    public sealed class DesWalkRound
    {
        public int Round;
        public uint LeftIn, RightIn, BoxesOut, F, LeftOut, RightOut;
        public ulong RoundKey, Expanded, Mixed;
        public DesWalkBox[] Boxes;
    }

    public sealed class DesWalk
    {
        /// <summary>Which known answer: "varkey", "vartext" or "subtab", one row of each NIST CAVP DES table.</summary>
        public string Name;
        public byte[] Key, Plaintext, Ciphertext;

        /// <summary>The key schedule: PC-1's 56 bits, C and D (28 bits each) after each round's left shift, and the 16 round keys from PC-2 (48 bits each).</summary>
        public ulong Chosen;
        public uint[] C, D;
        public ulong[] RoundKeys;

        /// <summary>IP's output, the 16 rounds, the swapped halves R16 L16, and FP's output, which is the ciphertext.</summary>
        public ulong Permuted, PreOutput, Output;
        public DesWalkRound[] Rounds;
    }

    /// <summary>
    /// The DES walk (FIPS 46-3; docs/sections-plan.md, section 4, the Feistel row) on published NIST CAVP known answers. Pure. Each value comes from
    /// the engine's own Des code through its traces, and the ciphertext is compared with Des.Encrypt, so a walk that differs from the real path
    /// throws DES_WALK_DIVERGED and shows nothing. The keys are public test keys, so it stays open with Show keys off.
    /// </summary>
    public static class DesWalks
    {
        // NIST CAVP KAT_TDES, the first row of TECBvarkey, TECBvartext and TECBsubtab. Each uses one DES key three times, which is single DES.
        static readonly string[] Keys = { "8001010101010101", "0101010101010101", "7ca110454a1a6e57" };
        static readonly string[] Plaintexts = { "0000000000000000", "8000000000000000", "01a1d6d039776742" };
        static readonly string[] Ciphertexts = { "95a8d72813daa94d", "95f8a5e5dd31d900", "690f5b0d9a26939b" };

        public static readonly string[] Names = new string[] { "varkey", "vartext", "subtab" };

        public static DesWalk Known(string name)
        {
            int i = Array.IndexOf(Names, name);
            if (i < 0) throw new ArgumentException("name must be varkey, vartext or subtab", "name");
            byte[] key = Hex.Decode(Keys[i]), plaintext = Hex.Decode(Plaintexts[i]);

            DesScheduleTrace schedule = new DesScheduleTrace();
            ulong[] roundKeys = Des.Schedule(key, 0, schedule);
            DesRunTrace run = new DesRunTrace();
            ulong output = Des.Encrypt(Endian.LoadBe64(plaintext, 0), roundKeys, run);

            DesWalk w = new DesWalk();
            w.Name = name;
            w.Key = key;
            w.Plaintext = plaintext;
            w.Ciphertext = new byte[8];
            Endian.StoreBe64(output, w.Ciphertext, 0);
            w.Chosen = schedule.Chosen;
            w.C = schedule.C;
            w.D = schedule.D;
            w.RoundKeys = roundKeys;
            w.Permuted = run.Permuted;
            w.PreOutput = run.PreOutput;
            w.Output = run.Output;
            w.Rounds = new DesWalkRound[16];
            for (int r = 0; r < 16; r++) w.Rounds[r] = Copy(r + 1, run.Rounds[r]);

            Require(output == Des.Encrypt(Endian.LoadBe64(plaintext, 0), Des.Schedule(key, 0)));
            Require(Hex.Encode(w.Ciphertext) == Ciphertexts[i]);
            return w;
        }

        static DesWalkRound Copy(int round, DesRoundTrace t)
        {
            DesWalkRound r = new DesWalkRound();
            r.Round = round;
            r.LeftIn = t.LeftIn; r.RightIn = t.RightIn; r.RoundKey = t.RoundKey; r.Expanded = t.Expanded; r.Mixed = t.Mixed;
            r.BoxesOut = t.BoxesOut; r.F = t.F; r.LeftOut = t.LeftOut; r.RightOut = t.RightOut;
            r.Boxes = new DesWalkBox[8];
            for (int b = 0; b < 8; b++)
            {
                r.Boxes[b] = new DesWalkBox();
                r.Boxes[b].Six = t.Boxes[b].Six; r.Boxes[b].Row = t.Boxes[b].Row; r.Boxes[b].Column = t.Boxes[b].Column; r.Boxes[b].Out = t.Boxes[b].Out;
            }
            return r;
        }

        internal static void Require(bool holds)
        {
            if (!holds) throw new NetSecException(NetSecError.Of(ErrorCodes.DesWalkDiverged, "The walk differs from the real DES path."));
        }
    }
}
