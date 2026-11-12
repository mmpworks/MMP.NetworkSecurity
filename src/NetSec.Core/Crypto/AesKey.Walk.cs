using System;
using System.Collections.Generic;
using NetSec.Errors;

namespace NetSec.Crypto
{
    public enum AesStepKind { AddRoundKey, SubBytes, ShiftRows, MixColumns, InvShiftRows, InvSubBytes, InvMixColumns }

    /// <summary>One step of a walk, and the state after it. The state is 16 bytes in r + 4c order.</summary>
    public sealed class AesStep
    {
        public readonly AesStepKind Kind;

        /// <summary>Encrypt: 0 to Nr. Decrypt: Nr down to 0. On an AddRoundKey step, this is the round key's number.</summary>
        public readonly int Round;
        public readonly byte[] State;

        /// <summary>AddRoundKey only. Else null.</summary>
        public readonly byte[] RoundKey;

        /// <summary>MixColumns and InvMixColumns only. Else null.</summary>
        public readonly AesColumnByte[] Terms;

        internal AesStep(AesStepKind kind, int round, byte[] state, byte[] roundKey, AesColumnByte[] terms)
        {
            Kind = kind; Round = round; State = (byte[])state.Clone(); RoundKey = roundKey; Terms = terms;
        }
    }

    public sealed class AesBlockWalk
    {
        public readonly int Rounds;
        public readonly byte[] Input, Output;
        public readonly AesStep[] Steps;

        internal AesBlockWalk(int rounds, byte[] input, byte[] output, AesStep[] steps)
        {
            Rounds = rounds; Input = input; Output = output; Steps = steps;
        }
    }

    /// <summary>One row of the FIPS 197 appendix A tables. An unused cell is null. A word of the key holds only Word and the 3 numbers.</summary>
    public sealed class AesKeyWord
    {
        public readonly int Index;

        /// <summary>Index / Nk, the test FIPS 197 section 5.2 applies to this word.</summary>
        public readonly int Divisor, Quotient, Remainder;
        public readonly byte[] Previous, Rotated, Substituted, Rcon, AfterRcon, KeyBack, Word;

        internal AesKeyWord(int index, int nk, byte[] previous, byte[] rotated, byte[] substituted, byte[] rcon, byte[] afterRcon, byte[] keyBack, byte[] word)
        {
            Index = index; Divisor = nk; Quotient = index / nk; Remainder = index % nk;
            Previous = previous; Rotated = rotated; Substituted = substituted; Rcon = rcon; AfterRcon = afterRcon; KeyBack = keyBack; Word = word;
        }
    }

    /// <summary>One field multiply by 2. Shifted is 9 bits, before the reduction by 11b.</summary>
    public sealed class AesDoubling
    {
        public readonly byte From;
        public readonly int Shifted;
        public readonly bool Reduced;
        public readonly byte To;

        internal AesDoubling(byte from, byte to)
        {
            From = from; Shifted = from << 1; Reduced = (from & 0x80) != 0; To = to;
        }
    }

    /// <summary>One factor x input term of a mixed byte.</summary>
    public sealed class AesTerm
    {
        /// <summary>2, 3, 1 or 14, 11, 13, 9.</summary>
        public readonly int Factor;
        public readonly byte Input;

        /// <summary>As far as the factor needs. The inverse factors need 3.</summary>
        public readonly AesDoubling[] Doublings;

        /// <summary>The input and doubled values that make up the factor, low bit first, and their running XOR.</summary>
        public readonly byte[] Picks, Sums;

        /// <summary>Any doubling needed the reduction by 11b.</summary>
        public readonly bool Reduced;
        public readonly byte Result;

        internal AesTerm(int factor, byte input, AesDoubling[] doublings, byte[] picks, byte[] sums, bool reduced)
        {
            Factor = factor; Input = input; Doublings = doublings; Picks = picks; Sums = sums; Reduced = reduced;
            Result = sums[sums.Length - 1];
        }
    }

    public sealed class AesColumnByte
    {
        public readonly AesTerm[] Terms;

        /// <summary>The XOR after each term. Its last value is Result.</summary>
        public readonly byte[] Running;
        public readonly byte Result;

        internal AesColumnByte(AesTerm[] terms, byte[] running)
        {
            Terms = terms; Running = running; Result = running[running.Length - 1];
        }
    }

    /// <summary>
    /// The walk path (docs/walkthrough-design.md section 3.2). EncryptBlock and DecryptBlock stay as they are, because they do SubBytes and ShiftRows in one loop.
    /// So the round order lives in two places here, and each walk checks its result against the real path and throws AES_WALK_DIVERGED on a difference.
    /// </summary>
    public sealed partial class AesKey
    {
        static readonly int[] MixRow = { 2, 3, 1, 1 };
        static readonly int[] InverseMixRow = { 14, 11, 13, 9 };

        /// <summary>Throws AES_WALK_DIVERGED if the walk differs from EncryptBlock.</summary>
        public AesBlockWalk WalkEncrypt(byte[] block)
        {
            Arg.Range(block, 0, BlockSize);
            byte[] state = FirstBlock(block);
            List<AesStep> steps = new List<AesStep>(4 * _rounds);
            WalkAddRoundKey(steps, state, 0);
            for (int round = 1; round <= _rounds; round++)
            {
                Sub(state, AesTables.Sbox);
                steps.Add(new AesStep(AesStepKind.SubBytes, round, state, null, null));
                Move(state, ShiftRowsMap);
                steps.Add(new AesStep(AesStepKind.ShiftRows, round, state, null, null));
                if (round < _rounds) WalkMix(steps, state, round, false);
                WalkAddRoundKey(steps, state, round);
            }
            byte[] real = new byte[BlockSize];
            EncryptBlock(block, 0, real, 0);
            RequireSame(real, state);
            return new AesBlockWalk(_rounds, FirstBlock(block), state, steps.ToArray());
        }

        /// <summary>Throws AES_WALK_DIVERGED if the walk differs from DecryptBlock.</summary>
        public AesBlockWalk WalkDecrypt(byte[] block)
        {
            Arg.Range(block, 0, BlockSize);
            byte[] state = FirstBlock(block);
            List<AesStep> steps = new List<AesStep>(4 * _rounds);
            WalkAddRoundKey(steps, state, _rounds);
            for (int round = _rounds - 1; round >= 0; round--)
            {
                Move(state, InverseShiftRowsMap);
                steps.Add(new AesStep(AesStepKind.InvShiftRows, round, state, null, null));
                Sub(state, AesTables.InverseSbox);
                steps.Add(new AesStep(AesStepKind.InvSubBytes, round, state, null, null));
                WalkAddRoundKey(steps, state, round);
                if (round > 0) WalkMix(steps, state, round, true);
            }
            byte[] real = new byte[BlockSize];
            DecryptBlock(block, 0, real, 0);
            RequireSame(real, state);
            return new AesBlockWalk(_rounds, FirstBlock(block), state, steps.ToArray());
        }

        /// <summary>Nb * (Nr + 1) rows. Each row's stages come from the same RotWord and SubWord as ExpandKey, and its word must equal the expanded key.</summary>
        public AesKeyWord[] WalkKeyExpansion()
        {
            int keyWords = _rounds - 6;
            AesKeyWord[] rows = new AesKeyWord[4 * (_rounds + 1)];
            byte rcon = 1;
            for (int word = 0; word < rows.Length; word++)
            {
                if (word < keyWords) rows[word] = new AesKeyWord(word, keyWords, null, null, null, null, null, null, ExpandedWord(word));
                else if (word % keyWords == 0)
                {
                    rows[word] = RotatingWord(word, keyWords, rcon);
                    rcon = Xtime(rcon);
                }
                else rows[word] = OtherWord(word, keyWords);
            }
            return rows;
        }

        AesKeyWord RotatingWord(int word, int keyWords, byte rcon)
        {
            byte[] temp = ExpandedWord(word - 1);
            byte[] previous = (byte[])temp.Clone();
            RotWord(temp);
            byte[] rotated = (byte[])temp.Clone();
            SubWord(temp);
            byte[] substituted = (byte[])temp.Clone();
            temp[0] ^= rcon;
            byte[] keyBack = ExpandedWord(word - keyWords);
            byte[] finished = FinishWord(word, temp, keyBack);
            return new AesKeyWord(word, keyWords, previous, rotated, substituted, new byte[] { rcon, 0, 0, 0 }, temp, keyBack, finished);
        }

        /// <summary>A plain word, or AES-256's SubWord-only word.</summary>
        AesKeyWord OtherWord(int word, int keyWords)
        {
            byte[] temp = ExpandedWord(word - 1);
            byte[] previous = (byte[])temp.Clone();
            byte[] substituted = null;
            if (keyWords > 6 && word % keyWords == 4)
            {
                SubWord(temp);
                substituted = temp;
            }
            byte[] keyBack = ExpandedWord(word - keyWords);
            return new AesKeyWord(word, keyWords, previous, null, substituted, null, null, keyBack, FinishWord(word, temp, keyBack));
        }

        byte[] FinishWord(int word, byte[] temp, byte[] keyBack)
        {
            byte[] made = new byte[4];
            for (int i = 0; i < 4; i++) made[i] = (byte)(keyBack[i] ^ temp[i]);
            RequireSame(ExpandedWord(word), made);
            return made;
        }

        /// <summary>Word number word of the expanded key, as its 4 bytes (FIPS 197 word order). The walk may allocate (PRD 7.4).</summary>
        byte[] ExpandedWord(int word)
        {
            byte[] w = new byte[4];
            Endian.StoreBe32(_ek[word], w, 0);
            return w;
        }

        /// <summary>The 16 bytes of round key number round, in state order.</summary>
        byte[] RoundKeyBytes(int round)
        {
            byte[] key = new byte[BlockSize];
            for (int j = 0; j < 4; j++) Endian.StoreBe32(_ek[4 * round + j], key, 4 * j);
            return key;
        }

        public static byte[] SubstitutionTable() { return (byte[])AesTables.Sbox.Clone(); }
        public static byte[] InverseSubstitutionTable() { return (byte[])AesTables.InverseSbox.Clone(); }
        public static int[] ShiftMap(bool inverse) { return (int[])(inverse ? InverseShiftRowsMap : ShiftRowsMap).Clone(); }

        /// <summary>Each value is the one before it, doubled in the field.</summary>
        public static byte[] RoundConstants(int count)
        {
            byte[] values = new byte[count];
            byte value = 1;
            for (int i = 0; i < count; i++)
            {
                values[i] = value;
                value = Xtime(value);
            }
            return values;
        }

        /// <summary>count - 1 doublings, one between each pair of values.</summary>
        public static AesDoubling[] RoundConstantSteps(int count)
        {
            byte[] values = RoundConstants(count);
            AesDoubling[] steps = new AesDoubling[count - 1];
            for (int i = 0; i < steps.Length; i++) steps[i] = new AesDoubling(values[i], values[i + 1]);
            return steps;
        }

        /// <summary>One entry per state byte, in r + 4c order. Row r of the matrix multiplies column c of the state.</summary>
        public static AesColumnByte[] MixTerms(byte[] before, bool inverse)
        {
            Arg.Range(before, 0, BlockSize);
            int[] row = inverse ? InverseMixRow : MixRow;
            AesColumnByte[] all = new AesColumnByte[BlockSize];
            for (int i = 0; i < BlockSize; i++)
            {
                int column = i - i % 4, r = i % 4;
                AesTerm[] terms = new AesTerm[4];
                byte[] running = new byte[4];
                byte sum = 0;
                for (int j = 0; j < 4; j++)
                {
                    terms[j] = Term(row[(j - r + 4) % 4], before[column + j]);
                    sum ^= terms[j].Result;
                    running[j] = sum;
                }
                all[i] = new AesColumnByte(terms, running);
            }
            return all;
        }

        /// <summary>Walks the factor's bits from the low end. A set bit picks the value so far, and each further bit needs one more doubling.</summary>
        static AesTerm Term(int factor, byte input)
        {
            List<AesDoubling> doublings = new List<AesDoubling>();
            List<byte> picks = new List<byte>(), sums = new List<byte>();
            byte value = input, sum = 0;
            bool reduced = false;
            for (int bits = factor; bits != 0; bits >>= 1)
            {
                if ((bits & 1) != 0)
                {
                    picks.Add(value);
                    sum ^= value;
                    sums.Add(sum);
                }
                if ((bits >> 1) == 0) break;
                AesDoubling doubling = new AesDoubling(value, Xtime(value));
                doublings.Add(doubling);
                reduced |= doubling.Reduced;
                value = doubling.To;
            }
            return new AesTerm(factor, input, doublings.ToArray(), picks.ToArray(), sums.ToArray(), reduced);
        }

        void WalkAddRoundKey(List<AesStep> steps, byte[] state, int round)
        {
            byte[] key = RoundKeyBytes(round);
            AddRoundKey(state, key);
            steps.Add(new AesStep(AesStepKind.AddRoundKey, round, state, key, null));
        }

        // ---- the byte-level helpers of the walk, on the FIPS 197 byte state (moved here from AesKey.cs; the block path works on words) ----

        static void AddRoundKey(byte[] state, byte[] key)
        {
            for (int i = 0; i < BlockSize; i++) state[i] ^= key[i];
        }

        static void MixColumns(byte[] s)
        {
            byte[] t2 = AesTables.Times2, t3 = AesTables.Times3;
            for (int c = 0; c < BlockSize; c += 4)
            {
                byte a = s[c], b = s[c + 1], d = s[c + 2], e = s[c + 3];
                s[c] = (byte)(t2[a] ^ t3[b] ^ d ^ e);
                s[c + 1] = (byte)(a ^ t2[b] ^ t3[d] ^ e);
                s[c + 2] = (byte)(a ^ b ^ t2[d] ^ t3[e]);
                s[c + 3] = (byte)(t3[a] ^ b ^ d ^ t2[e]);
            }
        }

        static void InverseMixColumns(byte[] s)
        {
            byte[] t9 = AesTables.Times9, t11 = AesTables.Times11, t13 = AesTables.Times13, t14 = AesTables.Times14;
            for (int c = 0; c < BlockSize; c += 4)
            {
                byte a = s[c], b = s[c + 1], d = s[c + 2], e = s[c + 3];
                s[c] = (byte)(t14[a] ^ t11[b] ^ t13[d] ^ t9[e]);
                s[c + 1] = (byte)(t9[a] ^ t14[b] ^ t11[d] ^ t13[e]);
                s[c + 2] = (byte)(t13[a] ^ t9[b] ^ t14[d] ^ t11[e]);
                s[c + 3] = (byte)(t11[a] ^ t13[b] ^ t9[d] ^ t14[e]);
            }
        }

        static void RotWord(byte[] t)
        {
            byte first = t[0];
            t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = first;
        }

        static void SubWord(byte[] t)
        {
            for (int i = 0; i < 4; i++) t[i] = AesTables.Sbox[t[i]];
        }

        /// <summary>Multiply by 2 in GF(2^8), modulo x^8 + x^4 + x^3 + x + 1.</summary>
        static byte Xtime(byte a) { return (byte)((a << 1) ^ ((a & 0x80) != 0 ? 0x1b : 0)); }

        /// <summary>The real mix makes the state. The terms explain it, and each must give the same byte.</summary>
        static void WalkMix(List<AesStep> steps, byte[] state, int round, bool inverse)
        {
            AesColumnByte[] terms = MixTerms(state, inverse);
            if (inverse) InverseMixColumns(state);
            else MixColumns(state);
            for (int i = 0; i < BlockSize; i++) if (terms[i].Result != state[i]) throw Diverged();
            steps.Add(new AesStep(inverse ? AesStepKind.InvMixColumns : AesStepKind.MixColumns, round, state, null, terms));
        }

        static void Sub(byte[] state, byte[] box)
        {
            for (int i = 0; i < BlockSize; i++) state[i] = box[state[i]];
        }

        static void Move(byte[] state, int[] map)
        {
            byte[] scratch = new byte[BlockSize];
            for (int i = 0; i < BlockSize; i++) scratch[i] = state[map[i]];
            Buffer.BlockCopy(scratch, 0, state, 0, BlockSize);
        }

        static byte[] FirstBlock(byte[] block)
        {
            byte[] copy = new byte[BlockSize];
            Buffer.BlockCopy(block, 0, copy, 0, BlockSize);
            return copy;
        }

        internal static void RequireSame(byte[] real, byte[] walked)
        {
            for (int i = 0; i < real.Length; i++) if (real[i] != walked[i]) throw Diverged();
        }

        static NetSecException Diverged()
        {
            return new NetSecException(NetSecError.Of(ErrorCodes.AesWalkDiverged, "the walk differs from the real AES path"));
        }
    }
}
