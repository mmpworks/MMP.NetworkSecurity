using System;
using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>
    /// A19, the field terms, shift maps, round constants and the one-bit spread inside the engine (docs/walkthrough-design.md sections 2.2b, 2.2c, 2.2d, 3.3, slice W1a).
    /// The expected values are the design's worked examples, FIPS 197, and RefField. None comes from the code under test.
    /// </summary>
    public static class AesFieldClauses
    {
        static readonly int[] Sizes = new int[] { 16, 24, 32 };

        [Clause("A19.walk.terms-equal-reference-and-xor", PerBuild = true)]
        public static string TermsEqualReference(Ctx c)
        {
            Random random = new Random(20261107);
            int cells = 0, mixes = 0;
            foreach (int size in Sizes)
            {
                byte[] key = new byte[size], block = new byte[16];
                random.NextBytes(key); random.NextBytes(block);
                foreach (bool encrypt in new bool[] { true, false })
                {
                    WalkRun w = encrypt ? WalkSubject.Encrypt(key, block) : WalkSubject.Decrypt(key, block);
                    string before = w.Input;
                    foreach (WalkStep s in w.Steps)
                    {
                        string where = (size * 8) + "-bit " + (encrypt ? "encrypt" : "decrypt") + ", " + s;
                        if (s.Kind.EndsWith("MixColumns"))
                        {
                            cells += RefField.Compare(where, RefField.MixTerms(Hex.Decode(before), !encrypt), s.Terms, s.State);
                            mixes++;
                        }
                        else Check.True(s.Terms == null, where + ": carries terms");
                        before = s.State;
                    }
                }
            }
            return cells + " terms in " + mixes + " mix steps, in every round, both directions and 3 key sizes, equal RefField and XOR to the state byte";
        }

        static string ColumnOf(IList<ColumnByte> terms, int first)
        {
            string s = "";
            for (int i = 0; i < 4; i++) s += terms[first + i].Result;
            return s.ToLowerInvariant();
        }

        [Clause("A19.walk.terms-worked-example", PerBuild = true)]
        public static string WorkedExample(Ctx c)
        {
            byte[] before = Hex.Decode("d4bf5d30" + "e0b452ae" + "b84111f1" + "1e2798e5");     // FIPS 197 appendix B, round 1, after ShiftRows
            IList<ColumnByte> mix = WalkSubject.MixTerms(before, false);
            Check.True(ColumnOf(mix, 0) == "046681e5", "column d4 bf 5d 30 gave " + ColumnOf(mix, 0) + ", expected 04 66 81 e5");
            string[,] parts = { { "2", "d4", "b3" }, { "3", "bf", "da" }, { "1", "5d", "5d" }, { "1", "30", "30" } };
            for (int j = 0; j < 4; j++)
            {
                TermPart p = mix[0].Parts[j];
                Check.True(p.Factor.ToString() == parts[j, 0] && p.Input == parts[j, 1] && p.Result == parts[j, 2], "term " + j + " is " + p.Factor + " x " + p.Input + " = " + p.Result + ", expected " + parts[j, 0] + " x " + parts[j, 1] + " = " + parts[j, 2]);
            }
            Check.True(mix[0].Parts[0].Reduced && mix[0].Parts[1].Reduced, "2 x d4 and 3 x bf both need the reduction by 11b");
            Check.True(!mix[0].Parts[2].Reduced && mix[0].Parts[2].Doublings.Count == 0, "1 x 5d needs no doubling");
            Doubling first = mix[0].Parts[0].Doublings[0];
            Check.True(first.From == "d4" && first.Shifted == 0x1a8 && first.Reduced && first.To == "b3", "2 x d4: from " + first.From + ", shifted " + first.Shifted.ToString("x") + ", to " + first.To + ", expected d4, 1a8, b3");
            Check.True(string.Join(" ", mix[0].Running.ToArray()) == "b3 69 34 04", "running is " + string.Join(" ", mix[0].Running.ToArray()) + ", expected b3 69 34 04");

            byte[] back = new byte[16];
            Array.Copy(Hex.Decode("046681e5"), back, 4);
            IList<ColumnByte> inv = WalkSubject.MixTerms(back, true);
            Check.True(inv[0].Result == "d4", "the inverse gave " + inv[0].Result + ", expected d4");
            string[,] inverse = { { "14", "04", "38", "08 10 20" }, { "11", "66", "b7", "cc 83 1d" }, { "13", "81", "d7", "19 32 64" }, { "9", "e5", "8c", "d1 b9 69" } };
            for (int j = 0; j < 4; j++)
            {
                TermPart p = inv[0].Parts[j];
                List<string> tos = new List<string>();
                foreach (Doubling x in p.Doublings) tos.Add(x.To);
                string d = string.Join(" ", tos.ToArray());
                Check.True(p.Factor.ToString() == inverse[j, 0] && p.Input == inverse[j, 1] && p.Result == inverse[j, 2] && d == inverse[j, 3],
                    "inverse term " + j + " is " + p.Factor + " x " + p.Input + " = " + p.Result + " with doublings " + d + ", expected " + inverse[j, 0] + " x " + inverse[j, 1] + " = " + inverse[j, 2] + " with " + inverse[j, 3]);
            }
            Check.True(string.Join(" ", inv[0].Parts[0].Picks.ToArray()) == "08 10 20", "14 x 04 picks " + string.Join(" ", inv[0].Parts[0].Picks.ToArray()) + ", expected 08 10 20");
            Check.True(string.Join(" ", inv[0].Parts[0].Sums.ToArray()) == "08 18 38", "14 x 04 sums " + string.Join(" ", inv[0].Parts[0].Sums.ToArray()) + ", expected 08 18 38");
            return "d4 bf 5d 30 gives 04 66 81 e5 with its 4 terms and running XOR, and the inverse's 4 terms, doublings, picks and sums give d4 back";
        }

        [Clause("A19.walk.round-constants", PerBuild = true)]
        public static string RoundConstants(Ctx c)
        {
            string got = Hex.Encode(WalkSubject.RoundConstants(10));
            Check.True(got == "01020408102040801b36", "RoundConstants(10) is " + got + ", expected 01 02 04 08 10 20 40 80 1b 36");
            Check.True(Hex.Encode(WalkSubject.RoundConstants(1)) == "01", "RoundConstants(1) is " + Hex.Encode(WalkSubject.RoundConstants(1)));
            string[] examples = new string[] { "A.1", "A.2", "A.3" };
            int[] used = new int[] { 10, 8, 7 };
            for (int n = 0; n < 3; n++)
            {
                string key;
                WalkCheck.ExpectedRows(c, examples[n], out key);
                int seen = 0;
                foreach (KeyRow row in WalkSubject.KeyWords(Hex.Decode(key)))
                {
                    if (row.Rcon == null) continue;
                    Check.True(row.Rcon == got.Substring(2 * seen, 2) + "000000", examples[n] + " w[" + row.Index + "]: Rcon " + row.Rcon + ", expected constant " + (seen + 1));
                    seen++;
                }
                Check.True(seen == used[n], examples[n] + " uses " + seen + " round constants, expected " + used[n]);
            }
            return "the row is 01 02 04 08 10 20 40 80 1b 36, and the key rows use 10, 8 and 7 of them, in order";
        }

        [Clause("A19.walk.shift-map", PerBuild = true)]
        public static string ShiftMap(Ctx c)
        {
            int[] forward = new int[] { 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11 }, inverse = new int[] { 0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3 };
            Check.True(string.Join(",", Str(WalkSubject.ShiftMap(false))) == string.Join(",", Str(forward)), "ShiftMap(false) is " + string.Join(",", Str(WalkSubject.ShiftMap(false))));
            Check.True(string.Join(",", Str(WalkSubject.ShiftMap(true))) == string.Join(",", Str(inverse)), "ShiftMap(true) is " + string.Join(",", Str(WalkSubject.ShiftMap(true))));
            int[] copy = WalkSubject.ShiftMap(false);
            copy[1] = 99;
            bool copied = WalkSubject.ShiftMap(false)[1] == 5;
            copy[1] = 5;
            Check.True(copied, "a map call returned the engine's own array");
            Random random = new Random(11);
            int moves = 0;
            foreach (int size in Sizes)
            {
                byte[] key = new byte[size], block = new byte[16];
                random.NextBytes(key); random.NextBytes(block);
                foreach (bool encrypt in new bool[] { true, false })
                {
                    WalkRun w = encrypt ? WalkSubject.Encrypt(key, block) : WalkSubject.Decrypt(key, block);
                    string before = w.Input;
                    foreach (WalkStep s in w.Steps)
                    {
                        if (s.Kind.EndsWith("ShiftRows"))
                        {
                            int[] map = encrypt ? forward : inverse;
                            for (int i = 0; i < 16; i++) Check.True(s.State.Substring(2 * i, 2) == before.Substring(2 * map[i], 2), s + ": state[" + i + "] after is not state[" + map[i] + "] before");
                            moves++;
                        }
                        before = s.State;
                    }
                }
            }
            return "both maps equal FIPS 197, a call returns a copy, and " + moves + " shift steps move each byte by the map";
        }

        static string[] Str(int[] a) { string[] s = new string[a.Length]; for (int i = 0; i < a.Length; i++) s[i] = a[i].ToString(); return s; }

        static int Changed(string a, string b)
        {
            int n = 0;
            for (int i = 0; i < 32; i += 2) if (a.Substring(i, 2) != b.Substring(i, 2)) n++;
            return n;
        }

        static string StateAfterRound(WalkRun w, int round)
        {
            foreach (WalkStep s in w.Steps) if (s.Kind == "AddRoundKey" && s.Round == round) return s.State;
            throw new FailException("the walk has no AddRoundKey for round " + round);
        }

        /// <summary>
        /// A changed byte after SubBytes stays one changed byte through ShiftRows. MixColumns gives 4 changed bytes in that column, since every factor is nonzero. The next ShiftRows puts those 4 in 4 columns, so the next MixColumns gives 16.
        /// So the counts hold for any one input bit, on any key and block. The clause runs every one of the 128 bits.
        /// </summary>
        [Clause("A19.walk.one-bit-spread", PerBuild = true)]
        public static string OneBitSpread(Ctx c)
        {
            const int Runs = 12;
            Random random = new Random(20261108);
            int compared = 0;
            for (int n = 0; n < Runs; n++)
            {
                byte[] key = new byte[Sizes[n % 3]], block = new byte[16];
                random.NextBytes(key); random.NextBytes(block);
                WalkRun plain = WalkSubject.Encrypt(key, block);
                for (int bit = 0; bit < 128; bit++)
                {
                    byte[] other = (byte[])block.Clone();
                    other[bit / 8] ^= (byte)(1 << (bit % 8));
                    WalkRun flipped = WalkSubject.Encrypt(key, other);
                    int one = Changed(StateAfterRound(plain, 1), StateAfterRound(flipped, 1)), two = Changed(StateAfterRound(plain, 2), StateAfterRound(flipped, 2));
                    Check.True(one == 4, "run " + n + ", bit " + bit + ": " + one + " bytes changed after round 1, expected 4");
                    Check.True(two == 16, "run " + n + ", bit " + bit + ": " + two + " bytes changed after round 2, expected 16");
                    compared++;
                }
            }
            return compared + " one-bit changes, across all 128 bits and 3 key sizes, each change 4 bytes after round 1 and 16 after round 2";
        }
    }
}
