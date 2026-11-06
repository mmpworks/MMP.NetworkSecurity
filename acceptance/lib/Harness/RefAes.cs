using System;
using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>One step of an AES walk, in the suite's own terms. Hex is lower case. RoundKey is null except on AddRoundKey.</summary>
    public sealed class WalkStep
    {
        public string Kind; public int Round; public string State, RoundKey;
        public List<ColumnByte> Terms;   // MixColumns and InvMixColumns only
        public override string ToString() { return Kind + " round " + Round; }
    }

    public sealed class WalkRun
    {
        public int Rounds; public string Input, Output;
        public List<WalkStep> Steps = new List<WalkStep>();
    }

    /// <summary>One row of the FIPS 197 appendix A table. A cell the row does not use is null.</summary>
    public sealed class KeyRow
    {
        public int Index; public string Previous, Rotated, Substituted, Rcon, AfterRcon, KeyBack, Word;
        public int Divisor = -1, Quotient = -1, Remainder = -1;   // Index / Nk. -1 means the source does not state it (FIPS 197 appendix A)
    }

    /// <summary>
    /// The suite's own AES with its round states, from FIPS 197 sections 3.4 and 5. It shares no code with NetSec.Core. It builds the S-box from the field inverse and the affine map (section 5.1.1), so it holds no copy of the table.
    /// SELF.walk-reference-matches-fips holds it to the 372 appendix C values, the appendix A rows, figures 7 and 14, and the BCL.
    /// </summary>
    public sealed class RefAes
    {
        public static readonly byte[] Sbox, InverseSbox;

        static RefAes()
        {
            Sbox = new byte[256]; InverseSbox = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                int inverse = 0;
                for (int j = 1; j < 256 && i != 0; j++) if (Mul((byte)i, (byte)j) == 1) { inverse = j; break; }
                int s = inverse;
                for (int bit = 1; bit <= 4; bit++) s ^= ((inverse << bit) | (inverse >> (8 - bit))) & 0xff;
                Sbox[i] = (byte)(s ^ 0x63);
                InverseSbox[Sbox[i]] = (byte)i;
            }
        }

        static byte Mul(byte a, byte b)
        {
            int r = 0, x = a;
            for (int i = 0; i < 8; i++)
            {
                if ((b >> i & 1) != 0) r ^= x;
                x <<= 1;
                if ((x & 0x100) != 0) x ^= 0x11b;
            }
            return (byte)r;
        }

        readonly int _nk, _nr;
        readonly byte[][] _w;
        readonly List<KeyRow> _rows = new List<KeyRow>();

        public RefAes(byte[] key)
        {
            _nk = key.Length / 4;
            _nr = _nk + 6;
            _w = new byte[4 * (_nr + 1)][];
            byte rc = 1;
            for (int i = 0; i < _w.Length; i++)
            {
                if (i < _nk)
                {
                    _w[i] = new byte[] { key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3] };
                    KeyRow first = new KeyRow(); first.Index = i; first.Word = Hex.Encode(_w[i]); first.Divisor = _nk; first.Quotient = i / _nk; first.Remainder = i % _nk;
                    _rows.Add(first);
                    continue;
                }
                KeyRow row = new KeyRow();
                row.Index = i; row.Divisor = _nk; row.Quotient = i / _nk; row.Remainder = i % _nk;
                byte[] t = (byte[])_w[i - 1].Clone();
                row.Previous = Hex.Encode(t);
                if (i % _nk == 0)
                {
                    t = new byte[] { t[1], t[2], t[3], t[0] };
                    row.Rotated = Hex.Encode(t);
                    t = SubWord(t);
                    row.Substituted = Hex.Encode(t);
                    row.Rcon = Hex.Encode(new byte[] { rc, 0, 0, 0 });
                    t[0] ^= rc;
                    row.AfterRcon = Hex.Encode(t);
                    rc = Mul(rc, 2);
                }
                else if (_nk > 6 && i % _nk == 4)
                {
                    t = SubWord(t);
                    row.Substituted = Hex.Encode(t);
                }
                row.KeyBack = Hex.Encode(_w[i - _nk]);
                _w[i] = new byte[4];
                for (int b = 0; b < 4; b++) _w[i][b] = (byte)(t[b] ^ _w[i - _nk][b]);
                row.Word = Hex.Encode(_w[i]);
                _rows.Add(row);
            }
        }

        static byte[] SubWord(byte[] w) { return new byte[] { Sbox[w[0]], Sbox[w[1]], Sbox[w[2]], Sbox[w[3]] }; }

        public List<KeyRow> KeyRows { get { return _rows; } }

        byte[] RoundKey(int round)
        {
            byte[] k = new byte[16];
            for (int i = 0; i < 4; i++) Array.Copy(_w[4 * round + i], 0, k, 4 * i, 4);
            return k;
        }

        static void Shift(byte[] s, int direction)
        {
            byte[] o = (byte[])s.Clone();
            for (int r = 1; r < 4; r++)
                for (int c = 0; c < 4; c++)
                    s[r + 4 * c] = o[r + 4 * ((c + direction * r + 4) % 4)];
        }

        static void Mix(byte[] s, byte a, byte b, byte c, byte d)
        {
            for (int col = 0; col < 4; col++)
            {
                byte s0 = s[4 * col], s1 = s[4 * col + 1], s2 = s[4 * col + 2], s3 = s[4 * col + 3];
                s[4 * col] = (byte)(Mul(s0, a) ^ Mul(s1, b) ^ Mul(s2, c) ^ Mul(s3, d));
                s[4 * col + 1] = (byte)(Mul(s0, d) ^ Mul(s1, a) ^ Mul(s2, b) ^ Mul(s3, c));
                s[4 * col + 2] = (byte)(Mul(s0, c) ^ Mul(s1, d) ^ Mul(s2, a) ^ Mul(s3, b));
                s[4 * col + 3] = (byte)(Mul(s0, b) ^ Mul(s1, c) ^ Mul(s2, d) ^ Mul(s3, a));
            }
        }

        static void Note(WalkRun run, string kind, int round, byte[] state, byte[] roundKey)
        {
            WalkStep w = new WalkStep();
            w.Kind = kind; w.Round = round; w.State = Hex.Encode(state);
            w.RoundKey = roundKey == null ? null : Hex.Encode(roundKey);
            run.Steps.Add(w);
        }

        static void Add(WalkRun run, byte[] s, byte[] key, int round)
        {
            for (int i = 0; i < 16; i++) s[i] ^= key[i];
            Note(run, "AddRoundKey", round, s, key);
        }

        static void Sub(byte[] s, byte[] box) { for (int i = 0; i < 16; i++) s[i] = box[s[i]]; }

        public WalkRun Encrypt(byte[] block)
        {
            WalkRun run = new WalkRun();
            run.Rounds = _nr; run.Input = Hex.Encode(block);
            byte[] s = (byte[])block.Clone();
            Add(run, s, RoundKey(0), 0);
            for (int r = 1; r <= _nr; r++)
            {
                Sub(s, Sbox); Note(run, "SubBytes", r, s, null);
                Shift(s, 1); Note(run, "ShiftRows", r, s, null);
                if (r < _nr) { List<ColumnByte> t = RefField.MixTerms(s, false); Mix(s, 2, 3, 1, 1); Note(run, "MixColumns", r, s, null); run.Steps[run.Steps.Count - 1].Terms = t; }
                Add(run, s, RoundKey(r), r);
            }
            run.Output = Hex.Encode(s);
            return run;
        }

        /// <summary>The order of FIPS 197 section 5.3. The Round of a step is the number of the round key its group ends with.</summary>
        public WalkRun Decrypt(byte[] block)
        {
            WalkRun run = new WalkRun();
            run.Rounds = _nr; run.Input = Hex.Encode(block);
            byte[] s = (byte[])block.Clone();
            Add(run, s, RoundKey(_nr), _nr);
            for (int r = _nr - 1; r >= 0; r--)
            {
                Shift(s, -1); Note(run, "InvShiftRows", r, s, null);
                Sub(s, InverseSbox); Note(run, "InvSubBytes", r, s, null);
                Add(run, s, RoundKey(r), r);
                if (r > 0) { List<ColumnByte> t = RefField.MixTerms(s, true); Mix(s, 14, 11, 13, 9); Note(run, "InvMixColumns", r, s, null); run.Steps[run.Steps.Count - 1].Terms = t; }
            }
            run.Output = Hex.Encode(s);
            return run;
        }
    }
}
