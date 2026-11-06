using System;
using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>
    /// A19: reads vectors/aes-fips197-rounds.nsv and compares a walk with it by position. The values are data. No product code computes one.
    /// The FIPS labels map to steps as follows. Encrypt: start[r+1] (or output) is the state after AddRoundKey r, k_sch[r] is its round key, s_box, s_row and m_col are the state after each step.
    /// Inverse: FIPS round i is the course's round Nr - i. ik_sch[i] is the key, ik_add[i] (or ioutput) the state after AddRoundKey, is_row and is_box the state after each step, istart[i+1] the state after InvMixColumns (or after the first AddRoundKey).
    /// </summary>
    public static class WalkCheck
    {
        public const string File = "aes-fips197-rounds.nsv";

        sealed class Listed
        {
            readonly Dictionary<string, string> _v = new Dictionary<string, string>();
            public string Key, Input;
            public int Rounds;
            public void Add(int round, string label, string value)
            {
                _v[round + "." + label] = value;
                if (round > Rounds) Rounds = round;
            }
            public int Count { get { return _v.Count; } }
            public string Get(int round, string label)
            {
                string s;
                if (!_v.TryGetValue(round + "." + label, out s)) throw new NotRunException("VECTORS_MISSING", "no FIPS value round[" + round + "]." + label);
                return s;
            }
        }

        static Listed Load(Ctx c, string example, string direction)
        {
            Listed l = new Listed();
            foreach (VectorRecord r in c.Vectors(File, "round-values"))
            {
                if (r.Str("example") != example || r.Str("direction") != direction) continue;
                l.Key = r.Str("key");
                l.Add(r.Int("round"), r.Str("label"), r.Str("value"));
            }
            if (l.Count == 0) throw new NotRunException("VECTORS_MISSING", "no FIPS values for " + example + " " + direction);
            return l;
        }

        static WalkStep Step(string kind, int round, string state, string key)
        {
            WalkStep s = new WalkStep();
            s.Kind = kind; s.Round = round; s.State = state; s.RoundKey = key;
            return s;
        }

        /// <summary>The key of a FIPS example, as hex.</summary>
        public static string KeyOf(Ctx c, string example) { return Load(c, example, "encrypt").Key; }

        public static WalkRun Expected(Ctx c, string example, string direction)
        {
            Listed f = Load(c, example, direction);
            int nr = f.Rounds;
            WalkRun run = new WalkRun();
            run.Rounds = nr;
            if (direction == "encrypt")
            {
                run.Input = f.Get(0, "input");
                run.Output = f.Get(nr, "output");
                run.Steps.Add(Step("AddRoundKey", 0, f.Get(1, "start"), f.Get(0, "k_sch")));
                for (int r = 1; r <= nr; r++)
                {
                    run.Steps.Add(Step("SubBytes", r, f.Get(r, "s_box"), null));
                    run.Steps.Add(Step("ShiftRows", r, f.Get(r, "s_row"), null));
                    if (r < nr) run.Steps.Add(Step("MixColumns", r, f.Get(r, "m_col"), null));
                    run.Steps.Add(Step("AddRoundKey", r, r < nr ? f.Get(r + 1, "start") : f.Get(r, "output"), f.Get(r, "k_sch")));
                }
                return run;
            }
            run.Input = f.Get(0, "iinput");
            run.Output = f.Get(nr, "ioutput");
            run.Steps.Add(Step("AddRoundKey", nr, f.Get(1, "istart"), f.Get(0, "ik_sch")));
            for (int i = 1; i <= nr; i++)
            {
                int round = nr - i;
                run.Steps.Add(Step("InvShiftRows", round, f.Get(i, "is_row"), null));
                run.Steps.Add(Step("InvSubBytes", round, f.Get(i, "is_box"), null));
                run.Steps.Add(Step("AddRoundKey", round, i < nr ? f.Get(i, "ik_add") : f.Get(i, "ioutput"), f.Get(i, "ik_sch")));
                if (i < nr) run.Steps.Add(Step("InvMixColumns", round, f.Get(i + 1, "istart"), null));
            }
            return run;
        }

        /// <summary>A FAIL at the first step that differs, by position. Returns the number of values compared.</summary>
        public static int Compare(string where, WalkRun expected, WalkRun actual)
        {
            Check.True(actual != null, where + ": no walk");
            Check.True(actual.Rounds == expected.Rounds, where + ": rounds " + actual.Rounds + ", expected " + expected.Rounds);
            Check.True(Same(actual.Input, expected.Input), where + ": input " + actual.Input + ", expected " + expected.Input);
            Check.True(actual.Steps.Count == expected.Steps.Count, where + ": " + actual.Steps.Count + " steps, expected " + expected.Steps.Count);
            int values = 1;     // the input. The output is the state of the last step
            for (int i = 0; i < expected.Steps.Count; i++)
            {
                WalkStep e = expected.Steps[i], a = actual.Steps[i];
                string at = where + ", step " + (i + 1) + " of " + expected.Steps.Count;
                Check.True(a.Kind == e.Kind && a.Round == e.Round, at + ": got " + a + ", expected " + e);
                Check.True(Same(a.State, e.State), at + " (" + e + "): state " + a.State + ", expected " + e.State);
                values++;
                if (e.RoundKey == null) Check.True(a.RoundKey == null, at + " (" + e + "): carries a round key");
                else { Check.True(Same(a.RoundKey, e.RoundKey), at + " (" + e + "): round key " + a.RoundKey + ", expected " + e.RoundKey); values++; }
            }
            Check.True(Same(actual.Output, expected.Output), where + ": output " + actual.Output + ", expected " + expected.Output);
            return values;
        }

        public static string Lower(byte[] b) { return b == null ? null : Hex.Encode(b); }

        static bool Same(string a, string b) { return string.Equals(a, b, StringComparison.OrdinalIgnoreCase); }

        /// <summary>The rows with i at or past Nk, from appendix A. Earlier rows hold only the word, which is the key itself.</summary>
        public static List<KeyRow> ExpectedRows(Ctx c, string example, out string key)
        {
            key = null;
            List<KeyRow> rows = new List<KeyRow>();
            foreach (VectorRecord r in c.Vectors(File, "key-rows"))
            {
                if (r.Str("example") != example) continue;
                if (key == null)
                {
                    key = r.Str("key");
                    for (int i = 0; i < key.Length / 8; i++) { KeyRow first = new KeyRow(); first.Index = i; first.Word = key.Substring(8 * i, 8); rows.Add(first); }
                }
                KeyRow row = new KeyRow();
                row.Index = r.Int("i"); row.Previous = r.Str("temp"); row.KeyBack = r.Str("keyback"); row.Word = r.Str("word");
                if (r.Has("rot")) row.Rotated = r.Str("rot");
                if (r.Has("sub")) row.Substituted = r.Str("sub");
                if (r.Has("rcon")) row.Rcon = r.Str("rcon");
                if (r.Has("after")) row.AfterRcon = r.Str("after");
                rows.Add(row);
            }
            if (rows.Count == 0) throw new NotRunException("VECTORS_MISSING", "no FIPS key rows for " + example);
            return rows;
        }

        public static int CompareRows(string where, List<KeyRow> expected, IList<KeyRow> actual)
        {
            Check.True(actual != null && actual.Count == expected.Count, where + ": " + (actual == null ? 0 : actual.Count) + " key rows, expected " + expected.Count);
            int values = 0;
            for (int i = 0; i < expected.Count; i++)
            {
                KeyRow e = expected[i], a = actual[i];
                Check.True(a.Index == e.Index, where + ": row " + i + " has index " + a.Index + ", expected " + e.Index);
                values += Cell(where, e.Index, "previous", e.Previous, a.Previous);
                values += Cell(where, e.Index, "rotated", e.Rotated, a.Rotated);
                values += Cell(where, e.Index, "substituted", e.Substituted, a.Substituted);
                values += Cell(where, e.Index, "rcon", e.Rcon, a.Rcon);
                values += Cell(where, e.Index, "afterRcon", e.AfterRcon, a.AfterRcon);
                values += Cell(where, e.Index, "keyBack", e.KeyBack, a.KeyBack);
                values += Cell(where, e.Index, "word", e.Word, a.Word);
            }
            return values;
        }

        static int Cell(string where, int index, string name, string e, string a)
        {
            if (e == null)
            {
                Check.True(a == null, where + ": w[" + index + "]." + name + " should be empty, holds " + a);
                return 0;
            }
            Check.True(Same(a, e), where + ": w[" + index + "]." + name + " is " + a + ", expected " + e);
            return 1;
        }

        public static string Table(Ctx c, string table)
        {
            foreach (VectorRecord r in c.Vectors(File, "tables")) if (r.Str("table") == table) return r.Str("value");
            throw new NotRunException("VECTORS_MISSING", "no FIPS table " + table);
        }

        /// <summary>The order of step kinds for a key size, from FIPS 197 sections 5.1 and 5.3. It is built here from the rule, with no vector.</summary>
        public static List<string> KindOrder(int rounds, bool encrypt)
        {
            List<string> k = new List<string>();
            k.Add("AddRoundKey");
            for (int r = 1; r <= rounds; r++)
            {
                if (encrypt)
                {
                    k.Add("SubBytes"); k.Add("ShiftRows");
                    if (r < rounds) k.Add("MixColumns");
                    k.Add("AddRoundKey");
                }
                else
                {
                    k.Add("InvShiftRows"); k.Add("InvSubBytes"); k.Add("AddRoundKey");
                    if (r < rounds) k.Add("InvMixColumns");
                }
            }
            return k;
        }
    }
}
