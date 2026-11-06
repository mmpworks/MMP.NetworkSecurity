using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// Proof for the A19 engine clauses. RefAes must reproduce FIPS 197 and the BCL. The clause bodies must PASS on RefAes and FAIL on each named defect. One changed byte in the vector file must FAIL the clause.
    /// A canned walk (the FIPS C.1 answer for every input) must FAIL the random clauses and every other FIPS clause.
    /// </summary>
    public static class SelfWalk
    {
        delegate string Body(Ctx c);

        static Ctx Copy(Ctx c, string vectorsDir)
        {
            Ctx n = new Ctx();
            n.Build = "net10"; n.VectorsDir = vectorsDir; n.AcceptanceDir = c.AcceptanceDir; n.RepoRoot = c.RepoRoot; n.WorkDir = c.WorkDir;
            foreach (KeyValuePair<string, string> kv in c.Props) n.Props[kv.Key] = kv.Value;
            return n;
        }

        static string Run(Body b, Ctx c)
        {
            try { return "PASS: " + b(c); }
            catch (NotRunException ex) { return "NOT RUN " + ex.Reason + ": " + ex.Message; }
            catch (FailException ex) { return "FAIL: " + ex.Message; }
        }

        [Clause("SELF.walk-reference-matches-fips")]
        public static string ReferenceMatchesFips(Ctx c)
        {
            int values = 0;
            foreach (string example in new string[] { "C.1", "C.2", "C.3" })
            {
                byte[] key = Hex.Decode(WalkCheck.KeyOf(c, example));
                WalkRun e = WalkCheck.Expected(c, example, "encrypt"), d = WalkCheck.Expected(c, example, "inverse");
                values += WalkCheck.Compare(example + " encrypt", e, new RefAes(key).Encrypt(Hex.Decode(e.Input)));
                values += WalkCheck.Compare(example + " inverse", d, new RefAes(key).Decrypt(Hex.Decode(d.Input)));
            }
            Check.True(values == 372, "the three examples hold " + values + " values, expected 372");
            int cells = 0;
            foreach (string example in new string[] { "A.1", "A.2", "A.3" })
            {
                string key;
                List<KeyRow> rows = WalkCheck.ExpectedRows(c, example, out key);
                cells += WalkCheck.CompareRows(example, rows, new RefAes(Hex.Decode(key)).KeyRows);
            }
            Check.True(Hex.Encode(RefAes.Sbox) == WalkCheck.Table(c, "sbox"), "RefAes builds an S-box other than figure 7");
            Check.True(Hex.Encode(RefAes.InverseSbox) == WalkCheck.Table(c, "inverse"), "RefAes builds an inverse S-box other than figure 14");
            Random r = new Random(5);
            int[] sizes = new int[] { 16, 24, 32 };
            using (Aes aes = Aes.Create())
            {
                for (int n = 0; n < 3000; n++)
                {
                    byte[] key = new byte[sizes[n % 3]], block = new byte[16];
                    r.NextBytes(key); r.NextBytes(block);
                    aes.Key = key;
                    Check.True(Hex.Encode(aes.EncryptEcb(block, PaddingMode.None)) == new RefAes(key).Encrypt(block).Output, "RefAes encrypt differs from the BCL at round " + n);
                    Check.True(Hex.Encode(aes.DecryptEcb(block, PaddingMode.None)) == new RefAes(key).Decrypt(block).Output, "RefAes decrypt differs from the BCL at round " + n);
                }
            }
            return values + " FIPS 197 round values, " + cells + " key cells, 2 tables and 6,000 BCL outputs equal RefAes";
        }

        sealed class Row
        {
            public string Id; public Body Run; public string[] Defects;
            public Row(string id, Body run, params string[] defects) { Id = id; Run = run; Defects = defects; }
        }

        static readonly Row[] Rows = new Row[]
        {
            new Row("A19.walk.states.c1-encrypt", AesStepClauses.C1Encrypt, "state-flip", "extra-mix", "row-first", "output-other"),
            new Row("A19.walk.states.c1-inverse", AesStepClauses.C1Inverse, "inverse-flip", "equivalent-order"),
            new Row("A19.walk.states.c2-encrypt", AesStepClauses.C2Encrypt, "state-flip", "canned"),
            new Row("A19.walk.states.c2-inverse", AesStepClauses.C2Inverse, "inverse-flip", "canned"),
            new Row("A19.walk.states.c3-encrypt", AesStepClauses.C3Encrypt, "state-flip", "canned"),
            new Row("A19.walk.states.c3-inverse", AesStepClauses.C3Inverse, "inverse-flip", "canned"),
            new Row("A19.walk.key-rows.a1", AesStepClauses.A1, "key-row-flip", "rcon-empty"),
            new Row("A19.walk.key-rows.a2", AesStepClauses.A2, "key-row-flip"),
            new Row("A19.walk.key-rows.a3", AesStepClauses.A3, "key-row-flip"),
            new Row("A19.walk.tables-equal-fips", AesStepClauses.Tables, "sbox-flip", "inverse-sbox-flip", "shared-table"),
            new Row("A19.walk.step-order", AesStepClauses.StepOrder, "extra-mix", "equivalent-order"),
            new Row("A19.walk.equals-real-path-and-reference", AesStepClauses.EqualsRealPath, "real-path-differs", "state-flip", "inverse-flip", "canned", "key-row-flip"),
            new Row("A19.walk.terms-equal-reference-and-xor", AesFieldClauses.TermsEqualReference, "steps-carry-no-terms", "step-term-flip", "inverse-terms-forward"),
            new Row("A19.walk.terms-worked-example", AesFieldClauses.WorkedExample, "term-wrong-result", "term-not-reduced", "term-no-doublings", "term-plain-multiply"),
            new Row("A19.walk.round-constants", AesFieldClauses.RoundConstants, "rcon-plain-double", "rcon-empty"),
            new Row("A19.walk.shift-map", AesFieldClauses.ShiftMap, "map-shared", "map-swapped", "map-right-for-left", "state-flip"),
            new Row("A19.walk.one-bit-spread", AesFieldClauses.OneBitSpread, "canned", "no-spread"),
            new Row("A19.walk.output-equals-bcl", AesStepClauses.OutputEqualsBcl, "output-other", "canned"),
        };

        [Clause("SELF.walk-clauses-pass-and-bite")]
        public static string ClausesPassAndBite(Ctx c)
        {
            int passes = 0, bites = 0;
            try
            {
                foreach (Row row in Rows)
                {
                    WalkSubject.Defect = "";
                    string good = Run(row.Run, c);
                    Check.True(good.StartsWith("PASS"), row.Id + " should PASS on RefAes, gave " + good);
                    passes++;
                    foreach (string d in row.Defects)
                    {
                        WalkSubject.Defect = d;
                        string bad = Run(row.Run, c);
                        Check.True(bad.StartsWith("FAIL"), row.Id + " should FAIL on the defect '" + d + "', gave " + bad);
                        bites++;
                    }
                }
            }
            finally { WalkSubject.Defect = ""; }
            return passes + " clauses PASS on RefAes, and " + bites + " defects (a canned walk among them) each FAIL";
        }

        /// <summary>Change one hex digit of each of the 372 values in turn, in a copy of the file. The clause for that example must FAIL every time. The control on the real file must PASS.</summary>
        [Clause("SELF.walk-vector-flip-fails")]
        public static string VectorFlipFails(Ctx c)
        {
            string[] lines = File.ReadAllLines(Path.Combine(c.VectorsDir, WalkCheck.File), Encoding.UTF8);
            string dir = Path.Combine(c.WorkDir, "walk-flip");
            Directory.CreateDirectory(dir);
            string target = Path.Combine(dir, WalkCheck.File);
            Ctx flipped = Copy(c, dir);
            Dictionary<string, Body> bodies = new Dictionary<string, Body>();
            bodies["C.1 encrypt"] = AesStepClauses.C1Encrypt; bodies["C.1 inverse"] = AesStepClauses.C1Inverse;
            bodies["C.2 encrypt"] = AesStepClauses.C2Encrypt; bodies["C.2 inverse"] = AesStepClauses.C2Inverse;
            bodies["C.3 encrypt"] = AesStepClauses.C3Encrypt; bodies["C.3 inverse"] = AesStepClauses.C3Inverse;
            foreach (KeyValuePair<string, Body> kv in bodies) Check.True(Run(kv.Value, c).StartsWith("PASS"), "control: " + kv.Key + " should PASS on the real file");
            string example = null, direction = null, label = null;
            int flips = 0, skipped = 0;
            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].StartsWith("[") && lines[i] != "[round-values]" && flips > 0) break;
                if (lines[i].StartsWith("example = ")) example = lines[i].Substring(10);
                if (lines[i].StartsWith("direction = ")) direction = lines[i].Substring(12);
                if (lines[i].StartsWith("label = ")) label = lines[i].Substring(8);
                if (!lines[i].StartsWith("value = ")) continue;
                string[] copy = (string[])lines.Clone();
                char first = lines[i][8];
                copy[i] = "value = " + (first == '0' ? '1' : '0') + lines[i].Substring(9);
                File.WriteAllLines(target, copy, new UTF8Encoding(false));
                string result = Run(bodies[example + " " + direction], flipped);
                if (result.StartsWith("PASS")) throw new FailException("a changed " + example + " " + direction + " " + label + " value still PASSED");
                Check.True(result.StartsWith("FAIL"), "a changed " + label + " value gave " + result + ", expected FAIL");
                flips++;
            }
            Check.True(flips == 372 && skipped == 0, flips + " values flipped, expected 372");
            return "control PASS on the real file. Each of " + flips + " one-byte changes to the vector file FAILS its clause";
        }
    }
}
