using System;
using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>
    /// A19, the AES walk inside the engine (docs/walkthrough-design.md section 3.3, slice W1a). Every expected value comes from vectors/aes-fips197-rounds.nsv or from the suite's RefAes, and never from the code under test.
    /// The clauses call WalkSubject, so SELF.walk-clauses-pass-and-bite runs them on RefAes with named defects.
    /// </summary>
    public static class AesStepClauses
    {
        static string States(Ctx c, string example, string direction)
        {
            WalkRun expected = WalkCheck.Expected(c, example, direction);
            byte[] key = Hex.Decode(WalkCheck.KeyOf(c, example));
            byte[] input = Hex.Decode(expected.Input);
            WalkRun actual = direction == "encrypt" ? WalkSubject.Encrypt(key, input) : WalkSubject.Decrypt(key, input);
            int values = WalkCheck.Compare("FIPS 197 " + example + " " + direction, expected, actual);
            return values + " values equal FIPS 197 " + example + " " + direction + " by position, in " + expected.Steps.Count + " steps";
        }

        [Clause("A19.walk.states.c1-encrypt", PerBuild = true)] public static string C1Encrypt(Ctx c) { return States(c, "C.1", "encrypt"); }
        [Clause("A19.walk.states.c1-inverse", PerBuild = true)] public static string C1Inverse(Ctx c) { return States(c, "C.1", "inverse"); }
        [Clause("A19.walk.states.c2-encrypt", PerBuild = true)] public static string C2Encrypt(Ctx c) { return States(c, "C.2", "encrypt"); }
        [Clause("A19.walk.states.c2-inverse", PerBuild = true)] public static string C2Inverse(Ctx c) { return States(c, "C.2", "inverse"); }
        [Clause("A19.walk.states.c3-encrypt", PerBuild = true)] public static string C3Encrypt(Ctx c) { return States(c, "C.3", "encrypt"); }
        [Clause("A19.walk.states.c3-inverse", PerBuild = true)] public static string C3Inverse(Ctx c) { return States(c, "C.3", "inverse"); }

        static string Rows(Ctx c, string example)
        {
            string key;
            List<KeyRow> expected = WalkCheck.ExpectedRows(c, example, out key);
            int values = WalkCheck.CompareRows("FIPS 197 " + example, expected, WalkSubject.KeyWords(Hex.Decode(key)));
            return values + " cells in " + expected.Count + " key rows equal FIPS 197 " + example;
        }

        [Clause("A19.walk.key-rows.a1", PerBuild = true)] public static string A1(Ctx c) { return Rows(c, "A.1"); }
        [Clause("A19.walk.key-rows.a2", PerBuild = true)] public static string A2(Ctx c) { return Rows(c, "A.2"); }
        [Clause("A19.walk.key-rows.a3", PerBuild = true)] public static string A3(Ctx c) { return Rows(c, "A.3"); }

        [Clause("A19.walk.tables-equal-fips", PerBuild = true)]
        public static string Tables(Ctx c)
        {
            byte[] sbox = WalkSubject.Sbox(), inverse = WalkSubject.InverseSbox();
            Check.True(sbox.Length == 256 && inverse.Length == 256, "a table holds " + sbox.Length + " and " + inverse.Length + " entries, expected 256");
            string s = Hex.Encode(sbox), i = Hex.Encode(inverse);
            Check.True(s == WalkCheck.Table(c, "sbox"), "the S-box differs from FIPS 197 figure 7 at entry " + FirstDiff(s, WalkCheck.Table(c, "sbox")));
            Check.True(i == WalkCheck.Table(c, "inverse"), "the inverse S-box differs from FIPS 197 figure 14 at entry " + FirstDiff(i, WalkCheck.Table(c, "inverse")));
            Check.True(sbox[0x53] == 0xed && inverse[0xed] == 0x53, "S-box of 53 is " + sbox[0x53].ToString("x2") + ", inverse of ed is " + inverse[0xed].ToString("x2"));
            sbox[0] ^= 1;
            bool copied = WalkSubject.Sbox()[0] == 0x63;
            sbox[0] ^= 1;     // A shared array would otherwise stay changed for the clauses after this one
            Check.True(copied, "a table call returned the engine's own array: changing the copy changed the table");
            return "256 of 256 entries of both tables equal FIPS 197 figures 7 and 14, and a call returns a copy";
        }

        static int FirstDiff(string a, string b)
        {
            for (int i = 0; i + 1 < a.Length && i + 1 < b.Length; i += 2) if (a[i] != b[i] || a[i + 1] != b[i + 1]) return i / 2;
            return a.Length / 2;
        }

        [Clause("A19.walk.step-order", PerBuild = true)]
        public static string StepOrder(Ctx c)
        {
            Random r = new Random(20261106);
            int[] sizes = new int[] { 16, 24, 32 }, rounds = new int[] { 10, 12, 14 }, counts = new int[] { 40, 48, 56 };
            for (int n = 0; n < 3; n++)
            {
                byte[] key = new byte[sizes[n]], block = new byte[16];
                r.NextBytes(key); r.NextBytes(block);
                foreach (bool encrypt in new bool[] { true, false })
                {
                    WalkRun w = encrypt ? WalkSubject.Encrypt(key, block) : WalkSubject.Decrypt(key, block);
                    string name = (sizes[n] * 8) + "-bit " + (encrypt ? "encrypt" : "decrypt");
                    Check.True(w.Rounds == rounds[n], name + ": rounds " + w.Rounds + ", expected " + rounds[n]);
                    Check.True(w.Steps.Count == counts[n], name + ": " + w.Steps.Count + " steps, expected " + counts[n]);
                    List<string> want = WalkCheck.KindOrder(rounds[n], encrypt);
                    for (int i = 0; i < want.Count; i++) Check.True(w.Steps[i].Kind == want[i], name + ", step " + (i + 1) + ": " + w.Steps[i].Kind + ", expected " + want[i]);
                    int mix = 0;
                    foreach (WalkStep s in w.Steps) if (s.Kind.EndsWith("MixColumns")) mix++;
                    Check.True(mix == rounds[n] - 1, name + ": " + mix + " mix steps, expected " + (rounds[n] - 1));
                    Check.True(w.Steps[0].Kind == "AddRoundKey" && w.Steps[0].Round == (encrypt ? 0 : rounds[n]), name + ": the first step is " + w.Steps[0]);
                    WalkStep last = w.Steps[w.Steps.Count - 1];
                    Check.True(last.Kind == "AddRoundKey" && last.Round == (encrypt ? rounds[n] : 0), name + ": the last step is " + last);
                }
            }
            return "40, 48 and 56 steps per direction, in the order of FIPS 197 sections 5.1 and 5.3. The last encrypt round has no MixColumns";
        }

        /// <summary>Random keys and blocks. The real path and RefAes both judge every run, and the suite never trusts the walk's own guard.</summary>
        [Clause("A19.walk.equals-real-path-and-reference", PerBuild = true)]
        public static string EqualsRealPath(Ctx c)
        {
            const int Rounds = 10000, Deep = 300;
            Random r = new Random(19700101);
            int[] sizes = new int[] { 16, 24, 32 };
            for (int n = 0; n < Rounds; n++)
            {
                byte[] key = new byte[sizes[n % 3]], block = new byte[16];
                r.NextBytes(key); r.NextBytes(block);
                WalkRun e = WalkSubject.Encrypt(key, block), d = WalkSubject.Decrypt(key, block);
                Check.True(e.Output == Hex.Encode(WalkSubject.RealEncrypt(key, block)), "round " + n + ": the encrypt walk differs from EncryptBlock");
                Check.True(d.Output == Hex.Encode(WalkSubject.RealDecrypt(key, block)), "round " + n + ": the decrypt walk differs from DecryptBlock");
                if (n >= Deep) continue;
                RefAes refAes = new RefAes(key);
                WalkCheck.Compare("round " + n + " encrypt against RefAes", refAes.Encrypt(block), e);
                WalkCheck.Compare("round " + n + " decrypt against RefAes", refAes.Decrypt(block), d);
                WalkCheck.CompareRows("round " + n + " key rows against RefAes", refAes.KeyRows, WalkSubject.KeyWords(key));
            }
            return Rounds + " random runs equal EncryptBlock and DecryptBlock. The first " + Deep + " equal RefAes at every state and key row";
        }

        [Clause("A19.walk.output-equals-bcl", PerBuild = true)]
        public static string OutputEqualsBcl(Ctx c)
        {
            const int Rounds = 2000;
            Random r = new Random(19700102);
            int[] sizes = new int[] { 16, 24, 32 };
            Tally t = new Tally();
            using (BclOracle o = BclOracle.Start(c))
            {
                for (int n = 0; n < Rounds; n++)
                {
                    byte[] key = new byte[sizes[n % 3]], block = new byte[16];
                    r.NextBytes(key); r.NextBytes(block);
                    t.Compare("round " + n + " encrypt", o.Bytes("output", "aes-ecb-encrypt", "key", key, "data", block, "padding", "none"), Hex.Decode(WalkSubject.Encrypt(key, block).Output));
                    t.Compare("round " + n + " decrypt", o.Bytes("output", "aes-ecb-decrypt", "key", key, "data", block, "padding", "none"), Hex.Decode(WalkSubject.Decrypt(key, block).Output));
                }
            }
            return t.Done() + ": encrypt and decrypt walk outputs equal the .NET library";
        }
    }
}
