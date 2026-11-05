using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// Proof that the A17 text clauses and the A15a binding bite. Each runs docs_checks.py over small stand-in product trees:
    /// one good tree must PASS, and each tree with one change must FAIL or read NOT RUN with the named reason.
    /// </summary>
    public static class SelfA17Text
    {
        static readonly string TicGate = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".claude", "hooks", "tic-gate.py");
        const string TestKeysLine = "Use test keys only. This course shows your keys on screen and in saved files.";

        static void Put(string root, string rel, string text)
        {
            string p = Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(p));
            File.WriteAllText(p, text);
        }

        static Dictionary<string, string> Docs(Ctx c, string root, string ids)
        {
            string script = Path.Combine(c.AcceptanceDir, "checks", "docs_checks.py"), output;
            Proc.Run("python", "-I \"" + script + "\" --root \"" + root + "\" --ids " + ids, null, 120000, out output);
            Dictionary<string, string> r = new Dictionary<string, string>();
            foreach (string line in output.Split('\n'))
            {
                if (!line.StartsWith("@@CLAUSE ")) continue;
                Dictionary<string, object> d = MiniJson.AsObject(MiniJson.Parse(line.Substring(9)));
                r[MiniJson.Str(d, "id")] = MiniJson.Str(d, "status") + ":" + MiniJson.Str(d, "reason") + ":" + MiniJson.Str(d, "detail");
            }
            return r;
        }

        static void Expect(Dictionary<string, string> r, string id, string prefix, string label)
        {
            Check.True(r.ContainsKey(id) && r[id].StartsWith(prefix), label + ": " + id + " should read " + prefix + ", gave " + (r.ContainsKey(id) ? r[id] : "nothing"));
        }

        // ---------------------------------------------------------------- A17 wording and copy

        static void GoodUi(string root)
        {
            Put(root, "app/src/wizard-copy.json",
                "{\"wizard.common.test-keys-only\":\"" + TestKeysLine + "\"," +
                "\"wizard.my-login.check.device\":\"No outside tool can judge this. Our own check passed.\"," +
                "\"wizard.my-payment.check\":\"No outside tool can judge this. Our code matches the published vectors.\"," +
                "\"wizard.my-certificates.check\":\"Checked against the root you gave it. A local root is trusted only by what was told to trust it.\"}");
            Put(root, "app/src/components/SecurityPage.vue", "<template><p>{{ t('wizard.common.test-keys-only') }}</p><span>Built-in key</span><span>My test key</span></template>");
        }

        const string UiIds = "A17.ui.no-word-real,A17.ui.test-keys-line,A17.ui.no-outside-judge-line,A17.copy.grade-and-tics";

        [Clause("SELF.a17-text-checks-bite")]
        public static string TextChecksBite(Ctx c)
        {
            string tmp = Path.Combine(c.WorkDir, "a17-text");
            string empty = Path.Combine(tmp, "empty"), good = Path.Combine(tmp, "good");
            Directory.CreateDirectory(empty);
            foreach (KeyValuePair<string, string> kv in Docs(c, empty, UiIds)) Check.True(kv.Value.StartsWith("NOT RUN:PRODUCT_MISSING"), "empty root: " + kv.Key + " gave " + kv.Value);

            GoodUi(good);
            Dictionary<string, string> g = Docs(c, good, UiIds);
            bool ticGate = File.Exists(TicGate);
            foreach (string id in UiIds.Split(','))
            {
                if (id == "A17.copy.grade-and-tics" && !ticGate) { Expect(g, id, "NOT RUN:TOOL_MISSING", "good root without tic-gate.py"); continue; }
                Expect(g, id, "PASS:", "good root");
            }

            int bites = 0;
            // 1. A button that says Real.
            string r1 = Path.Combine(tmp, "bad-real"); GoodUi(r1);
            Put(r1, "app/src/components/ModeSwitch.vue", "<template><button>Real mode</button></template>");
            Expect(Docs(c, r1, "A17.ui.no-word-real"), "A17.ui.no-word-real", "FAIL:", "a Real mode button"); bites++;
            // The word in prose that means production stays allowed.
            string r1b = Path.Combine(tmp, "ok-prose"); GoodUi(r1b);
            Put(r1b, "app/src/components/About.vue", "<template><p>A real HSM shows only a key id and a check value.</p></template>");
            Expect(Docs(c, r1b, "A17.ui.no-word-real"), "A17.ui.no-word-real", "PASS:", "prose about a real HSM");
            // 2. The test-keys line changed, and the line used by no component.
            string r2 = Path.Combine(tmp, "bad-line"); GoodUi(r2);
            Put(r2, "app/src/wizard-copy.json", File.ReadAllText(Path.Combine(r2, "app", "src", "wizard-copy.json")).Replace("Use test keys only.", "Use keys carefully."));
            Expect(Docs(c, r2, "A17.ui.test-keys-line"), "A17.ui.test-keys-line", "FAIL:", "a changed test-keys line"); bites++;
            string r2b = Path.Combine(tmp, "bad-line-unused"); GoodUi(r2b);
            File.Delete(Path.Combine(r2b, "app", "src", "components", "SecurityPage.vue"));
            Put(r2b, "app/src/components/SecurityPage.vue", "<template><span>Built-in key</span><span>My test key</span></template>");
            Expect(Docs(c, r2b, "A17.ui.test-keys-line"), "A17.ui.test-keys-line", "FAIL:", "a line no component shows"); bites++;
            // 3. A tool named for a type no tool can judge, and a pass that says trusted.
            string r3 = Path.Combine(tmp, "bad-judge"); GoodUi(r3);
            Put(r3, "app/src/wizard-copy.json", File.ReadAllText(Path.Combine(r3, "app", "src", "wizard-copy.json")).Replace("}", ",\"wizard.my-payment.check.pass\":\"Checked with OpenSSL.\"}"));
            Expect(Docs(c, r3, "A17.ui.no-outside-judge-line"), "A17.ui.no-outside-judge-line", "FAIL:", "OpenSSL named for the payment keys"); bites++;
            string r3b = Path.Combine(tmp, "bad-trusted"); GoodUi(r3b);
            Put(r3b, "app/src/wizard-copy.json", File.ReadAllText(Path.Combine(r3b, "app", "src", "wizard-copy.json")).Replace("}", ",\"wizard.my-certificates.pass\":\"Your certificate is now trusted.\"}"));
            Expect(Docs(c, r3b, "A17.ui.no-outside-judge-line"), "A17.ui.no-outside-judge-line", "FAIL:", "a pass that says trusted"); bites++;
            string r3c = Path.Combine(tmp, "bad-missing-none"); GoodUi(r3c);
            Put(r3c, "app/src/wizard-copy.json", File.ReadAllText(Path.Combine(r3c, "app", "src", "wizard-copy.json")).Replace("No outside tool can judge this. Our code matches the published vectors.", "Our code matches the published vectors."));
            Expect(Docs(c, r3c, "A17.ui.no-outside-judge-line"), "A17.ui.no-outside-judge-line", "FAIL:", "the payment keys with no no-outside-tool line"); bites++;
            // 4. Hard words, and a tic.
            string r4 = Path.Combine(tmp, "bad-grade"); GoodUi(r4);
            Put(r4, "app/src/wizard-copy.json", File.ReadAllText(Path.Combine(r4, "app", "src", "wizard-copy.json")).Replace("}", ",\"wizard.hard\":\"Cryptographic authentication necessitates comprehensive interoperability considerations notwithstanding organizational infrastructure.\"}"));
            Expect(Docs(c, r4, "A17.copy.grade-and-tics"), "A17.copy.grade-and-tics", "FAIL:", "hard words"); bites++;
            if (ticGate)
            {
                string r4b = Path.Combine(tmp, "bad-tic"); GoodUi(r4b);
                Put(r4b, "app/src/wizard-copy.json", File.ReadAllText(Path.Combine(r4b, "app", "src", "wizard-copy.json")).Replace("}", ",\"wizard.tic\":\"This shows exactly what you need.\"}"));
                Expect(Docs(c, r4b, "A17.copy.grade-and-tics"), "A17.copy.grade-and-tics", "FAIL:", "a tic word"); bites++;
            }
            return "empty root: 4 clauses NOT RUN PRODUCT_MISSING; good tree: 4 PASS" + (ticGate ? "" : " (copy clause NOT RUN TOOL_MISSING: no tic-gate.py)") + "; " + bites + " one-change trees each FAIL; prose about a real HSM still passes";
        }

        // ---------------------------------------------------------------- A15a binding

        static string TourJson(string claimText, string stepText, string textMine, bool extraClaim)
        {
            StringBuilder sb = new StringBuilder("{\"lesson\":6,\"claims\":[{\"id\":\"L6-C01\",\"text\":\"" + claimText + "\",\"source\":\"docs/names.md\"}");
            if (extraClaim) sb.Append(",{\"id\":\"L6-C02\",\"text\":\"A second claim.\",\"source\":\"docs/names.md\"}");
            sb.Append("],\"steps\":[");
            for (int i = 1; i <= 3; i++)
            {
                if (i > 1) sb.Append(',');
                string text = i == 1 ? stepText : "Step " + i + " has plain words.";
                sb.Append("{\"id\":\"L6-S0" + i + "\",\"lesson\":6,\"title\":\"Step " + i + "\",\"text\":[\"" + text + "\"],\"glossary\":[],\"bind\":{\"kind\":\"concept\"}");
                if (i == 1 && textMine != null) sb.Append(",\"textMine\":[\"" + textMine + "\"]");
                sb.Append('}');
            }
            return sb.Append("]}").ToString();
        }

        static string Verdict(string reader, string claimVerdict, string claimHash, string textHash, int stepsRead, int problemsOpen, string claimId)
        {
            return "{\"reader\":\"" + reader + "\",\"authors\":[\"author-y\"],\"claims\":[{\"id\":\"" + claimId + "\",\"verdict\":\"" + claimVerdict + "\"" + (claimHash == null ? "" : ",\"textHash\":\"" + claimHash + "\"") + "}]," +
                   "\"textRead\":{\"stepsRead\":" + stepsRead + ",\"problemsFound\":" + problemsOpen + ",\"problemsOpen\":" + problemsOpen + ",\"problems\":[]" + (textHash == null ? "" : ",\"textHash\":\"" + textHash + "\"") + "}}";
        }

        static string[] Hashes(Ctx c, string root)
        {
            string script = Path.Combine(c.AcceptanceDir, "checks", "docs_checks.py"), output;
            Check.True(Proc.Run("python", "-I \"" + script + "\" --root \"" + root + "\" --hashes", null, 60000, out output) == 0, "docs_checks.py --hashes failed: " + output);
            Dictionary<string, object> lesson = MiniJson.Obj(MiniJson.AsObject(MiniJson.Parse(output)), "6");
            string claim = MiniJson.Str(MiniJson.AsObject(MiniJson.Arr(lesson, "claims")[0]), "textHash"), text = MiniJson.Str(MiniJson.Obj(lesson, "textRead"), "textHash");
            return new string[] { claim, text };
        }

        const string Claim = "A managed heap can keep copies of an erased key.";
        const string StepText = "The pad makes a new key for each sale.";

        static Dictionary<string, string> A15a(Ctx c, string root, string tour, string verdict)
        {
            Put(root, "app/src/tours/lesson-06.json", tour);
            Put(root, "app/src/glossary.json", "{\"terms\":[{\"id\":\"key\",\"term\":\"key\",\"short\":\"A secret number.\"}]}");
            Put(root, "docs/_verdicts/a15a-lesson-06.json", verdict);
            return Docs(c, root, "A15a.tours.reader-verdicts");
        }

        [Clause("SELF.a17-a15a-binding-bites")]
        public static string BindingBites(Ctx c)
        {
            const string id = "A15a.tours.reader-verdicts";
            string tmp = Path.Combine(c.WorkDir, "a15a-bind");
            // The reader stamps the hashes of the tour as it stands. Then the verdict binds.
            string baseRoot = Path.Combine(tmp, "base");
            Put(baseRoot, "app/src/tours/lesson-06.json", TourJson(Claim, StepText, null, false));
            Put(baseRoot, "app/src/glossary.json", "{\"terms\":[{\"id\":\"key\",\"term\":\"key\",\"short\":\"A secret number.\"}]}");
            string[] h = Hashes(c, baseRoot);
            string goodVerdict = Verdict("reader-x", "accurate", h[0], h[1], 3, 0, "L6-C01");
            Expect(A15a(c, Path.Combine(tmp, "good"), TourJson(Claim, StepText, null, false), goodVerdict), id, "PASS:", "a verdict bound to the tour");

            int bites = 0;
            // Text changed after the read.
            Expect(A15a(c, Path.Combine(tmp, "step-changed"), TourJson(Claim, "The pad makes two keys for each sale.", null, false), goodVerdict), id, "NOT RUN:ACCURACY_VERDICT_STALE", "a step sentence changed"); bites++;
            Expect(A15a(c, Path.Combine(tmp, "mine-added"), TourJson(Claim, StepText, "On your key the root is yours.", false), goodVerdict), id, "NOT RUN:ACCURACY_VERDICT_STALE", "a textMine variant added"); bites++;
            Expect(A15a(c, Path.Combine(tmp, "claim-changed"), TourJson("A managed heap never keeps copies of an erased key.", StepText, null, false), goodVerdict), id, "NOT RUN:ACCURACY_VERDICT_STALE", "a claim changed"); bites++;
            Expect(A15a(c, Path.Combine(tmp, "claim-added"), TourJson(Claim, StepText, null, true), goodVerdict), id, "NOT RUN:ACCURACY_VERDICT_STALE", "a claim with no verdict"); bites++;
            Expect(A15a(c, Path.Combine(tmp, "claim-orphan"), TourJson(Claim, StepText, null, false), Verdict("reader-x", "accurate", h[0], h[1], 3, 0, "L6-C09")), id, "NOT RUN:ACCURACY_VERDICT_STALE", "a verdict for a claim the tour does not declare"); bites++;
            Expect(A15a(c, Path.Combine(tmp, "steps-count"), TourJson(Claim, StepText, null, false), Verdict("reader-x", "accurate", h[0], h[1], 2, 0, "L6-C01")), id, "NOT RUN:ACCURACY_VERDICT_STALE", "a reader who read fewer steps than the tour has"); bites++;
            // Verdicts that carry no hash cannot bind.
            Expect(A15a(c, Path.Combine(tmp, "no-claim-hash"), TourJson(Claim, StepText, null, false), Verdict("reader-x", "accurate", null, h[1], 3, 0, "L6-C01")), id, "NOT RUN:ACCURACY_VERDICT_UNBOUND", "a claim verdict with no hash"); bites++;
            Expect(A15a(c, Path.Combine(tmp, "no-text-hash"), TourJson(Claim, StepText, null, false), Verdict("reader-x", "accurate", h[0], null, 3, 0, "L6-C01")), id, "NOT RUN:ACCURACY_VERDICT_UNBOUND", "a step-text result with no hash"); bites++;
            // A bound verdict that says no.
            Expect(A15a(c, Path.Combine(tmp, "inaccurate"), TourJson(Claim, StepText, null, false), Verdict("reader-x", "inaccurate", h[0], h[1], 3, 0, "L6-C01")), id, "FAIL:", "a claim judged inaccurate"); bites++;
            Expect(A15a(c, Path.Combine(tmp, "open-problem"), TourJson(Claim, StepText, null, false), Verdict("reader-x", "accurate", h[0], h[1], 3, 1, "L6-C01")), id, "FAIL:", "a step-text problem still open"); bites++;
            Expect(A15a(c, Path.Combine(tmp, "self-read"), TourJson(Claim, StepText, null, false), Verdict("author-y", "accurate", h[0], h[1], 3, 0, "L6-C01")), id, "FAIL:", "the reader is the author"); bites++;
            return "a verdict bound to claim id and text hash PASSes; " + bites + " variants (step, textMine or claim text changed, claim added or orphaned, fewer steps read, hash missing, claim inaccurate, problem open, reader is the author) each read FAIL or NOT RUN with the named reason";
        }
    }
}
