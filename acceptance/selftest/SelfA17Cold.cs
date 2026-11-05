using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// Proof that the cold-reader clause bites. A fake Host makes a real token on a learner's key, a stand-in repository holds the reader's verdict,
    /// and each defect in the verdict (a builder as reader, a built-in key, a changed token, a commit that does not exist, words too hard) must FAIL.
    /// With no verdict file the clause reads NOT RUN COLD_READER_PENDING, never PASS.
    /// </summary>
    public static class SelfA17Cold
    {
        static string Script(Ctx c) { return Path.Combine(c.AcceptanceDir, "selftest", "FakeHost", "fakevault.py"); }

        static FakeHost NewFake(Ctx c, string tag) { return new FakeHost(Path.Combine(c.WorkDir, "fake-" + tag), "", Referees.OpenSsl(c), Script(c)); }

        static Ctx Attach(Ctx c, string repo, FakeHost f, string tag)
        {
            Ctx n = new Ctx();
            n.Build = "net10"; n.VectorsDir = c.VectorsDir; n.AcceptanceDir = c.AcceptanceDir; n.RepoRoot = repo;
            n.WorkDir = Path.Combine(c.WorkDir, "run-" + tag);
            Directory.CreateDirectory(n.WorkDir);
            foreach (KeyValuePair<string, string> kv in c.Props) n.Props[kv.Key] = kv.Value;
            n.Props.Remove("host");
            n.Props["a17.attach"] = f.Port + "," + f.Token + "," + f.Dir;
            return n;
        }

        static void G(string dir, string args)
        {
            string o;
            if (Proc.Run("git", "-C \"" + dir + "\" " + args, dir, 60000, out o) != 0) throw new FailException("self-test setup: git " + args + ": " + o.Trim());
        }

        static void Put(string root, string rel, string text)
        {
            string p = Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(p));
            File.WriteAllText(p, text);
        }

        /// <summary>The token and public key a lesson 10 run shows on the given Host.</summary>
        static void TokenOf(Ctx c, FakeHost fake, bool learnerKey, string tag, out string token, out string pubHex)
        {
            Ctx n = Attach(c, c.RepoRoot, fake, tag);
            using (HostProc h = HostProc.Start(n, tag, null))
            {
                if (learnerKey) A17.RunFlow(h, "my-login");
                SessionRun run = HostSession.Run(h, 10, "glass", null);
                token = null; pubHex = null;
                foreach (A17.SecretRef s in A17.Secrets(run))
                {
                    if (s.Name == "auth.token") token = Encoding.ASCII.GetString(Hex.Decode(s.Hex));
                    if (s.Name == "auth.issuer-public") pubHex = s.Hex.ToLowerInvariant();
                }
                Check.True(token != null && pubHex != null, "self-test setup: the fake gave no token");
            }
        }

        static string Verdict(string name, string kind, bool fresh, string commit, bool understood, string token, string pubHex, bool agentFresh)
        {
            Dictionary<string, object> reader = new Dictionary<string, object> { { "name", name }, { "kind", kind } };
            if (kind == "agent") reader["freshContext"] = agentFresh;
            return MiniJson.Write(new Dictionary<string, object>
            {
                { "reader", reader },
                { "clone", new Dictionary<string, object> { { "fresh", fresh }, { "commit", commit } } },
                { "keys", new Dictionary<string, object> { { "issuerPublicHex", pubHex } } },
                { "run", new Dictionary<string, object> { { "lesson", 10.0 }, { "token", token } } },
                { "understoodWithoutHelp", understood },
            });
        }

        static string Outcome(Ctx c)
        {
            try { return "PASS: " + ColdClauses.ColdLesson10(c); }
            catch (NotRunException ex) { return "NOT RUN " + ex.Reason + ": " + ex.Message; }
            catch (FailException ex) { return "FAIL: " + ex.Message; }
        }

        static void Expect(string got, string prefix, string label) { Check.True(got.StartsWith(prefix), label + ": expected " + prefix + ", gave " + got); }

        [Clause("SELF.a17-cold-clause-bites")]
        public static string ColdClauseBites(Ctx c)
        {
            // A stand-in repository: plain tour and wizard words, one commit.
            string repo = Path.Combine(c.WorkDir, "cold-repo");
            Directory.CreateDirectory(repo);
            G(repo, "init --quiet"); G(repo, "config user.email self@example.invalid"); G(repo, "config user.name self");
            Put(repo, "app/src/tours/lesson-06.json", "{\"lesson\":6,\"steps\":[{\"id\":\"L6-S01\",\"lesson\":6,\"title\":\"Step 1\",\"text\":[\"The pad makes a new key for each sale.\"],\"glossary\":[],\"bind\":{\"kind\":\"concept\"}}]}");
            Put(repo, "app/src/glossary.json", "{\"terms\":[{\"id\":\"key\",\"term\":\"key\",\"short\":\"A secret number.\"}]}");
            Put(repo, "app/src/wizard-copy.json", "{\"wizard.common.test-keys-only\":\"Use test keys only. This course shows your keys on screen and in saved files.\"}");
            G(repo, "add ."); G(repo, "commit --quiet -m init");
            string o;
            Proc.Run("git", "-C \"" + repo + "\" rev-parse HEAD", repo, 30000, out o);
            string head = o.Trim();

            string readerToken, readerPub;
            using (FakeHost readerFake = NewFake(c, "reader")) TokenOf(c, readerFake, true, "reader", out readerToken, out readerPub);

            Dictionary<string, string> cases = new Dictionary<string, string>();
            int bites = 0;
            // Each case gets a fresh fake, because "built-in key" is judged against that Host's own built-in issuer key.
            Func<string, string, string, string> run = delegate (string tag, string verdict, string wizardCopy)
            {
                using (FakeHost fake = NewFake(c, tag))
                {
                    string verdicts = Path.Combine(repo, "docs", "_verdicts", ColdClauses.VerdictFile);
                    if (verdict == null) { if (File.Exists(verdicts)) File.Delete(verdicts); }
                    else Put(repo, "docs/_verdicts/" + ColdClauses.VerdictFile, verdict);
                    if (wizardCopy != null) Put(repo, "app/src/wizard-copy.json", wizardCopy);
                    return Outcome(Attach(c, repo, fake, tag));
                }
            };
            const string goodCopy = "{\"wizard.common.test-keys-only\":\"Use test keys only. This course shows your keys on screen and in saved files.\"}";

            Expect(run("good", Verdict("Sam Reader", "human", true, head, true, readerToken, readerPub, false), goodCopy), "PASS", "a named human on their own key");
            Expect(run("agent-ok", Verdict("fresh-reader-7", "agent", true, head, true, readerToken, readerPub, true), goodCopy), "PASS", "a fresh agent on their own key");
            Expect(run("pending", null, goodCopy), "NOT RUN COLD_READER_PENDING", "no verdict file");
            Expect(run("builder", Verdict("Echo", "agent", true, head, true, readerToken, readerPub, true), goodCopy), "FAIL", "a builder as the reader"); bites++;
            Expect(run("agent-stale", Verdict("fresh-reader-7", "agent", true, head, true, readerToken, readerPub, false), goodCopy), "FAIL", "an agent reader with memory"); bites++;
            Expect(run("not-understood", Verdict("Sam Reader", "human", true, head, false, readerToken, readerPub, false), goodCopy), "FAIL", "a reader who needed help"); bites++;
            Expect(run("not-fresh", Verdict("Sam Reader", "human", false, head, true, readerToken, readerPub, false), goodCopy), "FAIL", "a clone that was not fresh"); bites++;
            Expect(run("bad-commit", Verdict("Sam Reader", "human", true, new string('0', 40), true, readerToken, readerPub, false), goodCopy), "FAIL", "a commit the repository does not hold"); bites++;
            string[] parts = readerToken.Split('.');
            string changed = parts[0] + "." + parts[1] + "." + (parts[2][0] == 'A' ? "B" : "A") + parts[2].Substring(1);
            Expect(run("tampered", Verdict("Sam Reader", "human", true, head, true, changed, readerPub, false), goodCopy), "FAIL", "a token with a changed signature"); bites++;
            // A token from the fake's built-in key, which the clause's own Host also shows as its built-in key.
            using (FakeHost builtinFake = NewFake(c, "builtin"))
            {
                string bt, bp;
                TokenOf(c, builtinFake, false, "builtin-token", out bt, out bp);
                string verdicts = Path.Combine(repo, "docs", "_verdicts");
                Put(repo, "docs/_verdicts/" + ColdClauses.VerdictFile, Verdict("Sam Reader", "human", true, head, true, bt, bp, false));
                Expect(Outcome(Attach(c, repo, builtinFake, "builtin-run")), "FAIL", "a reader who ran on the built-in key"); bites++;
            }
            Expect(run("hard-words", Verdict("Sam Reader", "human", true, head, true, readerToken, readerPub, false),
                "{\"wizard.hard\":\"Cryptographic authentication necessitates comprehensive interoperability considerations notwithstanding organizational infrastructure.\"}"), "FAIL", "words the reader saw that read too hard"); bites++;
            return "a named human and a fresh agent on their own keys PASS; " + bites + " defects (builder as reader, agent with memory, reader needed help, clone not fresh, unknown commit, changed token, built-in key, hard words) each FAIL; no verdict file reads NOT RUN COLD_READER_PENDING";
        }
    }
}
