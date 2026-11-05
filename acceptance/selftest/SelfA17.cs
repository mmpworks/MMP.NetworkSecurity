using System;
using System.Collections.Generic;
using System.IO;

namespace Acceptance
{
    /// <summary>
    /// Proof that the A17 clauses bite. The real clause bodies run against a fake Host built from acceptance/CONTRACT.md section 5.
    /// A faithful fake must give PASS. The same fake with one named defect must give FAIL for the clause that owns the defect.
    /// With no Host at all, every clause must read NOT RUN PRODUCT_MISSING, never PASS.
    /// </summary>
    public static class SelfA17
    {
        delegate string Body(Ctx c);

        sealed class Case
        {
            public string Id; public Body Run; public string[] Mutations;
            public Case(string id, Body run, params string[] mutations) { Id = id; Run = run; Mutations = mutations; }
        }

        static readonly Case[] Cases = new Case[]
        {
            new Case("A17.readiness.refuses-by-name", V0Clauses.ReadinessRefusesByName, "ready-runs-anyway", "ready-no-name", "proven-not-checked", "ready-code-wrong"),
            new Case("A17.readiness.types-disagree", V0Clauses.TypesDisagree, "disagree-ignored"),
            new Case("A17.import.warns-on-personal-ssh-path", V0Clauses.WarnsOnPersonalSshPath, "no-personal-warning"),
            new Case("A17.flow.login.walk", V0Clauses.LoginWalk, "machine-allows-any", "stale-accepted", "back-after-check", "no-judge-facts", "device-judge-claimed"),
            new Case("A17.referee.token-issuer-go", V0Clauses.TokenIssuerGo, "token-wrong-key", "key-route-other-public", "pub-in-trace-wrong"),
        };

        static string Outcome(Body b, Ctx c)
        {
            try { return "PASS: " + b(c); }
            catch (NotRunException ex) { return "NOT RUN " + ex.Reason + ": " + ex.Message; }
            catch (FailException ex) { return "FAIL: " + ex.Message; }
        }

        static Ctx WithFake(Ctx c, FakeHost fake, string tag)
        {
            Ctx n = new Ctx();
            n.Build = "net10"; n.VectorsDir = c.VectorsDir; n.AcceptanceDir = c.AcceptanceDir; n.RepoRoot = c.RepoRoot;
            n.WorkDir = Path.Combine(c.WorkDir, "a17-" + tag);
            Directory.CreateDirectory(n.WorkDir);
            foreach (KeyValuePair<string, string> kv in c.Props) n.Props[kv.Key] = kv.Value;
            n.Props.Remove("host");
            n.Props["a17.attach"] = fake.Port + "," + fake.Token + "," + fake.Dir;
            return n;
        }

        static string Against(Ctx c, Case k, string mutation)
        {
            string tag = k.Id.Replace('.', '-') + "-" + (mutation.Length == 0 ? "good" : mutation);
            string dir = Path.Combine(c.WorkDir, "fake-" + tag);
            using (FakeHost fake = new FakeHost(dir, mutation, Referees.OpenSsl(c)))
                return Outcome(k.Run, WithFake(c, fake, tag));
        }

        [Clause("SELF.a17-clauses-pass-and-bite")]
        public static string ClausesPassAndBite(Ctx c)
        {
            int passes = 0, bites = 0;
            List<string> notRun = new List<string>();
            foreach (Case k in Cases)
            {
                string good = Against(c, k, "");
                if (good.StartsWith("NOT RUN")) { notRun.Add(k.Id + " (" + good.Substring(0, Math.Min(good.Length, 90)) + ")"); continue; }
                Check.True(good.StartsWith("PASS"), k.Id + " should PASS on the faithful fake, gave " + good);
                passes++;
                foreach (string m in k.Mutations)
                {
                    string bad = Against(c, k, m);
                    Check.True(bad.StartsWith("FAIL"), k.Id + " should FAIL when the fake has the defect '" + m + "', gave " + bad);
                    bites++;
                }
            }
            if (passes == 0) throw new NotRunException("REFEREE_MISSING", "no A17 clause could run on the fake: " + string.Join("; ", notRun.ToArray()));
            return passes + " clauses PASS on the faithful fake; " + bites + " named defects each FAIL their clause" + (notRun.Count > 0 ? "; NOT RUN: " + string.Join("; ", notRun.ToArray()) : "");
        }

        [Clause("SELF.a17-absent-host-is-not-run")]
        public static string AbsentHostIsNotRun(Ctx c)
        {
            Ctx n = new Ctx();
            n.Build = "net10"; n.VectorsDir = c.VectorsDir; n.AcceptanceDir = c.AcceptanceDir; n.RepoRoot = c.RepoRoot;
            n.WorkDir = Path.Combine(c.WorkDir, "a17-absent");
            Directory.CreateDirectory(n.WorkDir);
            foreach (Case k in Cases)
            {
                string r = Outcome(k.Run, n);
                Check.True(r.StartsWith("NOT RUN PRODUCT_MISSING"), k.Id + " with no Host should read NOT RUN PRODUCT_MISSING, gave " + r);
            }
            return Cases.Length + " clauses with no Host each read NOT RUN PRODUCT_MISSING";
        }
    }
}
