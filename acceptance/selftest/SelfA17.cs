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
            new Case("A17.import.warns-on-personal-ssh-path", V0Clauses.WarnsOnPersonalSshPath, "no-personal-warning", "personal-path-is-error"),
            new Case("A17.flow.login.walk", V0Clauses.LoginWalk, "machine-allows-any", "stale-accepted", "no-judge-facts", "device-judge-claimed"),
            new Case("A17.referee.token-issuer-go", V0Clauses.TokenIssuerGo, "token-wrong-key", "key-route-other-public", "pub-in-trace-wrong"),
            new Case("A17.show-keys.default-on", V3Clauses.DefaultOn, "default-off", "no-health-showkeys"),
            new Case("A17.show-keys.off-holds-no-secret", V3Clauses.OffHoldsNoSecret, "off-keeps-hex-in-events", "off-keeps-hex-in-file", "off-hex-in-frames", "off-hex-in-message", "off-hex-in-plain", "wire-carries-a-key", "hidden-missing", "keylog-served-when-off"),
            new Case("A17.show-keys.mine-shows-exportable", V3Clauses.MineShowsExportable, "mine-key-route-no-hex", "no-key-in-use"),
            new Case("A17.show-keys.non-exportable-hidden-when-on", V3Clauses.NonExportableHiddenWhenOn, "exercise-key-leaks"),
            new Case("A17.show-keys.fingerprint-compare", V3Clauses.FingerprintCompare, "fingerprint-wrong"),
            new Case("A17.vault.export-refused-and-audited", V1Clauses.ExportRefusedAndAudited, "export-not-audited", "export-allowed"),
            new Case("A17.vault.exercise-sign-judged-by-openssl", V1Clauses.ExerciseSignJudgedByOpenssl, "sign-bad-signature"),
            new Case("A17.vault.exercise-walk", V1Clauses.ExerciseWalk, "derive-random", "audit-check-blind", "export-allowed"),
            new Case("A17.vault.audit-check-names-limits", V1Clauses.AuditLimits, "limits-missing", "limits-names-two", "limits-only-on-pass"),
            new Case("A17.vault.export-audited-with-caller", V1Clauses.ExportAuditedWithCaller, "export-caller-missing", "export-as-course-read", "course-read-unaudited"),
            new Case("A17.vault.tampered-row-refused", V1Clauses.TamperedRowRefused, "tamper-ignored"),
            new Case("A17.vault.audit-failure-refuses", V1Clauses.AuditFailureRefuses, "audit-failure-ignored"),
            new Case("A17.vault.exportable-is-one-way", V1Clauses.ExportableIsOneWay, "exercise-key-exportable", "export-allowed"),
            new Case("A17.flow.certificates.walk", WalkClauses.Certificates, "readback-drops-type", "says-trusted", "version-not-bumped", "no-judge-facts"),
            new Case("A17.flow.ssh.walk", WalkClauses.Ssh, "readback-drops-type", "version-not-bumped"),
            new Case("A17.flow.payment.known-answer-walk", WalkClauses.Payment, "dukpt-judge-claimed", "readback-drops-type"),
            new Case("A17.flow.lesson-keys.walk", WalkClauses.LessonKeys, "readback-drops-type"),
            new Case("A17.payment.known-answer-vectors-through-flow-code", WalkClauses.PaymentKnownAnswer, "dukpt-pad-constant"),
            new Case("A17.referee.lesson-keys-openssl-mac", LessonKeysReferee.LessonKeysOpensslMac, "mac-wrong-key"),
            new Case("A17.proof.root-negative-control", CertClauses.RootNegativeControl, "check-self-verifies"),
            new Case("A17.chain.alg-unsupported-named", CertClauses.AlgUnsupportedNamed, "alg-reports-cert-signature"),
            new Case("A17.clock.new-certificate-not-expired", CertClauses.NewCertificateNotExpired, "clock-fixed", "expired-not-named"),
            new Case("A17.attacks.unavailable-names-code", CertClauses.UnavailableNamesCode, "attack-always-available"),
            new Case("A17.attacks.hit-named-field", CertClauses.HitNamedField, "attack-wrong-field"),
            new Case("A17.lesson-1.my-keys", MyKeysClauses.L1, "mine-run-differs", "builtin-half"),
            new Case("A17.lesson-2.my-keys", MyKeysClauses.L2, "mine-run-differs", "builtin-half"),
            new Case("A17.lesson-4.my-keys", MyKeysClauses.L4, "mine-run-differs", "builtin-half"),
            new Case("A17.lesson-5.my-keys", MyKeysClauses.L5, "mine-run-differs", "builtin-half"),
            new Case("A17.lesson-6.my-keys", MyKeysClauses.L6, "mine-run-differs", "builtin-half"),
            new Case("A17.lesson-7.my-keys", MyKeysClauses.L7, "mine-run-differs", "builtin-half"),
            new Case("A17.lesson-8.my-keys", MyKeysClauses.L8, "mine-run-differs", "builtin-half"),
            new Case("A17.lesson-9.my-keys", MyKeysClauses.L9, "mine-run-differs", "builtin-half"),
            new Case("A19.host.tables-equal-fips-and-stay-open", AesWalkHostClauses.TablesEqualFips, "walk-table-flip", "walk-tables-closed-off"),
            new Case("A19.host.block-real-run-two-seeds", AesWalkHostClauses.BlockRealRun, "walk-canned", "walk-state-flip", "walk-inverse-order", "walk-key-row-flip", "walk-input-other", "walk-word-test-wrong"),
            new Case("A17.attacks.every-row-forks-to-its-code", AttackRowClauses.EveryRowForksToItsCode, "attack-finish-other-code", "attack-finish-no-check", "attack-row-unavailable"),
            new Case("A19.host.practice-key-192-256", AesWalkHostClauses.PracticeKeySizes, "walk-practice-no-xor", "walk-practice-says-run", "walk-block-open-off"),
            new Case("A19.host.show-keys-off-closes-block-first", AesWalkHostClauses.OffClosesBlock, "walk-block-open-off", "walk-session-before-toggle", "walk-off-error-bytes", "walk-tables-closed-off"),
            new Case("A19.host.replies-carry-no-store", AesWalkHostClauses.NoStore, "walk-no-store-missing"),
            new Case("A19.host.errors-carry-a-code", AesWalkHostClauses.Errors, "walk-lesson-wrong-code", "walk-bad-argument-500", "walk-no-request-id"),
            new Case("A19.host.walk-adds-no-trace-event", AesWalkHostClauses.AddsNoEvent, "walk-adds-event", "walk-state-in-events"),
            new Case("A19.host.tables-carry-maps-rcon-sizes", AesWalkHostClauses.TablesCarryMaps, "walk-map-wrong", "walk-rcon-wrong", "walk-sizes-wrong"),
            new Case("A19.host.rcon-steps", AesWalkHostClauses.RconSteps, "walk-rcon-steps-missing", "walk-rcon-steps-short", "walk-rcon-steps-drop-bit", "walk-rcon-steps-all-reduced"),
            new Case("A19.host.block-terms-real-run", AesWalkHostClauses.BlockTerms, "walk-canned", "walk-term-flip", "walk-no-terms", "walk-doubling-bytes", "walk-running-wrong"),
            new Case("A19.host.off-holds-no-word-or-term", AesWalkHostClauses.OffHoldsNoWord, "walk-block-open-off", "walk-off-error-bytes", "walk-tables-leak-key", "walk-off-error-terms", "walk-tables-leak-terms", "walk-tables-leak-words"),
            new Case("A19.host.ecb-fork-says-match", AesWalkHostClauses.EcbForkMatches, "walk-fork-not-sent", "walk-fork-other-key"),
            new Case("A19.host.control-run-says-not-sent", AesWalkHostClauses.ControlNotSent, "walk-label-match"),
            new Case("A17.lesson-10.my-keys", MyKeysClauses.L10, "mine-run-differs", "builtin-half", "no-key-in-use"),
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
            using (FakeHost fake = new FakeHost(dir, mutation, Referees.OpenSsl(c), Path.Combine(c.AcceptanceDir, "selftest", "FakeHost", "fakevault.py")))
                return Outcome(k.Run, WithFake(c, fake, tag));
        }

        [Clause("SELF.a17-part-not-built-is-not-run")]
        public static string PartNotBuiltIsNotRun(Ctx c)
        {
            const string Part = "WIZARD_PART_NOT_BUILT";
            List<string> one = new List<string> { "The course cannot make x yet." };
            bool notRun = false;
            try { A17.NotRunIfOnlyPartNotBuilt(new List<string> { Part, Part }, one, "a step"); }
            catch (NotRunException e) { notRun = e.Reason == Part && e.Message.Contains("cannot make x"); }
            Check.True(notRun, "only WIZARD_PART_NOT_BUILT should read NOT RUN and name the owed part");
            A17.NotRunIfOnlyPartNotBuilt(new List<string> { Part, "WIZARD_TYPE_NOT_IN_FLOW" }, one, "a step");
            A17.NotRunIfOnlyPartNotBuilt(new List<string> { "KEY_FILE_UNREADABLE" }, one, "a step");
            A17.NotRunIfOnlyPartNotBuilt(new List<string>(), one, "a step");
            return "only WIZARD_PART_NOT_BUILT throws NOT RUN; a second code, another code, and no code each go on to the clause's own check";
        }

        // One row ran all cases and outgrew the runner's 900 s budget for one clause. The cases now run in 4 rows by area. The last row takes
        // every case the first 3 leave, so each case runs in exactly one row, and a new case cannot fall between them.
        static bool LessonRow(string id) { return id.StartsWith("A17.lesson-", StringComparison.Ordinal); }
        static bool HostWalkRow(string id) { return id.StartsWith("A19.host.", StringComparison.Ordinal); }
        static bool VaultKeysRow(string id) { return id.StartsWith("A17.vault", StringComparison.Ordinal) || id.StartsWith("A17.show-keys", StringComparison.Ordinal); }

        [Clause("SELF.a17-clauses-pass-and-bite-lessons")]
        public static string PassAndBiteLessons(Ctx c) { return ClausesPassAndBite(c, LessonRow); }

        [Clause("SELF.a17-clauses-pass-and-bite-walk-host")]
        public static string PassAndBiteWalkHost(Ctx c) { return ClausesPassAndBite(c, HostWalkRow); }

        [Clause("SELF.a17-clauses-pass-and-bite-vault-keys")]
        public static string PassAndBiteVaultKeys(Ctx c) { return ClausesPassAndBite(c, VaultKeysRow); }

        [Clause("SELF.a17-clauses-pass-and-bite-rest")]
        public static string PassAndBiteRest(Ctx c) { return ClausesPassAndBite(c, delegate (string id) { return !LessonRow(id) && !HostWalkRow(id) && !VaultKeysRow(id); }); }

        static string ClausesPassAndBite(Ctx c, Predicate<string> inRow)
        {
            int passes = 0, bites = 0;
            List<string> notRun = new List<string>();
            // ACC_SELF_ONLY keeps only the clauses whose id holds that text, so one clause can be run again while it is being fixed.
            string only = Environment.GetEnvironmentVariable("ACC_SELF_ONLY");
            foreach (Case k in Cases)
            {
                if (!inRow(k.Id)) continue;
                if (!string.IsNullOrEmpty(only) && k.Id.IndexOf(only, StringComparison.Ordinal) < 0) continue;
                string good = Against(c, k, "");
                // On the faithful fake, the fake is the product, so PRODUCT_MISSING here means the clause cannot reach what it needs. A lesson 1 clause went dark this way until a person read the code.
                if (good.StartsWith("NOT RUN PRODUCT_MISSING")) Check.True(false, k.Id + " cannot reach what it needs on the faithful fake: " + good);
                if (good.StartsWith("NOT RUN")) { notRun.Add(k.Id + " (" + good.Substring(0, Math.Min(good.Length, 90)) + ")"); continue; }
                Check.True(good.StartsWith("PASS"), k.Id + " should PASS on the faithful fake, gave " + good);
                passes++;
                foreach (string m in k.Mutations)
                {
                    string bad = Against(c, k, m);
                    Check.True(bad.StartsWith("FAIL"), k.Id + " should FAIL when the fake has the defect '" + m + "', gave " + bad);
                    bites++;
                    // ACC_SELF_LOG names a file that receives one line per defect with the reason the clause gave, so a person can check each FAIL is for the right reason.
                    string log = Environment.GetEnvironmentVariable("ACC_SELF_LOG");
                    if (!string.IsNullOrEmpty(log)) File.AppendAllText(log, m + " => " + bad.Substring(0, Math.Min(bad.Length, 230)) + "\n");
                }
            }
            if (passes == 0) throw new NotRunException("REFEREE_MISSING", "no A17 clause could run on the fake: " + string.Join("; ", notRun.ToArray()));
            return passes + " clauses PASS on the faithful fake; " + bites + " named defects each FAIL their clause" + (notRun.Count > 0 ? "; NOT RUN: " + string.Join("; ", notRun.ToArray()) : "");
        }

        /// <summary>
        /// HostSession.Run and Fork read one connection. When another session of the same Host ends on that connection first, the run must keep reading until its own session ends,
        /// and must say how many foreign frames it passed. The fake sends a foreign trace event and a foreign session.finished (code FOREIGN_SESSION) ahead of the run's own frames.
        /// </summary>
        [Clause("SELF.a17-drive-takes-own-session")]
        public static string DriveTakesOwnSession(Ctx c)
        {
            int[] baseEvents = new int[2];
            string summary = "";
            foreach (string mutation in new string[] { "", "foreign-finish-first" })
            {
                bool foreign = mutation.Length > 0;
                string tag = "drive-" + (foreign ? "foreign" : "good");
                using (FakeHost fake = new FakeHost(Path.Combine(c.WorkDir, "fake-" + tag), mutation, Referees.OpenSsl(c), Path.Combine(c.AcceptanceDir, "selftest", "FakeHost", "fakevault.py")))
                using (HostProc h = A17.Host(WithFake(c, fake, tag), tag))
                {
                    SessionRun lesson = HostSession.Run(h, 4, "glass", null);
                    SessionRun fork = HostSession.Fork(h, lesson.SessionId, "L4-flip-cert-byte");
                    SessionRun[] runs = new SessionRun[] { lesson, fork };
                    string[] names = new string[] { "the run", "the fork" };
                    for (int i = 0; i < runs.Length; i++)
                    {
                        SessionRun r = runs[i];
                        string what = names[i] + (foreign ? " with a foreign session ahead of it" : "");
                        Check.True(r.Finished != null, what + " did not finish");
                        Check.Equal(what + ": the session that finished", r.SessionId, MiniJson.Str(r.Finished, "sessionId"));
                        Check.True(MiniJson.Str(r.Finished, "code") != "FOREIGN_SESSION", what + " took the foreign session's finish as its own");
                        foreach (Dictionary<string, object> ev in r.Events)
                            Check.True(!(MiniJson.Str(ev, "streamId") ?? "").StartsWith("s-other/", StringComparison.Ordinal), what + " kept an event of the foreign session");
                        Check.Equal(what + ": frames of another session passed", foreign ? 2 : 0, r.ForeignFrames);
                        if (!foreign) baseEvents[i] = r.Events.Count;
                        else Check.Equal(what + ": events kept, against the run without a foreign session", baseEvents[i], r.Events.Count);
                    }
                    Check.Equal("the fork's ending code", "CERT_SIGNATURE", MiniJson.Str(fork.Finished, "code"));
                    summary += (foreign ? "; with a foreign session ahead: " : "without: ") + lesson.Events.Count + " + " + fork.Events.Count + " events, own finish, " + (lesson.ForeignFrames + fork.ForeignFrames) + " foreign frames passed";
                }
            }
            return "Run and Fork read only their own session: " + summary;
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
