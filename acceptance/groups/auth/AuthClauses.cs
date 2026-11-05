using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Labs;
using NetSec.Platform;
using NetSec.Trace;

namespace Acceptance
{
    /// <summary>
    /// A11: mutual TLS, tokens, DPoP replay and role checks each have a passing control and an attack that differs by one field
    /// and gets a named rejection. The attacks are the rows of AttackCatalog (program-design.md section 2.5); this group runs each
    /// row beside its control and compares ExpectCode and ExpectCheck. A token from the product verifies under the Go tokenverify
    /// referee. Passkey and capabilities are cut first (roles.json auth.passkey, auth.capabilities).
    /// </summary>
    public static class AuthClauses
    {
        sealed class LabRun
        {
            public bool Completed; public string Code, Check; public RecordingSink Sink;
            public override string ToString() { return Completed ? "completed" : "stopped at " + (Check ?? "?") + " [" + (Code ?? "?") + "]"; }
        }

        static LabRun RunLab(int lesson, AttackDefinition attack, int seed)
        {
            ILab lab = LabCatalog.Find(lesson);
            LabContext ctx = new LabContext();
            LabRun r = new LabRun();
            r.Sink = new RecordingSink();
            ctx.Seed = seed;
            ctx.Transports = new GlassTransportFactory(new TrainingKeySource());
            ctx.Gate = new OpenGate();
            ctx.Sink = r.Sink;
            ctx.Clock = new MonotonicClock();
            ctx.Random = new TestRandom((ulong)seed);
            ctx.Attack = attack;
            IFuture<LabResult> f = lab.Run(ctx);
            if (!f.Wait(120000)) throw new FailException("lesson " + lesson + " lab did not finish in 120 s");
            if (f.IsFaulted) throw new FailException("lesson " + lesson + " lab faulted: " + f.Exception);
            LabResult res = f.Result;
            r.Completed = res.Completed; r.Code = res.FailedCode ?? r.Sink.FailedCheckCode; r.Check = res.FailedCheck;
            return r;
        }

        /// <summary>Runs one row beside its control and compares the expectation. Returns a one-line summary.</summary>
        static string RowBesideControl(AttackDefinition a)
        {
            int fields = (a.Plan != null ? 1 : 0) + (a.Options == null ? 0 : a.Options.Length);
            Check.True(fields == 1, "attack '" + a.AttackId + "' changes " + fields + " things; an attack differs from its control by exactly one field");
            LabRun control = RunLab(a.Lesson, null, 11);
            Check.True(control.Completed, "control run of lesson " + a.Lesson + " did not complete: " + control);
            Check.True(control.Sink.FailedCheckCode == null, "control run of lesson " + a.Lesson + " has a failed check: " + control.Sink.FailedCheckCode);
            LabRun attack = RunLab(a.Lesson, a, 11);
            if (a.Expect == AttackOutcome.NoCheck)
            {
                Check.True(attack.Sink.FailedCheckCode == null, "attack '" + a.AttackId + "' expects no failed check (the attack works), but check " + attack.Sink.FailedCheckCode + " failed");
                return a.AttackId + ": no check fails, as the lesson says";
            }
            Check.True(!attack.Completed, "attack '" + a.AttackId + "' ran to the end; the lesson says a named check stops it");
            Check.Equal("attack '" + a.AttackId + "' failed check code", a.ExpectCode, attack.Code);
            Check.Equal("attack '" + a.AttackId + "' failed check name", a.ExpectCheck, attack.Check);
            return a.AttackId + ": control completes, attack stopped by " + a.ExpectCheck + " [" + a.ExpectCode + "]";
        }

        static AttackDefinition FindRow(int lesson, string checkName)
        {
            foreach (AttackDefinition a in AttackCatalog.All)
                if (a.Lesson == lesson && string.Equals(a.ExpectCheck, checkName, StringComparison.OrdinalIgnoreCase)) return a;
            throw new FailException("no attack in lesson " + lesson + " expects the check '" + checkName + "' (ux-design.md section 7 names it)");
        }

        // The five checks lesson 10 names in ux-design.md section 7.
        [Clause("A11.mtls.missing-client-cert-beside-control")]
        public static string Mtls(Ctx c) { return RowBesideControl(FindRow(10, "bad_certificate alert")); }

        [Clause("A11.dpop.replay-beside-control")]
        public static string Dpop(Ctx c) { return RowBesideControl(FindRow(10, "jti already used")); }

        [Clause("A11.token.claim-changed-beside-control")]
        public static string TokenClaim(Ctx c) { return RowBesideControl(FindRow(10, "token signature")); }

        [Clause("A11.roles.capability-not-granted-beside-control")]
        public static string Capability(Ctx c) { return RowBesideControl(FindRow(10, "permission check")); }

        [Clause("A11.passkey.challenge-replay-beside-control")]
        public static string Passkey(Ctx c) { return RowBesideControl(FindRow(10, "challenge already used")); }

        [Clause("A11.catalog.every-row-beside-control")]
        public static string EveryRow(Ctx c)
        {
            AttackDefinition[] all = AttackCatalog.All;
            Check.True(all.Length > 0, "AttackCatalog is empty");
            Tally t = new Tally();
            foreach (AttackDefinition a in all)
            {
                try { RowBesideControl(a); t.Ok(); }
                catch (FailException ex) { t.Miss(a.AttackId, ex.Message); }
            }
            return t.Done();
        }

        // ---------------------------------------------------------------- the product's token under the Go verifier

        [Clause("A11.token.verifies-under-go-tokenverify")]
        public static string TokenUnderGo(Ctx c)
        {
            string tokenverify = Referees.GoTool(c, "tokenverify");
            TrainingKeySource keys = new TrainingKeySource();
            ITrainingKey issuer = keys.Find(KeyIds.TokenIssuer);
            string dir = LivePki.Dir(c, "a11-token");
            string pubFile = Path.Combine(dir, "issuer.pub");
            File.WriteAllText(pubFile, Hex.Encode(issuer.CopyPublic()) + "\n");
            string token = NetSec.Auth.Token.IssueEdDsa(keys, KeyIds.TokenIssuer, "alice", new string[] { "reader" }, DateTime.UtcNow.AddHours(1));
            string[] parts = token.Split('.');
            Check.True(parts.Length == 3, "a compact JWS has three dot-separated parts, got " + parts.Length);

            string output;
            int ok = Proc.Run(tokenverify, "-pub \"" + pubFile + "\" -token " + token, dir, 30000, out output);
            Check.True(ok == 0 && output.Contains("OK"), "tokenverify refused the product's token (exit " + ok + "): " + output.Trim());
            // Control pair: one changed character in the claims part must be refused.
            char[] claims = parts[1].ToCharArray();
            claims[2] = claims[2] == 'A' ? 'B' : 'A';
            string tampered = parts[0] + "." + new string(claims) + "." + parts[2];
            int bad = Proc.Run(tokenverify, "-pub \"" + pubFile + "\" -token " + tampered, dir, 30000, out output);
            Check.True(bad != 0, "tokenverify accepted a token whose claims changed: " + output.Trim());
            return "tokenverify accepts the product's EdDSA token and refuses a token with one changed claim character";
        }
    }
}
