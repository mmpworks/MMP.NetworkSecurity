using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Auth;
using NetSec.Io;
using NetSec.Pki;
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
            // Lesson 11 calls netsec_ct.dll through DllImport. This program has no copy beside it, so the suite builds the library and loads it first.
            if (lesson == 11 && Ctx.Current != null) NativeBuild.EnsureLoaded(Ctx.Current);
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
        // RFC 8446 section 4.4.2.4: a client that sends an empty Certificate to a server that requires one gets the fatal alert
        // certificate_required (116, section 6.2). bad_certificate (42) is for a certificate that is corrupt or does not verify.
        // Both rows below run beside a control; the first also runs against the Go referee further down.
        static string RowWithCode(AttackDefinition row, string expectCode)
        {
            Check.Equal("ExpectCode of the catalog row '" + row.AttackId + "'", expectCode, row.ExpectCode);
            return RowBesideControl(row);
        }

        [Clause("A11.mtls.missing-client-cert-beside-control")]
        public static string Mtls(Ctx c) { return RowWithCode(FindRow(10, "certificate_required alert"), "TLS13_CERT_REQUIRED"); }

        [Clause("A11.mtls.corrupt-client-cert-beside-control")]
        public static string MtlsCorrupt(Ctx c) { return RowWithCode(FindRow(10, "bad_certificate alert"), "TLS13_BAD_CERTIFICATE"); }

        /// <summary>
        /// The alert number comes from Go crypto/tls, not from our own table. The glass client offers no client certificate to a Go server
        /// that requires one, and must see alert 116. A control: the same server without the requirement lets the same client in.
        /// </summary>
        [Clause("A11.mtls.go-referee-requires-client-cert")]
        public static string MtlsGoReferee(Ctx c)
        {
            PkiDir p = PkiDir.Export(c, "a11-mtls");
            string common = "-mode server -listen 127.0.0.1:0 -naccept 1 -groups x25519 -cert \"" + p.Cert + "\" -key \"" + p.Key + "\"";
            using (GoPeer open = GoPeer.StartListening(c, "tlspeer", common))
            {
                ProbeRequest req = ProbeKit.Request(WireProtocol.Tls13, open.Port, "localhost");
                req.Group = KexGroup.X25519;
                req.Send = System.Text.Encoding.ASCII.GetBytes("hello\n");
                ProbeResult ok = ProbeKit.Connect(req, "control (server does not ask for a client certificate)");
                Check.True(ok.Completed, "control run stopped: " + ok.CheckName + " [" + ok.Code + "]");
            }
            using (GoPeer strict = GoPeer.StartListening(c, "tlspeer", common + " -ca \"" + p.Root + "\" -require-client-cert"))
            {
                ProbeRequest req = ProbeKit.Request(WireProtocol.Tls13, strict.Port, "localhost");
                req.Group = KexGroup.X25519;
                req.Send = System.Text.Encoding.ASCII.GetBytes("hello\n");
                ProbeResult r = ProbeKit.Connect(req, "attack (no client certificate)");
                Check.True(!r.Completed, "the handshake completed although the server requires a client certificate");
                Check.Equal("alert received from Go", "116", r.AlertReceived.ToString());
                string code = strict.ErrorCode;
                if (code == null) { strict.WaitEvent("error", 5000); code = strict.ErrorCode; }
                Check.Equal("Go's own name for the failure", "TLS_CLIENT_CERT_MISSING", code);
                return "control opens; a server that requires a client certificate answers an empty Certificate with alert 116 (certificate_required), and Go names it TLS_CLIENT_CERT_MISSING";
            }
        }

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
            string dir = LivePki.Dir(c, "a11-token");
            TrainingPki.Export(dir);                                  // writes issuer.pub (PEM SPKI), which the referee reads
            string pubFile = Path.Combine(dir, "issuer.pub");
            Check.True(File.Exists(pubFile), "TrainingPki.Export wrote no issuer.pub in " + dir);
            TrainingKeySource keys = new TrainingKeySource();
            ITrainingKey issuer = keys.Find(KeyIds.TokenIssuer);
            string claims = "{\"sub\":\"alice\",\"roles\":[\"reader\"],\"exp\":" + (DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600) + "}";
            string token = NetSec.Auth.Token.Issue(issuer, claims);
            string[] parts = token.Split('.');
            Check.True(parts.Length == 3, "a compact JWS has three dot-separated parts, got " + parts.Length);

            // The referee accepts the product's token, and the product accepts it too.
            string good = Verify(tokenverify, pubFile, token, dir);
            Check.Equal("tokenverify code for the product's token", "TOKEN_OK", good);
            AuthDecision own = NetSec.Auth.Token.Verify(issuer.CopyPublic(), token, DateTime.UtcNow);
            Check.True(own.Allowed, "the product refused its own token: " + own.Code);

            // Control pair: one changed character in the claims part is refused by both.
            char[] cl = parts[1].ToCharArray();
            cl[2] = cl[2] == 'A' ? 'B' : 'A';
            string tampered = parts[0] + "." + new string(cl) + "." + parts[2];
            Check.Equal("tokenverify code for a changed claim", "TOKEN_BAD_SIGNATURE", Verify(tokenverify, pubFile, tampered, dir));
            AuthDecision bad = NetSec.Auth.Token.Verify(issuer.CopyPublic(), tampered, DateTime.UtcNow);
            Check.True(!bad.Allowed, "the product accepted a token whose claims changed");

            // A token signed by the attacker key is refused by both.
            ITrainingKey attacker = keys.Find(KeyIds.AttackerEd25519);
            string forged = NetSec.Auth.Token.Issue(attacker, claims);
            Check.Equal("tokenverify code for an attacker-signed token", "TOKEN_BAD_SIGNATURE", Verify(tokenverify, pubFile, forged, dir));
            Check.True(!NetSec.Auth.Token.Verify(issuer.CopyPublic(), forged, DateTime.UtcNow).Allowed, "the product accepted a token signed by the attacker key");
            return "tokenverify and the product agree on a good token, a changed claim, and an attacker-signed token";
        }

        /// <summary>Runs tokenverify and returns the code of its result event.</summary>
        static string Verify(string tool, string pubFile, string token, string dir)
        {
            string output;
            Proc.Run(tool, "-pub \"" + pubFile + "\" -token " + token, dir, 30000, out output);
            foreach (string line in output.Split('\n'))
            {
                string t = line.Trim();
                if (!t.StartsWith("{")) continue;
                System.Collections.Generic.Dictionary<string, object> d = MiniJson.AsObject(MiniJson.Parse(t));
                string code = MiniJson.Str(d, "code");
                if (code != null) return code;
            }
            throw new FailException("tokenverify printed no result event: " + output.Trim());
        }
    }
}
