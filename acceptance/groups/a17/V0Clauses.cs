using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// A17, slice V0: the readiness rule, the machine that owns the wizard's moves, the personal-path warning, and one type end to end
    /// (token.issuer). Everything here talks to NetSec.Host over HTTP and WebSocket. See acceptance/CONTRACT.md section 5.
    /// Verified is the product's own word and never counts here: a clause that needs proof runs an outside program.
    /// </summary>
    public static class V0Clauses
    {
        static string ProblemText(Reply r)
        {
            return string.Join(",", A17.ProblemCodes(r).ToArray());
        }

        // ---------------------------------------------------------------- readiness

        [Clause("A17.readiness.refuses-by-name")]
        public static string ReadinessRefusesByName(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-ready"))
            {
                // Control first: every type is built-in, so lesson 10 may run and does run.
                Reply ctl = A17.Readiness(h, 10);
                Check.True(ctl.Ok && MiniJson.Bool(ctl.Json, "mayRun", false), "control: with every type built-in, readiness for lesson 10 is " + ctl);
                SessionRun ok = HostSession.Run(h, 10, "glass", null);
                RequireLesson(ok, 10);
                Check.True(ok.Error == null && ok.Finished != null, "control: lesson 10 on built-in keys did not finish: " + (ok.Frames.Count == 0 ? "no frames" : ok.Frames[ok.Frames.Count - 1]));

                // "My test key" with no binding: Unconfigured. The lab refuses by name, and never runs on built-in keys in silence.
                A17.SetMode(h, "token.issuer", "Mine");
                Check.Equal("state of token.issuer with no binding", "Unconfigured", A17.StateOf(h, "token.issuer"));
                Reply r = A17.Readiness(h, 10);
                Check.True(r.Ok && !MiniJson.Bool(r.Json, "mayRun", true), "readiness for lesson 10 with an unconfigured type says mayRun true: " + r);
                Check.True(A17.ProblemCodes(r).Contains("token.issuer:SECURITY_TYPE_NOT_READY"), "problems[] lacks token.issuer:SECURITY_TYPE_NOT_READY, has [" + ProblemText(r) + "]");
                SessionRun refused = HostSession.Run(h, 10, "glass", null);
                Check.Equal("error code of session.start on an unconfigured type", "SECURITY_TYPE_NOT_READY", refused.ErrorCode);
                string frame = refused.Frames.Count > 0 ? refused.Frames[refused.Frames.Count - 1] : "";
                Check.True(frame.Contains("token.issuer"), "the refusal does not name the type token.issuer: " + frame);
                Check.True(frame.Contains("my-login"), "the refusal does not name the flow my-login that makes the type: " + frame);
                Check.True(refused.Events.Count == 0, "a refused lab still sent " + refused.Events.Count + " trace events: it ran anyway");

                // Configured, not proven: the flow wrote the binding and the check has not run. An unchecked key can fail for an unnamed reason inside a lesson.
                A17.Flow f = A17.Flow.Start(h, "my-login");
                f.MakeForMe(null, "Check");
                Check.Equal("state of token.issuer after Place", "Configured", A17.StateOf(h, "token.issuer"));
                Reply p = A17.Readiness(h, 10);
                Check.True(A17.ProblemCodes(p).Contains("token.issuer:SECURITY_TYPE_NOT_PROVEN"), "problems[] lacks token.issuer:SECURITY_TYPE_NOT_PROVEN, has [" + ProblemText(p) + "]");
                SessionRun unproven = HostSession.Run(h, 10, "glass", null);
                Check.Equal("error code of session.start on an unproven type", "SECURITY_TYPE_NOT_PROVEN", unproven.ErrorCode);

                // The check passes: the same lab now runs, on the learner's key.
                Reply chk = f.Send("check", null);
                Check.True(chk.Ok, "event check got " + chk);
                Check.Equal("state of token.issuer after the check", "Verified", A17.StateOf(h, "token.issuer"));
                Reply fin = A17.Readiness(h, 10);
                Check.True(MiniJson.Bool(fin.Json, "mayRun", false), "after the check, readiness for lesson 10 is " + fin);
                SessionRun mine = HostSession.Run(h, 10, "glass", null);
                Check.True(mine.Error == null && mine.Finished != null, "lesson 10 on a verified own key did not finish: " + (mine.Frames.Count == 0 ? "no frames" : mine.Frames[mine.Frames.Count - 1]));
                return "built-in control runs; Unconfigured gives SECURITY_TYPE_NOT_READY, Configured gives SECURITY_TYPE_NOT_PROVEN, both naming token.issuer and sending no event; Verified runs";
            }
        }

        [Clause("A17.readiness.types-disagree")]
        public static string TypesDisagree(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-disagree"))
            {
                A17.RunFlow(h, "my-certificates", null);
                // Control: all five certificate types are the learner's, so lesson 5 may run.
                Reply ctl = A17.Readiness(h, 5);
                Check.True(ctl.Ok && MiniJson.Bool(ctl.Json, "mayRun", false), "control: with the five certificate types all Mine and Verified, readiness for lesson 5 is " + ctl);
                // The trust list goes back to built-in: the learner's server certificate can no longer reach an anchor.
                A17.SetMode(h, "tls.trust", "BuiltIn");
                Reply r = A17.Readiness(h, 5);
                Check.True(r.Ok && !MiniJson.Bool(r.Json, "mayRun", true), "readiness says mayRun true with tls13.server Mine and tls.trust BuiltIn: " + r);
                bool named = false;
                foreach (string code in A17.ProblemCodes(r)) if (code.EndsWith(":SECURITY_TYPES_DISAGREE")) named = true;
                Check.True(named, "problems[] has no SECURITY_TYPES_DISAGREE, has [" + ProblemText(r) + "]");
                SessionRun refused = HostSession.Run(h, 5, "glass", null);
                Check.Equal("error code of session.start when the types disagree", "SECURITY_TYPES_DISAGREE", refused.ErrorCode);
                Check.True(refused.Events.Count == 0, "a refused lab still sent " + refused.Events.Count + " trace events");
                // Going back to Mine needs no new flow: the binding stayed.
                A17.SetMode(h, "tls.trust", "Mine");
                Reply back = A17.Readiness(h, 5);
                Check.True(MiniJson.Bool(back.Json, "mayRun", false), "after tls.trust returned to Mine, readiness for lesson 5 is " + back);
                return "five Mine types run; tls.trust BuiltIn gives SECURITY_TYPES_DISAGREE on readiness and on session.start; back to Mine runs again";
            }
        }

        static void RequireLesson(SessionRun run, int lesson)
        {
            if (run.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson " + lesson + " as not built yet");
        }

        // ---------------------------------------------------------------- the personal-path warning

        [Clause("A17.import.warns-on-personal-ssh-path")]
        public static string WarnsOnPersonalSshPath(Ctx c)
        {
            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            // A path that does not exist, so the suite never reads or touches a real key. The warning is about where the path points.
            string personal = Path.Combine(profile, ".ssh", "acceptance-canary-does-not-exist");
            string neutral = Path.Combine(A17.TempDir(c, "import"), "acceptance-canary-does-not-exist");
            using (HostProc h = A17.Host(c, "a17-import"))
            {
                // Control: a path outside ~/.ssh gets no personal-path warning (it may fail for being unreadable, which is a different code).
                A17.Flow ctl = ToPickFiles(h);
                ctl.Send("files", A17.Obj("paths", new Dictionary<string, object> { { "ssh.host-ed25519", neutral } }));
                Check.True(!ctl.ErrorCodes.Contains("KEY_PATH_PERSONAL"), "control: a path outside ~/.ssh got KEY_PATH_PERSONAL");

                A17.Flow f = ToPickFiles(h);
                f.Send("files", A17.Obj("paths", new Dictionary<string, object> { { "ssh.host-ed25519", personal } }));
                Check.True(f.ErrorCodes.Contains("KEY_PATH_PERSONAL"), "a path under " + Path.Combine(profile, ".ssh") + " got no KEY_PATH_PERSONAL. Codes: [" + string.Join(",", f.ErrorCodes.ToArray()) + "]");
                foreach (Dictionary<string, object> e in f.Errors)
                    if (MiniJson.Str(e, "code") == "KEY_PATH_PERSONAL")
                    {
                        Check.Equal("severity of KEY_PATH_PERSONAL", "warning", MiniJson.Str(e, "severity"));
                        Check.True(!string.IsNullOrEmpty(MiniJson.Str(e, "message")), "KEY_PATH_PERSONAL carries no message for the learner");
                    }
                return "a path under ~/.ssh gets the warning KEY_PATH_PERSONAL (severity warning, with a message); a path elsewhere does not";
            }
        }

        static A17.Flow ToPickFiles(HostProc h)
        {
            A17.Flow f = A17.Flow.Start(h, "my-ssh");
            f.Next();
            Reply r = f.Send("choose", A17.Obj("source", "files"));
            Check.True(r.Ok, "event choose (files) got " + r);
            Check.Equal("state after choosing files", "PickFiles", f.State);
            return f;
        }

        // ---------------------------------------------------------------- the machine owns the moves

        [Clause("A17.flow.login.walk")]
        public static string LoginWalk(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-login"))
            {
                A17.Flow f = A17.Flow.Start(h, "my-login");
                Check.Equal("first state", "Intro", f.State);
                Check.True(f.Step != null && MiniJson.Write(f.Step).Contains("wizard.common.test-keys-only"), "the Intro step does not carry the test-keys line (copy id wizard.common.test-keys-only)");
                Check.True(f.Allowed.Contains("next") && f.Allowed.Contains("cancel"), "Intro allows [" + string.Join(",", f.Allowed.ToArray()) + "], expected next and cancel");

                // The machine refuses a move that has no row: Intro has no event "check".
                int seq = f.Seq;
                Reply bad = f.Send("check", null);
                Check.True(!bad.Ok && bad.Code == "WIZARD_EVENT_NOT_ALLOWED", "event check at Intro got " + bad + "; expected WIZARD_EVENT_NOT_ALLOWED");
                Check.True((bad.Body ?? "").Contains("Intro") && (bad.Body ?? "").Contains("check"), "WIZARD_EVENT_NOT_ALLOWED does not name both the state (Intro) and the event (check): " + bad);
                Check.Equal("step after a refused event", seq, f.Seq);
                // A stale step number is refused too.
                f.Next();
                Reply stale = f.SendSeq("next", seq, null);
                Check.True(!stale.Ok && stale.Code == "WIZARD_STEP_STALE", "a stale stepSeq got " + stale + "; expected WIZARD_STEP_STALE");
                Reply gone = HostHttp.Get(h, "/api/security/runs/no-such-run");
                Check.True(!gone.Ok && gone.Code == "WIZARD_RUN_NOT_FOUND", "an unknown run got " + gone + "; expected WIZARD_RUN_NOT_FOUND");

                // The spine, one state at a time.
                Check.Equal("state after Intro", "ChooseSource", f.State);
                Check.Equal("kind of ChooseSource", "choose", f.Kind);
                Reply ch = f.Send("choose", A17.Obj("source", "make"));
                Check.True(ch.Ok, "event choose (make) got " + ch);
                Check.Equal("state after choosing make", "Options", f.State);
                Reply op = f.Send("option", A17.Obj("typeId", "token.issuer", "keepHidden", false));
                Check.True(op.Ok, "event option got " + op);
                f.Next();
                Check.Equal("state after Options", "ReadBack", f.State);
                Check.Equal("kind of ReadBack", "review", f.Kind);
                Check.True(f.Allowed.Contains("back"), "ReadBack must allow back (back works up to Place)");
                f.Next();
                Check.Equal("state after ReadBack", "Place", f.State);
                f.Next();
                Check.Equal("state after Place", "Check", f.State);
                Check.Equal("kind of Check", "prove", f.Kind);
                Check.True(!f.Allowed.Contains("back"), "Check allows back, but back works up to Place only");
                Check.Equal("state of token.issuer before the check", "Configured", A17.StateOf(h, "token.issuer"));
                Check.Equal("state of device.enrolment before the check", "Configured", A17.StateOf(h, "device.enrolment"));
                Reply chk = f.Send("check", null);
                Check.True(chk.Ok && f.ErrorCodes.Count == 0, "the check got " + chk);
                // Who judged each type, said on the step. The passkey-shaped login has no outside judge, and the step says so.
                bool sawToken = false, sawDevice = false;
                foreach (Dictionary<string, object> fact in f.Facts)
                {
                    string t = MiniJson.Str(fact, "typeId"), judge = MiniJson.Str(fact, "judge");
                    if (t == "token.issuer") { sawToken = true; Check.Equal("judge of token.issuer", "openssl", judge); }
                    if (t == "device.enrolment") { sawDevice = true; Check.Equal("judge of device.enrolment", "none", judge); }
                }
                Check.True(sawToken && sawDevice, "the Check step names no judge for " + (sawToken ? "" : "token.issuer ") + (sawDevice ? "" : "device.enrolment"));
                f.Next();
                Check.Equal("last state", "Done", f.State);
                Check.Equal("mode of token.issuer", "Mine", A17.ModeOf(h, "token.issuer"));
                Check.Equal("mode of device.enrolment", "Mine", A17.ModeOf(h, "device.enrolment"));
                string path = string.Join(">", f.States.ToArray());
                return "Intro>ChooseSource>Options>ReadBack>Place>Check>Done in order (" + path + "); off-table event, stale step and unknown run refused by name; token.issuer judged by openssl, device.enrolment by none";
            }
        }

        // ---------------------------------------------------------------- token.issuer, judged by the Go verifier

        [Clause("A17.referee.token-issuer-go")]
        public static string TokenIssuerGo(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-token"))
            {
                string verify = Referees.GoTool(c, "tokenverify");
                A17.RunFlow(h, "my-login", null);
                SessionRun run = HostSession.Run(h, 10, "glass", null);
                RequireLesson(run, 10);
                Check.True(run.Error == null && run.Finished != null, "lesson 10 on the learner's issuer key did not finish: " + (run.Frames.Count == 0 ? "no frames" : run.Frames[run.Frames.Count - 1]));
                string tokenHex = null, pubHex = null;
                foreach (A17.SecretRef s in A17.Secrets(run))
                {
                    if (s.Name == "auth.token" && s.Hex.Length > 0) tokenHex = s.Hex;
                    if (s.Name == "auth.issuer-public" && s.Hex.Length > 0) pubHex = s.Hex;
                }
                Check.True(tokenHex != null, "the lesson 10 trace holds no secret named auth.token with its hex (Show keys is ON)");
                Check.True(pubHex != null, "the lesson 10 trace holds no secret named auth.issuer-public with its hex");
                string token = Encoding.ASCII.GetString(Hex.Decode(tokenHex));
                Check.True(token.Split('.').Length == 3, "auth.token is not a compact JWS: '" + token + "'");
                // The issuer public key in the trace must be the learner's key, as the Host reports it.
                Reply key = A17.Key(h, "token.issuer");
                Check.True(key.Ok, "GET key of token.issuer got " + key);
                string reported = MiniJson.Str(key.Json, "publicHex");
                Check.True(reported != null && reported.Equals(pubHex, StringComparison.OrdinalIgnoreCase), "the issuer public key in the trace (" + pubHex + ") is not the public key the Host reports for token.issuer (" + reported + ")");

                string dir = A17.TempDir(c, "token");
                string pem = Path.Combine(dir, "issuer.pem");
                File.WriteAllText(pem, Ed25519Pem(Hex.Decode(pubHex)));
                Check.Equal("tokenverify code for the learner's token", "TOKEN_OK", Verify(verify, pem, token, dir));
                // Control: one changed character in the claims is refused by the same program.
                string[] parts = token.Split('.');
                char[] cl = parts[1].ToCharArray();
                cl[2] = cl[2] == 'A' ? 'B' : 'A';
                Check.Equal("tokenverify code for a changed claim", "TOKEN_BAD_SIGNATURE", Verify(verify, pem, parts[0] + "." + new string(cl) + "." + parts[2], dir));
                return "the Go tokenverify accepts a token signed by the learner's issuer key and refuses the same token with one claim character changed";
            }
        }

        public static string Ed25519Pem(byte[] pub)
        {
            byte[] spki = Hex.Concat(Hex.Decode("302a300506032b6570032100"), pub);
            return "-----BEGIN PUBLIC KEY-----\n" + Convert.ToBase64String(spki) + "\n-----END PUBLIC KEY-----\n";
        }

        static string Verify(string tool, string pemFile, string token, string dir)
        {
            string output;
            Proc.Run(tool, "-pub \"" + pemFile + "\" -token " + token, dir, 30000, out output);
            foreach (string line in output.Split('\n'))
            {
                string t = line.Trim();
                if (!t.StartsWith("{")) continue;
                string code = MiniJson.Str(MiniJson.AsObject(MiniJson.Parse(t)), "code");
                if (code != null) return code;
            }
            throw new FailException("tokenverify printed no result event: " + output.Trim());
        }
    }
}
