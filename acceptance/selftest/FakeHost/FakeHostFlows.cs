using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;

namespace Acceptance
{
    // The wizard machine of the fake Host: the five-screen path of wizards-ux.md 3.2 (Intro, ChooseSource, Place, ReadBack, Prove, Done) with the file branch
    // PickFiles. The suite drives by step kind, so the screen names here could be the ones of modes-design.md 8.2 and no clause would notice. See FakeHost.cs.
    public sealed partial class FakeHost
    {
        static string[] FlowTypesOf(string flowId) { return A17.TypesOf(flowId); }

        static List<object> Strs(params string[] s) { return new List<object>(s); }

        List<string> AllowedIn(FlowRun r)
        {
            switch (r.State)
            {
                case "Intro": return new List<string> { "next", "cancel" };
                case "ChooseSource": return new List<string> { "choose", "back", "cancel" };
                case "PickFiles": return new List<string> { "files", "back", "cancel" };
                case "Place": return new List<string> { "next", "back", "cancel" };
                case "ReadBack": return new List<string> { "next", "back", "cancel" };
                case "Prove":
                    List<string> a = new List<string> { "check", "next", "cancel" };
                    if (M("back-after-check")) a.Add("back");
                    return a;
                default: return new List<string>();
            }
        }

        static string KindOf(string state)
        {
            switch (state)
            {
                case "Intro": return "explain";
                case "ChooseSource": return "choose";
                case "PickFiles": return "file";
                case "Place": return "generate";
                case "ReadBack": return "review";
                case "Prove": return "prove";
                default: return "done";
            }
        }

        Dictionary<string, object> StepJson(FlowRun r)
        {
            List<object> allowed = new List<object>(AllowedIn(r).ToArray());
            Dictionary<string, object> s = D("runId", r.RunId, "flowId", r.FlowId, "state", r.State, "kind", KindOf(r.State), "stepSeq", (double)r.Seq,
                "allowed", allowed, "errors", new List<object>(r.Errors.ToArray()), "warnings", new List<object>(r.Warnings.ToArray()), "facts", new List<object>(r.Facts.ToArray()));
            if (r.State == "Intro") s["copy"] = Strs("wizard.common.test-keys-only");
            if (r.State == "ReadBack") s["facts"] = ReadBackFacts(r);
            return s;
        }

        void StartRun(HttpListenerContext ctx, string flowId)
        {
            if (flowId != "my-certificates" && flowId != "my-ssh" && flowId != "my-payment" && flowId != "my-login" && flowId != "my-lesson-keys")
            { Fail(ctx, 404, "WIZARD_FLOW_UNKNOWN", "no flow " + flowId); return; }
            FlowRun r = new FlowRun { RunId = "run" + (++_next), FlowId = flowId };
            _runs[r.RunId] = r;
            Write(ctx, 200, D("runId", r.RunId, "step", StepJson(r)));
        }

        string JudgeOf(string typeId)
        {
            if (typeId.StartsWith("ssh.")) return "ssh.exe";
            if (typeId.StartsWith("dukpt.") && M("dukpt-judge-claimed")) return "openssl";
            if (typeId.StartsWith("dukpt.") || typeId == "device.enrolment") return "none";
            return "openssl";
        }

        /// <summary>The stable id in says (modes-design.md section 8.6). The words live in the copy file.</summary>
        string SaysOf(string typeId)
        {
            switch (JudgeOf(typeId))
            {
                case "ssh.exe": return "checked-with-ssh-exe";
                case "none": return "no-outside-judge";
                default:
                    if (typeId == "token.issuer") return "checked-signature-only";
                    if (typeId.StartsWith("lab.")) return "checked-with-openssl";
                    return M("says-trusted") ? "trusted" : "checked-against-root";
            }
        }

        static string NameOf(string typeId)
        {
            switch (typeId)
            {
                case "pki.root-ca": return "MMP.NetworkSecurity training root";
                case "tls13.server": case "tls11.server": return "localhost";
                case "tls13.client": return "pump-reader-4";
                default: return typeId;
            }
        }

        static string AlgorithmOf(string typeId)
        {
            if (typeId == "tls11.server" || typeId == "ssh.host-rsa") return "RSA-2048";
            if (typeId.StartsWith("dukpt.") || typeId.StartsWith("lab.")) return "AES-128";
            return "Ed25519";
        }

        List<object> ReadBackFacts(FlowRun r)
        {
            List<object> facts = new List<object>();
            string[] types = FlowTypesOf(r.FlowId);
            int n = M("readback-drops-type") ? types.Length - 1 : types.Length;
            for (int i = 0; i < n; i++)
            {
                string id = types[i];
                using (SHA256 sha = SHA256.Create())
                    facts.Add(D("typeId", id, "name", NameOf(id), "notAfter", "2049-12-31", "algorithm", AlgorithmOf(id),
                        "fingerprint", "SHA256:" + Convert.ToBase64String(sha.ComputeHash(System.Text.Encoding.ASCII.GetBytes(r.RunId + id))).TrimEnd('=')));
            }
            return facts;
        }

        void FlowEvent(HttpListenerContext ctx, FlowRun r, Dictionary<string, object> body)
        {
            string ev = MiniJson.Str(body, "event");
            int seq = (int)MiniJson.Num(body, "stepSeq", -1);
            Dictionary<string, object> data = MiniJson.Obj(body, "data") ?? new Dictionary<string, object>();
            if (seq != r.Seq && !M("stale-accepted")) { Fail(ctx, 409, "WIZARD_STEP_STALE", "stepSeq " + seq + " is old; the run is at " + r.Seq); return; }
            if (!AllowedIn(r).Contains(ev) && !M("machine-allows-any"))
            { Fail(ctx, 409, "WIZARD_EVENT_NOT_ALLOWED", "event '" + ev + "' is not allowed in state '" + r.State + "'"); return; }
            r.Errors.Clear(); r.Warnings.Clear();
            switch (ev)
            {
                case "next":
                    switch (r.State)
                    {
                        case "Intro": Go(r, "ChooseSource"); break;
                        case "Place": Apply(r); Go(r, "ReadBack"); break;
                        case "ReadBack": Go(r, "Prove"); break;
                        case "Prove":
                            if (!r.Checked) { Fail(ctx, 409, "WIZARD_CHECK_NOT_DONE", "the check has not run"); return; }
                            Go(r, "Done");
                            break;
                    }
                    break;
                case "choose":
                    r.Source = MiniJson.Str(data, "source");
                    if (r.Source == "files") Go(r, "PickFiles");
                    else if (r.Source == "make") Go(r, "Place");
                    else { Fail(ctx, 409, "WIZARD_SOURCE_UNAVAILABLE", "source " + r.Source + " is not offered by " + r.FlowId); return; }
                    break;
                case "files":
                    CheckPaths(r, data);
                    if (!r.FileBlocked && r.Paths.Count > 0) { Apply(r); Go(r, "ReadBack"); }     // the branch checks the files, then places them
                    break;
                case "check":
                    RunCheck(r);
                    break;
                case "back":
                    if (r.State == "ReadBack") { r.Source = null; r.State = "ChooseSource"; r.Back.Clear(); r.Back.Add("Intro"); }      // back makes a new version
                    else if (r.Back.Count > 0) { r.State = r.Back[r.Back.Count - 1]; r.Back.RemoveAt(r.Back.Count - 1); }
                    break;
                case "cancel":
                    r.State = "Cancelled";
                    break;
            }
            r.Seq++;
            Write(ctx, 200, D("runId", r.RunId, "step", StepJson(r)));
        }

        static void Go(FlowRun r, string to) { r.Back.Add(r.State); r.State = to; }

        static bool IsEd25519Type(string typeId) { return typeId == "token.issuer" || typeId == "device.enrolment"; }

        void CheckPaths(FlowRun r, Dictionary<string, object> data)
        {
            Dictionary<string, object> paths = MiniJson.Obj(data, "paths");
            string ssh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
            r.FileBlocked = false;
            if (paths == null) return;
            foreach (KeyValuePair<string, object> kv in paths)
            {
                string p = kv.Value as string ?? "";
                r.Paths[kv.Key] = p;
                if (!M("no-personal-warning") && p.StartsWith(ssh, StringComparison.OrdinalIgnoreCase))
                {
                    Dictionary<string, object> w = D("code", "KEY_PATH_PERSONAL", "typeId", kv.Key, "message", "This path is in your own .ssh folder. Use a test key.");
                    if (M("personal-path-is-error")) { w["severity"] = "error"; r.Errors.Add(w); r.FileBlocked = true; } else r.Warnings.Add(w);
                }
                if (!File.Exists(p))
                {
                    r.Errors.Add(D("code", "KEY_FILE_UNREADABLE", "severity", "error", "typeId", kv.Key, "message", "The file cannot be read."));
                    r.FileBlocked = true;
                }
                else if (IsEd25519Type(kv.Key) && ReadKey(p) == null)
                {
                    r.Errors.Add(D("code", "KEY_FILE_FORMAT", "severity", "error", "typeId", kv.Key, "message", "The file is not an Ed25519 private key."));
                    r.FileBlocked = true;
                }
                else CertChecks(r, kv.Key, p);
            }
        }

        static byte[] RandomBytes(int n) { byte[] b = new byte[n]; RandomNumberGenerator.Fill(b); return b; }

        void Apply(FlowRun r)
        {
            foreach (string id in FlowTypesOf(r.FlowId))
            {
                TypeState t = _types[id];
                t.Mode = "Mine"; t.Bound = true; t.Verified = false; if (!M("version-not-bumped") || t.Version == 0) t.Version++;
                bool imported = r.Source == "files" && r.Paths.ContainsKey(id);
                t.Provider = imported ? "file" : "vault";
                ApplyCert(r, t, id, imported);
                if (id == "token.issuer")
                {
                    t.Key = imported ? ReadKey(r.Paths[id]) : NewKey("issuer");
                    t.Seed = t.Key.Seed;
                }
                else if (IsEd25519Type(id) && imported) t.Seed = ReadKey(r.Paths[id]).Seed;
                else t.Seed = RandomBytes(id.StartsWith("dukpt.") || id.StartsWith("lab.") ? 16 : 32);
                if (t.Provider == "vault") VaultStore(t);
            }
        }

        void RunCheck(FlowRun r)
        {
            r.Facts.Clear();
            bool failed = false;
            foreach (string id in FlowTypesOf(r.FlowId))
            {
                // A leaf the learner brought is checked against the root the learner gave. A leaf the root did not sign is refused.
                if (r.Source == "files" && Array.IndexOf(LeafCerts, id) >= 0 && r.Paths.ContainsKey(id) && r.Paths.ContainsKey("pki.root-ca") && !VerifyChain(r.Paths["pki.root-ca"], r.Paths[id]))
                {
                    r.Errors.Add(D("code", "CHECK_FAILED", "severity", "error", "typeId", id, "message", "OpenSSL does not verify this certificate against the root you gave."));
                    failed = true;
                    continue;
                }
                _types[id].Verified = true;
                string judge = JudgeOf(id);
                if (M("device-judge-claimed") && id == "device.enrolment") judge = "openssl";
                if (!M("no-judge-facts")) r.Facts.Add(D("typeId", id, "judge", judge, "says", SaysOf(id), "command", CommandOf(id, judge), "output", OutputOf(id, judge), "passed", true));
            }
            r.Checked = !failed;
        }

        static string CommandOf(string typeId, string judge)
        {
            if (judge == "none") return "";
            if (typeId == "token.issuer") return "openssl pkeyutl -verify -pubin -inkey issuer.pub -rawin -in signing-input.bin -sigfile signature.bin";
            if (judge == "ssh.exe") return "ssh.exe -F NUL -o BatchMode=yes -o StrictHostKeyChecking=yes echo hello";
            return "openssl verify -CAfile root.pem " + typeId + ".pem";
        }

        static string OutputOf(string typeId, string judge)
        {
            if (judge == "none") return "";
            if (typeId == "token.issuer") return "Signature Verified Successfully";
            if (judge == "ssh.exe") return "hello";
            return typeId + ".pem: OK";
        }
    }
}
