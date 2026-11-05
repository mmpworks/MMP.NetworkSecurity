using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;

namespace Acceptance
{
    // The wizard machine of the fake Host. See FakeHost.cs.
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
                case "PickFiles": return new List<string> { "files", "next", "back", "cancel" };
                case "Options": return new List<string> { "option", "next", "back", "cancel" };
                case "ReadBack": case "Place": return new List<string> { "next", "back", "cancel" };
                case "Check":
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
                case "Options": return "choose";
                case "ReadBack": return "review";
                case "Place": return "generate";
                case "Check": return "prove";
                default: return "done";
            }
        }

        Dictionary<string, object> StepJson(FlowRun r)
        {
            List<object> allowed = new List<object>(AllowedIn(r).ToArray());
            Dictionary<string, object> s = D("runId", r.RunId, "flowId", r.FlowId, "state", r.State, "kind", KindOf(r.State), "stepSeq", (double)r.Seq,
                "allowed", allowed, "errors", new List<object>(r.Errors.ToArray()), "facts", new List<object>(r.Facts.ToArray()));
            if (r.State == "Intro") s["copy"] = Strs("wizard.common.test-keys-only");
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

        static string JudgeOf(string typeId)
        {
            if (typeId.StartsWith("ssh.")) return "ssh.exe";
            if (typeId.StartsWith("dukpt.") || typeId == "device.enrolment") return "none";
            return "openssl";
        }

        string SaysOf(string typeId)
        {
            switch (JudgeOf(typeId))
            {
                case "ssh.exe": return "Checked with ssh.exe";
                case "none": return typeId == "device.enrolment" ? "No outside tool can judge this. Our own check passed." : "No outside tool can judge this. Our code matches the published vectors.";
                default:
                    if (typeId == "token.issuer" || typeId.StartsWith("lab.")) return "Checked with OpenSSL";
                    return M("says-trusted") ? "Trusted" : "Checked against the root you gave it";
            }
        }

        void FlowEvent(HttpListenerContext ctx, FlowRun r, Dictionary<string, object> body)
        {
            string ev = MiniJson.Str(body, "event");
            int seq = (int)MiniJson.Num(body, "stepSeq", -1);
            Dictionary<string, object> data = MiniJson.Obj(body, "data") ?? new Dictionary<string, object>();
            if (seq != r.Seq && !M("stale-accepted")) { Fail(ctx, 409, "WIZARD_STEP_STALE", "stepSeq " + seq + " is old; the run is at " + r.Seq); return; }
            if (!AllowedIn(r).Contains(ev) && !M("machine-allows-any"))
            { Fail(ctx, 409, "WIZARD_EVENT_NOT_ALLOWED", "event '" + ev + "' is not allowed in state '" + r.State + "'"); return; }
            r.Errors.Clear();
            switch (ev)
            {
                case "next":
                    switch (r.State)
                    {
                        case "Intro": Go(r, "ChooseSource"); break;
                        case "Options": Go(r, "ReadBack"); break;
                        case "PickFiles":
                            if (r.FileBlocked || r.Paths.Count == 0) { r.Errors.Add(D("code", "KEY_FILE_UNREADABLE", "severity", "error", "message", "Pick a readable key file for each row first.")); break; }
                            Go(r, HasOptions(r.FlowId) ? "Options" : "ReadBack");
                            break;
                        case "ReadBack": Go(r, "Place"); break;
                        case "Place": Apply(r); Go(r, "Check"); break;
                        case "Check":
                            if (!r.Checked) { Fail(ctx, 409, "WIZARD_CHECK_NOT_DONE", "the check has not run"); return; }
                            Go(r, "Done");
                            break;
                    }
                    break;
                case "choose":
                    r.Source = MiniJson.Str(data, "source");
                    if (r.Source == "files") Go(r, "PickFiles");
                    else if (r.Source == "make") Go(r, HasOptions(r.FlowId) ? "Options" : "ReadBack");
                    else { Fail(ctx, 409, "WIZARD_SOURCE_UNAVAILABLE", "source " + r.Source + " is not offered by " + r.FlowId); return; }
                    break;
                case "option":
                    r.KeepHidden[MiniJson.Str(data, "typeId")] = MiniJson.Bool(data, "keepHidden", false);
                    break;
                case "files":
                    CheckPaths(r, data);
                    break;
                case "check":
                    RunCheck(r);
                    break;
                case "back":
                    if (r.Back.Count > 0) { r.State = r.Back[r.Back.Count - 1]; r.Back.RemoveAt(r.Back.Count - 1); }
                    break;
                case "cancel":
                    r.State = "Cancelled";
                    break;
            }
            r.Seq++;
            Write(ctx, 200, D("runId", r.RunId, "step", StepJson(r)));
        }

        static bool HasOptions(string flowId) { return flowId == "my-ssh" || flowId == "my-payment" || flowId == "my-login"; }

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
                    r.Errors.Add(D("code", "KEY_PATH_PERSONAL", "severity", "warning", "typeId", kv.Key, "message", "This path is in your own .ssh folder. Use a test key."));
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
            }
        }

        static byte[] RandomBytes(int n) { byte[] b = new byte[n]; RandomNumberGenerator.Fill(b); return b; }

        void Apply(FlowRun r)
        {
            foreach (string id in FlowTypesOf(r.FlowId))
            {
                TypeState t = _types[id];
                t.Mode = "Mine"; t.Bound = true; t.Verified = false; t.Version++;
                bool hidden;
                r.KeepHidden.TryGetValue(id, out hidden);
                // Exportable is set when the vault key is made, and it is one-way: a later run cannot turn a hidden key back into a showing one.
                t.KeepHidden = (t.KeepHidden && !M("exportable-flips")) || hidden;
                bool imported = r.Source == "files" && r.Paths.ContainsKey(id);
                t.Provider = imported ? "file" : "vault";
                if (id == "token.issuer")
                {
                    t.Key = imported ? ReadKey(r.Paths[id]) : NewKey("issuer");
                    t.Seed = t.Key.Seed;
                }
                else if (IsEd25519Type(id) && imported) t.Seed = ReadKey(r.Paths[id]).Seed;
                else t.Seed = RandomBytes(id.StartsWith("dukpt.") || id.StartsWith("lab.") ? 16 : 32);
                if (t.Provider == "vault") VaultStore(t, t.KeepHidden);
            }
        }

        void RunCheck(FlowRun r)
        {
            r.Facts.Clear();
            foreach (string id in FlowTypesOf(r.FlowId))
            {
                _types[id].Verified = true;
                string judge = JudgeOf(id);
                if (M("device-judge-claimed") && id == "device.enrolment") judge = "openssl";
                if (!M("no-judge-facts")) r.Facts.Add(D("typeId", id, "judge", judge, "says", SaysOf(id)));
            }
            r.Checked = true;
        }
    }
}
