using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Threading;

namespace Acceptance
{
    // The wizard machine and the lesson sessions of the fake Host. See FakeHost.cs.
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
                case "Intro": return "info";
                case "ChooseSource": return "choose";
                case "PickFiles": return "pick";
                case "Options": return "options";
                case "ReadBack": return "review";
                case "Place": return "place";
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
            if (typeId.StartsWith("dukpt.") || typeId.StartsWith("lab.") || typeId == "device.enrolment") return "none";
            return "openssl";
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
            string from = r.State;
            switch (ev)
            {
                case "next":
                    switch (r.State)
                    {
                        case "Intro": Go(r, "ChooseSource"); break;
                        case "Options": Go(r, "ReadBack"); break;
                        case "PickFiles": Go(r, "ReadBack"); break;
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
                    if (r.Source == "files" && r.FlowId == "my-ssh") Go(r, "PickFiles");
                    else if (r.Source == "make") Go(r, "Options");
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

        static void Go(FlowRun r, string to) { r.Back.Add(r.State); r.State = to; }

        void CheckPaths(FlowRun r, Dictionary<string, object> data)
        {
            Dictionary<string, object> paths = MiniJson.Obj(data, "paths");
            string ssh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
            if (paths == null) return;
            foreach (KeyValuePair<string, object> kv in paths)
            {
                string p = kv.Value as string ?? "";
                if (!M("no-personal-warning") && p.StartsWith(ssh, StringComparison.OrdinalIgnoreCase))
                    r.Errors.Add(D("code", "KEY_PATH_PERSONAL", "severity", "warning", "typeId", kv.Key, "message", "This path is in your own .ssh folder. Use a test key."));
                if (!File.Exists(p))
                    r.Errors.Add(D("code", "KEY_FILE_UNREADABLE", "severity", "error", "typeId", kv.Key, "message", "The file cannot be read."));
            }
        }

        void Apply(FlowRun r)
        {
            foreach (string id in FlowTypesOf(r.FlowId))
            {
                TypeState t = _types[id];
                t.Mode = "Mine"; t.Bound = true; t.Verified = false;
                bool hidden;
                t.KeepHidden = r.KeepHidden.TryGetValue(id, out hidden) && hidden;
                if (id == "token.issuer") t.Key = NewKey("issuer");
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
                if (!M("no-judge-facts")) r.Facts.Add(D("typeId", id, "judge", judge));
            }
            r.Checked = true;
        }

        // ------------------------------------------------------------ sessions over the WebSocket

        static void SendText(WebSocket ws, object o)
        {
            byte[] b = Encoding.UTF8.GetBytes(MiniJson.Write(o));
            ws.SendAsync(new ArraySegment<byte>(b), WebSocketMessageType.Text, true, CancellationToken.None).Wait(15000);
        }

        void HandleSocket(HttpListenerContext ctx)
        {
            WebSocket ws = ctx.AcceptWebSocketAsync(null).Result.WebSocket;
            byte[] buf = new byte[1 << 16];
            List<Dictionary<string, object>> pending = null;
            string sessionId = null;
            while (ws.State == WebSocketState.Open)
            {
                WebSocketReceiveResult r;
                try { r = ws.ReceiveAsync(new ArraySegment<byte>(buf), CancellationToken.None).Result; } catch (Exception) { break; }
                if (r.MessageType == WebSocketMessageType.Close) break;
                Dictionary<string, object> m = MiniJson.AsObject(MiniJson.Parse(Encoding.UTF8.GetString(buf, 0, r.Count)));
                string type = MiniJson.Str(m, "type");
                if (type == "session.start")
                {
                    lock (_gate)
                    {
                        int lesson = (int)MiniJson.Num(m, "lesson", 0);
                        if (lesson < 1 || lesson > 11) { SendText(ws, D("type", "error", "code", "LESSON_NOT_BUILT", "message", "lesson " + lesson + " is not built")); break; }
                        List<Dictionary<string, object>> problems = Problems(lesson);
                        if (problems.Count > 0)
                        {
                            Dictionary<string, object> first = problems[0];
                            SendText(ws, D("type", "error", "requestId", MiniJson.Str(m, "requestId"), "code", MiniJson.Str(first, "code"), "message", MiniJson.Str(first, "message")));
                            break;
                        }
                        sessionId = "s" + (++_next);
                        pending = LessonEvents(lesson);
                        _sessions[sessionId] = pending;
                        string file = Path.Combine(Dir, "session-" + sessionId + ".ndjson");
                        File.WriteAllText(file, string.Join("\n", pending.ConvertAll(e => MiniJson.Write(e)).ToArray()) + "\n");
                        List<object> sec = new List<object>();
                        foreach (string id in A17.AllTypes) sec.Add(TypeJson(_types[id]));
                        SendText(ws, D("type", "session.started", "sessionId", sessionId, "transportKind", MiniJson.Str(m, "transport") ?? "glass",
                            "trainingOnly", (MiniJson.Str(m, "transport") ?? "glass") == "glass", "sessionFile", file, "showKeys", _showKeys, "security", sec));
                    }
                }
                else if (type == "session.run" && pending != null)
                {
                    foreach (Dictionary<string, object> e in pending) SendText(ws, D("type", "trace", "event", e));
                    SendText(ws, D("type", "session.finished", "sessionId", sessionId, "events", (double)pending.Count));
                    break;
                }
            }
            try { ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None).Wait(5000); } catch (Exception) { }
            try { ws.Dispose(); } catch (Exception) { }
        }

        List<object> Secret(string name, string holder, byte[] bytes, bool hiddenByLearner)
        {
            List<object> one = new List<object>();
            Dictionary<string, object> s = D("name", name, "holder", holder, "fingerprint", A17.Fingerprint(Hex.Encode(bytes)));
            if (_showKeys && !hiddenByLearner) s["hex"] = Hex.Encode(bytes);
            else s["hidden"] = hiddenByLearner ? "learner" : "show-keys-off";
            one.Add(s);
            return one;
        }

        List<Dictionary<string, object>> LessonEvents(int lesson)
        {
            List<Dictionary<string, object>> evs = new List<Dictionary<string, object>>();
            if (lesson == 10)
            {
                KeyPair signer = M("token-wrong-key") ? _builtinIssuer : ActiveIssuer();
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                string token = Sign(signer, "{\"iss\":\"lab\",\"sub\":\"learner\",\"iat\":" + now + ",\"exp\":" + (now + 300) + "}");
                KeyPair shown = M("pub-in-trace-wrong") ? _builtinIssuer : ActiveIssuer();
                List<object> secrets = new List<object>();
                secrets.AddRange(Secret("auth.token", "issuer", Encoding.ASCII.GetBytes(token), _types["token.issuer"].KeepHidden));
                secrets.AddRange(Secret("auth.issuer-public", "issuer", Hex.Decode(shown.PublicHex), false));
                evs.Add(D("type", "auth.token-issued", "eventId", "e1", "secrets", secrets));
                return evs;
            }
            if (lesson == 5)
            {
                for (int i = 1; i <= 5; i++)
                {
                    byte[] b = new byte[32];
                    new Random(20261105 + i).NextBytes(b);
                    evs.Add(D("type", "tls.secret", "eventId", "e" + i, "secrets", Secret("tls.secret" + i, "peer", b, false)));
                }
                return evs;
            }
            evs.Add(D("type", "lesson.step", "eventId", "e1", "secrets", new List<object>()));
            return evs;
        }
    }
}
