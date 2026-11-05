using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// What every A17 clause needs: the Host's security routes (modes-design.md section 8.3), the five flows as a driver, and a few readers.
    /// The shapes are in acceptance/CONTRACT.md, section 5. A name there marked ASSUMED is the suite's reading of a design that names no field.
    /// </summary>
    public static class A17
    {
        public static readonly string[] AllTypes = new string[]
        {
            "pki.root-ca", "tls.trust", "tls13.server", "tls13.client", "tls11.server",
            "ssh.host-ed25519", "ssh.host-rsa", "ssh.known-hosts", "ssh.client",
            "dukpt.bdk", "dukpt.pad", "token.issuer", "device.enrolment", "lab.aes-key", "lab.seal-key"
        };

        public static string Obj(params object[] kv)
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            for (int i = 0; i + 1 < kv.Length; i += 2) d[(string)kv[i]] = kv[i + 1];
            return MiniJson.Write(d);
        }

        public static HostProc Host(Ctx c, string name)
        {
            HostProc h = HostProc.Start(c, name, null);
            HostChecks.RequireShowKeysOn(h);
            return h;
        }

        // ------------------------------------------------------------ GET /api/security

        public static Dictionary<string, object> Security(HostProc h)
        {
            Reply r = HostHttp.Get(h, "/api/security");
            Check.True(r.Ok && r.Json != null, "GET /api/security got " + r);
            return r.Json;
        }

        /// <summary>The row of one type from GET /api/security, or a FAIL naming the type.</summary>
        public static Dictionary<string, object> TypeRow(HostProc h, string typeId)
        {
            List<object> types = MiniJson.Arr(Security(h), "types");
            Check.True(types != null, "GET /api/security has no types[]");
            foreach (object o in types)
            {
                Dictionary<string, object> d = MiniJson.AsObject(o);
                if (MiniJson.Str(d, "typeId") == typeId) return d;
            }
            throw new FailException("GET /api/security lists no type " + typeId + ". The 15 types of modes-design.md section 1 must all be there");
        }

        public static string StateOf(HostProc h, string typeId) { return MiniJson.Str(TypeRow(h, typeId), "state"); }
        public static string ModeOf(HostProc h, string typeId) { return MiniJson.Str(TypeRow(h, typeId), "mode"); }

        public static void SetMode(HostProc h, string typeId, string mode)
        {
            Reply r = HostHttp.Put(h, "/api/security/types/" + typeId + "/mode", Obj("mode", mode));
            Check.True(r.Ok, "PUT mode " + mode + " for " + typeId + " got " + r);
        }

        public static Reply Readiness(HostProc h, int lesson)
        {
            return HostHttp.Get(h, "/api/security/readiness?lesson=" + lesson);
        }

        /// <summary>The problems[] codes of a readiness answer, as "typeId:code".</summary>
        public static List<string> ProblemCodes(Reply readiness)
        {
            List<string> r = new List<string>();
            List<object> p = MiniJson.Arr(readiness.Json, "problems");
            if (p == null) return r;
            foreach (object o in p)
            {
                Dictionary<string, object> d = MiniJson.AsObject(o);
                r.Add(MiniJson.Str(d, "typeId") + ":" + MiniJson.Str(d, "code"));
            }
            return r;
        }

        public static Reply Key(HostProc h, string typeId) { return HostHttp.Get(h, "/api/security/types/" + typeId + "/key"); }

        public static bool ShowKeys(HostProc h)
        {
            Reply r = HostHttp.Get(h, "/api/security/show-keys");
            Check.True(r.Ok && r.Json != null, "GET /api/security/show-keys got " + r);
            return MiniJson.Bool(r.Json, "on", true);
        }

        public static void SetShowKeys(HostProc h, bool on)
        {
            Reply r = HostHttp.Put(h, "/api/security/show-keys", Obj("on", on));
            Check.True(r.Ok, "PUT show-keys " + on + " got " + r);
            Check.True(ShowKeys(h) == on, "the toggle did not take: asked for " + on);
        }

        public static List<Dictionary<string, object>> Audit(HostProc h)
        {
            Reply r = HostHttp.Get(h, "/api/security/vault/audit?after=0");
            Check.True(r.Ok && r.Json != null, "GET vault/audit got " + r);
            List<Dictionary<string, object>> rows = new List<Dictionary<string, object>>();
            List<object> a = MiniJson.Arr(r.Json, "rows");
            if (a != null) foreach (object o in a) rows.Add(MiniJson.AsObject(o));
            return rows;
        }

        // ------------------------------------------------------------ the flows

        /// <summary>One wizard run, driven event by event. Step is the last step the Host sent.</summary>
        public sealed class Flow
        {
            public HostProc H;
            public string RunId, FlowId;
            public Dictionary<string, object> Step;
            public List<string> States = new List<string>();
            public Reply Last;

            public string State { get { return MiniJson.Str(Step, "state"); } }
            public string Kind { get { return MiniJson.Str(Step, "kind"); } }
            public int Seq { get { return (int)MiniJson.Num(Step, "stepSeq", -1); } }

            public List<string> Allowed
            {
                get
                {
                    List<string> a = new List<string>();
                    List<object> l = MiniJson.Arr(Step, "allowed");
                    if (l != null) foreach (object o in l) a.Add(o as string);
                    return a;
                }
            }

            public List<string> ErrorCodes
            {
                get
                {
                    List<string> a = new List<string>();
                    foreach (Dictionary<string, object> e in Errors) a.Add(MiniJson.Str(e, "code"));
                    return a;
                }
            }

            public List<Dictionary<string, object>> Errors
            {
                get
                {
                    List<Dictionary<string, object>> a = new List<Dictionary<string, object>>();
                    List<object> l = MiniJson.Arr(Step, "errors");
                    if (l != null) foreach (object o in l) a.Add(MiniJson.AsObject(o));
                    return a;
                }
            }

            public List<Dictionary<string, object>> Facts
            {
                get
                {
                    List<Dictionary<string, object>> a = new List<Dictionary<string, object>>();
                    List<object> l = MiniJson.Arr(Step, "facts");
                    if (l != null) foreach (object o in l) a.Add(MiniJson.AsObject(o));
                    return a;
                }
            }

            public static Flow Start(HostProc h, string flowId)
            {
                Flow f = new Flow();
                f.H = h; f.FlowId = flowId;
                Reply r = HostHttp.Post(h, "/api/security/flows/" + flowId + "/runs", "{}");
                Check.True(r.Ok && r.Json != null, "POST flows/" + flowId + "/runs got " + r);
                f.RunId = MiniJson.Str(r.Json, "runId");
                Check.True(!string.IsNullOrEmpty(f.RunId), "the reply to POST flows/" + flowId + "/runs has no runId: " + r);
                f.Step = MiniJson.Obj(r.Json, "step");
                Check.True(f.Step != null, "the reply to POST flows/" + flowId + "/runs has no step: " + r);
                f.States.Add(f.State);
                return f;
            }

            /// <summary>Sends an event with the current stepSeq. Returns the reply. When the Host answers with a step, it becomes the current one.</summary>
            public Reply Send(string ev, string dataJson) { return SendSeq(ev, Seq, dataJson); }

            public Reply SendSeq(string ev, int stepSeq, string dataJson)
            {
                Last = HostHttp.Post(H, "/api/security/runs/" + RunId + "/events", Obj("event", ev, "stepSeq", (double)stepSeq, "data", dataJson == null ? new Dictionary<string, object>() : MiniJson.AsObject(MiniJson.Parse(dataJson))));
                Dictionary<string, object> step = MiniJson.Obj(Last.Json, "step");
                if (Last.Ok && step != null) { Step = step; States.Add(State); }
                return Last;
            }

            /// <summary>Sends next and requires the Host to take it.</summary>
            public void Next()
            {
                Reply r = Send("next", null);
                Check.True(r.Ok, "event next at state " + State + " got " + r);
                Check.True(ErrorCodes.Count == 0, "event next at state " + State + " gave errors " + string.Join(",", ErrorCodes.ToArray()));
            }

            /// <summary>
            /// "Make them for me" through the whole spine: Intro, ChooseSource, [Options], ReadBack, Place, Check, Done. keepHidden lists the types the
            /// learner asks to keep from showing. Stops at stopAt (a state name) when given, with that state as the current step.
            /// </summary>
            public void MakeForMe(Dictionary<string, bool> keepHidden, string stopAt)
            {
                Check.Equal("first state of " + FlowId, "Intro", State);
                if (stopAt == "Intro") return;
                Next();
                Check.Equal("state after Intro", "ChooseSource", State);
                if (stopAt == "ChooseSource") return;
                Reply c = Send("choose", Obj("source", "make"));
                Check.True(c.Ok, "event choose (make) got " + c);
                if (State == "Options")
                {
                    if (keepHidden != null)
                        foreach (KeyValuePair<string, bool> kv in keepHidden)
                        {
                            Reply o = Send("option", Obj("typeId", kv.Key, "keepHidden", kv.Value));
                            Check.True(o.Ok, "event option for " + kv.Key + " got " + o);
                        }
                    if (stopAt == "Options") return;
                    Next();
                }
                Check.Equal("state before ReadBack", "ReadBack", State);
                if (stopAt == "ReadBack") return;
                Next();
                Check.Equal("state after ReadBack", "Place", State);
                if (stopAt == "Place") return;
                Next();
                Check.Equal("state after Place", "Check", State);
                if (stopAt == "Check") return;
                // At Check the learner runs the check, and the Host runs the outside tool (section 8.6). Next goes on only after it passed.
                Reply k = Send("check", null);
                Check.True(k.Ok, "event check got " + k);
                Check.True(ErrorCodes.Count == 0, "the check of " + FlowId + " gave errors " + string.Join(",", ErrorCodes.ToArray()));
                if (stopAt == "Checked") return;
                Next();
                Check.Equal("state after Check", "Done", State);
            }
        }

        public static string FlowOf(string typeId)
        {
            switch (typeId)
            {
                case "pki.root-ca": case "tls.trust": case "tls13.server": case "tls13.client": case "tls11.server": return "my-certificates";
                case "ssh.host-ed25519": case "ssh.host-rsa": case "ssh.known-hosts": case "ssh.client": return "my-ssh";
                case "dukpt.bdk": case "dukpt.pad": return "my-payment";
                case "token.issuer": case "device.enrolment": return "my-login";
                default: return "my-lesson-keys";
            }
        }

        public static string[] TypesOf(string flowId)
        {
            switch (flowId)
            {
                case "my-certificates": return new string[] { "pki.root-ca", "tls.trust", "tls13.server", "tls13.client", "tls11.server" };
                case "my-ssh": return new string[] { "ssh.host-ed25519", "ssh.host-rsa", "ssh.known-hosts", "ssh.client" };
                case "my-payment": return new string[] { "dukpt.bdk", "dukpt.pad" };
                case "my-login": return new string[] { "token.issuer", "device.enrolment" };
                case "my-lesson-keys": return new string[] { "lab.aes-key", "lab.seal-key" };
            }
            throw new FailException("unknown flow " + flowId);
        }

        /// <summary>Runs a whole flow in "make them for me" and requires every type of it to be Mine and Verified afterwards.</summary>
        public static Flow RunFlow(HostProc h, string flowId, Dictionary<string, bool> keepHidden)
        {
            Flow f = Flow.Start(h, flowId);
            f.MakeForMe(keepHidden, null);
            foreach (string t in TypesOf(flowId))
            {
                Check.Equal("mode of " + t + " after " + flowId, "Mine", ModeOf(h, t));
                Check.Equal("state of " + t + " after " + flowId, "Verified", StateOf(h, t));
            }
            return f;
        }

        // ------------------------------------------------------------ reading secrets out of a session

        public static string Fingerprint(string hex)
        {
            byte[] b = Hex.Decode(hex);
            using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create())
            {
                byte[] d = sha.ComputeHash(b);
                return "fp:" + Hex.Encode(Hex.Slice(d, 0, 8));
            }
        }

        /// <summary>Every secrets[] entry of every event: name, holder, hex (or empty), fingerprint, hidden.</summary>
        public sealed class SecretRef { public string Name, Holder, Hex, Fingerprint, Hidden, EventType, EventId; }

        public static List<SecretRef> Secrets(SessionRun run)
        {
            List<SecretRef> r = new List<SecretRef>();
            foreach (Dictionary<string, object> ev in run.Events)
            {
                List<object> s = MiniJson.Arr(ev, "secrets");
                if (s == null) continue;
                foreach (object o in s)
                {
                    Dictionary<string, object> d = MiniJson.AsObject(o);
                    SecretRef x = new SecretRef();
                    x.Name = MiniJson.Str(d, "name"); x.Holder = MiniJson.Str(d, "holder"); x.Hex = MiniJson.Str(d, "hex") ?? "";
                    x.Fingerprint = MiniJson.Str(d, "fingerprint"); x.Hidden = MiniJson.Str(d, "hidden");
                    x.EventType = MiniJson.Str(ev, "type"); x.EventId = MiniJson.Str(ev, "eventId");
                    r.Add(x);
                }
            }
            return r;
        }

        /// <summary>The text of everything the Host exposed for a session: frames, /events, and the session file.</summary>
        public static string Everything(HostProc h, SessionRun run)
        {
            StringBuilder sb = new StringBuilder();
            foreach (string f in run.Frames) sb.Append(f).Append('\n');
            Reply ev = HostHttp.Get(h, "/api/sessions/" + run.SessionId + "/events?after=0");
            sb.Append(ev.Body ?? "").Append('\n');
            if (!string.IsNullOrEmpty(run.SessionFile) && File.Exists(run.SessionFile)) sb.Append(File.ReadAllText(run.SessionFile)).Append('\n');
            return sb.ToString();
        }

        public static string TempDir(Ctx c, string name)
        {
            string d = Path.Combine(c.WorkDir, "a17-" + name);
            Directory.CreateDirectory(d);
            return d;
        }
    }
}
