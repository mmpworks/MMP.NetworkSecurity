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

        /// <summary>
        /// One wizard run, driven by what each step says it is. The spine of modes-design.md 8.2 and the five screens of wizards-ux.md 3.2 name their states differently
        /// (Make or ChooseSource and Place, Review or ReadBack, Check or Prove). Both agree on the step kinds: explain, choose or generate, file, review, prove, done.
        /// So the driver reads the step kind and the events the step allows, and no clause depends on a state name.
        /// </summary>
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

            static List<string> Strings(List<object> l)
            {
                List<string> a = new List<string>();
                if (l != null) foreach (object o in l) a.Add(o as string);
                return a;
            }

            static List<Dictionary<string, object>> Objects(List<object> l)
            {
                List<Dictionary<string, object>> a = new List<Dictionary<string, object>>();
                if (l != null) foreach (object o in l) a.Add(MiniJson.AsObject(o));
                return a;
            }

            public List<string> Allowed { get { return Strings(MiniJson.Arr(Step, "allowed")); } }

            /// <summary>The errors that stop the step: errors[] without a severity of warning.</summary>
            public List<Dictionary<string, object>> Errors
            {
                get
                {
                    List<Dictionary<string, object>> a = new List<Dictionary<string, object>>();
                    foreach (Dictionary<string, object> e in Objects(MiniJson.Arr(Step, "errors"))) if (MiniJson.Str(e, "severity") != "warning") a.Add(e);
                    return a;
                }
            }

            /// <summary>The warnings that let the learner go on: warnings[], and any errors[] row with severity warning.</summary>
            public List<Dictionary<string, object>> Warnings
            {
                get
                {
                    List<Dictionary<string, object>> a = Objects(MiniJson.Arr(Step, "warnings"));
                    foreach (Dictionary<string, object> e in Objects(MiniJson.Arr(Step, "errors"))) if (MiniJson.Str(e, "severity") == "warning") a.Add(e);
                    return a;
                }
            }

            public List<string> ErrorCodes { get { return Codes(Errors); } }
            public List<string> WarningCodes { get { return Codes(Warnings); } }

            static List<string> Codes(List<Dictionary<string, object>> rows)
            {
                List<string> a = new List<string>();
                foreach (Dictionary<string, object> e in rows) a.Add(MiniJson.Str(e, "code"));
                return a;
            }

            public List<Dictionary<string, object>> Facts { get { return Objects(MiniJson.Arr(Step, "facts")); } }

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

            /// <summary>The first of the named events this step allows, or null.</summary>
            public string PickOrNull(params string[] preferred)
            {
                List<string> allowed = Allowed;
                foreach (string p in preferred) if (allowed.Contains(p)) return p;
                return null;
            }

            public string Pick(params string[] preferred)
            {
                string p = PickOrNull(preferred);
                if (p == null) throw new FailException("the " + Kind + " step (state " + State + ") allows [" + string.Join(",", Allowed.ToArray()) + "], and none of [" + string.Join(",", preferred) + "] is among them");
                return p;
            }

            void Ok(Reply r, string what)
            {
                Check.True(r.Ok, what + " got " + r);
                List<string> messages = new List<string>();
                foreach (Dictionary<string, object> e in Errors) messages.Add(MiniJson.Str(e, "message") ?? "");
                NotRunIfOnlyPartNotBuilt(ErrorCodes, messages, what);
                Check.True(ErrorCodes.Count == 0, what + " gave errors " + string.Join(",", ErrorCodes.ToArray()));
            }

            /// <summary>Goes on: next, or continue.</summary>
            public void Next() { string ev = Pick("next", "continue"); Ok(Send(ev, null), "event " + ev + " at the " + Kind + " step"); }

            /// <summary>Runs the check when the step has an event for it. A step that checks on its own already holds the result in facts[].</summary>
            public void RunCheck()
            {
                string ev = PickOrNull("check", "prove", "run");
                if (ev != null) Ok(Send(ev, null), "event " + ev);
            }

            /// <summary>One step of "Make it for me": the first make-like event the step allows.</summary>
            void Make()
            {
                string ev = Pick("make", "choose", "next", "continue");
                Ok(Send(ev, ev == "choose" ? Obj("source", "make") : null), "event " + ev + " at the " + Kind + " step");
            }

            /// <summary>
            /// "Make it for me" through the whole default path: explain, choose or generate, review, prove, done. Stops early at stopAt:
            /// Intro (the first step), Make (the first choose step), Review, Check (the prove step, not run), Checked (the check has run).
            /// </summary>
            public void MakeForMe(string stopAt)
            {
                Check.Equal("kind of the first step of " + FlowId, "explain", Kind);
                if (stopAt == "Intro") return;
                Next();
                Check.True(Kind == "choose" || Kind == "generate", "the step after Intro is " + Kind + "; expected choose or generate");
                if (stopAt == "Make") return;
                MakeAll();
                Tail(stopAt);
            }

            /// <summary>From a choose or generate step to Review: "Make it for me", whatever number of screens the default path spends on it.</summary>
            public void MakeAll()
            {
                int guard = 0;
                while (Kind != "review" && guard++ < 5)
                {
                    Check.True(Kind == "choose" || Kind == "generate", "the make screens hold a " + Kind + " step; expected choose or generate");
                    Make();
                }
            }

            /// <summary>"Use my own files": the branch screen, one row per type, by path. Then the same path from Review.</summary>
            public void UseFiles(Dictionary<string, string> paths, string stopAt)
            {
                Check.Equal("kind of the first step of " + FlowId, "explain", Kind);
                Next();
                OpenFileBranch();
                SubmitFiles(paths);
                Check.True(Kind != "file" || PickOrNull("next", "continue") != null, "the branch screen still waits after the files were read");
                int guard = 0;
                while (Kind != "review" && guard++ < 3) Next();
                Tail(stopAt);
            }

            public void OpenFileBranch()
            {
                string ev = PickOrNull("files-branch", "pick", "use-files");
                Reply r = ev != null ? Send(ev, null) : Send(Pick("choose"), Obj("source", "files"));
                Ok(r, "opening the file branch");
                Check.Equal("kind of the file branch", "file", Kind);
            }

            public Reply SubmitFiles(Dictionary<string, string> paths)
            {
                Dictionary<string, object> pd = new Dictionary<string, object>();
                foreach (KeyValuePair<string, string> kv in paths) pd[kv.Key] = kv.Value;
                Reply f = Send(Pick("files", "submit"), Obj("paths", pd));
                Check.True(f.Ok, "event files got " + f);
                foreach (Dictionary<string, object> e in Errors)
                    throw new FailException("event files gave the error " + MiniJson.Str(e, "code") + ": " + MiniJson.Str(e, "message"));
                return f;
            }

            void Tail(string stopAt)
            {
                Check.Equal("kind before Review", "review", Kind);
                if (stopAt == "Review") return;
                Next();
                Check.Equal("kind after Review", "prove", Kind);
                if (stopAt == "Check") return;
                RunCheck();
                if (stopAt == "Checked") return;
                Next();
                Check.Equal("kind after the check", "done", Kind);
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
        public static Flow RunFlow(HostProc h, string flowId)
        {
            Flow f = Flow.Start(h, flowId);
            f.MakeForMe(null);
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

        /// <summary>An Ed25519 private key the suite made itself, so it knows the bytes. Returns the PEM path, the 32-byte seed as hex, and the public key as hex.</summary>
        public sealed class TestKey { public string Pem, SeedHex, PublicHex; }

        public static TestKey MakeEd25519(Ctx c, string name)
        {
            string dir = TempDir(c, "keys"), o, pem = Path.Combine(dir, name + ".pem"), priv = Path.Combine(dir, name + ".priv.der"), pub = Path.Combine(dir, name + ".pub.der");
            string openssl = Referees.OpenSsl(c);
            if (Proc.Run(openssl, "genpkey -algorithm ed25519 -out \"" + pem + "\"", dir, 30000, out o) != 0) throw new FailException("openssl genpkey failed: " + o);
            if (Proc.Run(openssl, "pkey -in \"" + pem + "\" -outform DER -out \"" + priv + "\"", dir, 30000, out o) != 0) throw new FailException("openssl pkey failed: " + o);
            if (Proc.Run(openssl, "pkey -in \"" + pem + "\" -pubout -outform DER -out \"" + pub + "\"", dir, 30000, out o) != 0) throw new FailException("openssl pkey -pubout failed: " + o);
            byte[] p8 = File.ReadAllBytes(priv), spki = File.ReadAllBytes(pub);
            Check.True(p8.Length == 48 && spki.Length == 44, "the Ed25519 DER sizes are " + p8.Length + " and " + spki.Length + "; expected 48 and 44");
            return new TestKey { Pem = pem, SeedHex = Hex.Encode(Hex.Slice(p8, 16, 32)), PublicHex = Hex.Encode(Hex.Slice(spki, 12, 32)) };
        }

        // ------------------------------------------------------------ "Use my files", driven to the first refusal

        /// <summary>What an import run reached. Codes and messages are every blocking error the steps reported, in order. Warnings are kept apart.</summary>
        public sealed class ImportResult
        {
            public readonly List<string> Codes = new List<string>(), Messages = new List<string>(), Warnings = new List<string>();
            public bool Done;
            public Flow Flow;
            public bool Has(string code) { return Codes.Contains(code); }
            public override string ToString() { return (Done ? "reached Done" : "stopped at the " + (Flow == null ? "?" : Flow.Kind) + " step") + (Codes.Count == 0 ? "" : " with " + string.Join(",", Codes.ToArray())); }
        }

        /// <summary>The Host says WIZARD_PART_NOT_BUILT for a type with no row in FlowParts, so the clause has nothing to judge yet. Only that code reads NOT RUN: one other code in the list, or any other failure, stays FAIL.</summary>
        public static void NotRunIfOnlyPartNotBuilt(List<string> codes, List<string> messages, string what)
        {
            if (codes.Count == 0) return;
            foreach (string code in codes) if (code != "WIZARD_PART_NOT_BUILT") return;
            List<string> owed = new List<string>();
            foreach (string m in messages) if (!owed.Contains(m)) owed.Add(m);
            throw new NotRunException("WIZARD_PART_NOT_BUILT", what + ": the product owes this part. " + string.Join(" ", owed.ToArray()));
        }

        static bool Collect(ImportResult r, Reply reply)
        {
            if (!reply.Ok) { r.Codes.Add(reply.Code ?? ("HTTP_" + reply.Status)); r.Messages.Add(reply.ToString()); return false; }
            foreach (string w in r.Flow.WarningCodes) r.Warnings.Add(w);
            bool blocking = false;
            foreach (Dictionary<string, object> e in r.Flow.Errors)
            {
                r.Codes.Add(MiniJson.Str(e, "code")); r.Messages.Add(MiniJson.Str(e, "message") ?? "");
                blocking = true;
            }
            if (blocking) NotRunIfOnlyPartNotBuilt(r.Codes, r.Messages, "a file import");
            return !blocking;
        }

        /// <summary>
        /// Walks a flow with "Use my own files" and does not throw on a refusal: it records the codes and stops at the first step with an error (a warning does not stop it).
        /// A refusal can come when the files are read, at Review, or at the check, and the callers look for a code at any of them.
        /// </summary>
        public static ImportResult TryImport(HostProc h, string flowId, Dictionary<string, string> paths)
        {
            ImportResult r = new ImportResult();
            r.Flow = Flow.Start(h, flowId);
            Flow f = r.Flow;
            if (!Collect(r, f.Send(f.Pick("next", "continue"), null))) return r;
            string open = f.PickOrNull("files-branch", "pick", "use-files");
            if (!Collect(r, open != null ? f.Send(open, null) : f.Send(f.Pick("choose"), Obj("source", "files")))) return r;
            Dictionary<string, object> pd = new Dictionary<string, object>();
            foreach (KeyValuePair<string, string> kv in paths) pd[kv.Key] = kv.Value;
            if (!Collect(r, f.Send(f.Pick("files", "submit"), Obj("paths", pd)))) return r;
            int guard = 0;
            while (f.Kind != "review" && f.Kind != "prove" && f.Kind != "done" && guard++ < 3)
                if (!Collect(r, f.Send(f.Pick("next", "continue"), null))) return r;
            if (f.Kind == "review" && !Collect(r, f.Send(f.Pick("next", "continue"), null))) return r;
            if (f.Kind == "prove")
            {
                string check = f.PickOrNull("check", "prove", "run");
                if (check != null && !Collect(r, f.Send(check, null))) return r;
                if (!Collect(r, f.Send(f.Pick("next", "continue"), null))) return r;
            }
            r.Done = f.Kind == "done";
            return r;
        }

        // ------------------------------------------------------------ the practice vault, read from its file

        public static string VaultDbPath(HostProc h)
        {
            if (string.IsNullOrEmpty(h.SecurityDir)) throw new FailException("the suite does not know the Host's security folder");
            return Path.Combine(h.SecurityDir, "vault", "vault.db");
        }

        /// <summary>Runs checks/vaultdb.py against the Host's vault.db. Returns the parsed JSON, or a FAIL that carries the script's output.</summary>
        public static object VaultDb(Ctx c, HostProc h, string command)
        {
            string db = VaultDbPath(h), o;
            if (!File.Exists(db)) throw new FailException("the Host wrote no vault file at " + db + " (modes-design.md section 5.1)");
            string script = Path.Combine(c.AcceptanceDir, "checks", "vaultdb.py");
            int code = Proc.Run("python", "-I \"" + script + "\" " + command + " \"" + db + "\"", c.AcceptanceDir, 60000, out o);
            if (code != 0) throw new FailException("vaultdb.py " + command + " exited " + code + ": " + o.Trim());
            return MiniJson.Parse(o.Trim());
        }

        /// <summary>
        /// The key bytes of every vault key whose name starts with prefix, taken out of vault.db by the suite with vault/master.key (modes-design.md section 4.1:
        /// AES-256-GCM under a master key, name#version as the additional data; ASSUMED layout: wrapped = ciphertext then a 16-byte tag, nonce in its own column).
        /// If the file does not unwrap that way the clause reads NOT RUN VAULT_LAYOUT_UNKNOWN.
        /// </summary>
        public static List<string> UnwrapVaultKeys(Ctx c, HostProc h, string prefix)
        {
            string master = Path.Combine(h.SecurityDir, "vault", "master.key");
            if (!File.Exists(master)) throw new NotRunException("VAULT_LAYOUT_UNKNOWN", "no vault/master.key at " + master + " (modes-design.md section 5.1)");
            byte[] mk = File.ReadAllBytes(master);
            if (mk.Length != 32) throw new NotRunException("VAULT_LAYOUT_UNKNOWN", "vault/master.key holds " + mk.Length + " bytes; design 5.1 gives 32");
            List<string> found = new List<string>();
            foreach (object o in (List<object>)VaultDb(c, h, "key-versions-full"))
            {
                Dictionary<string, object> r = MiniJson.AsObject(o);
                string name = MiniJson.Str(r, "name");
                if (!name.StartsWith(prefix)) continue;
                byte[] nonce = Hex.Decode(MiniJson.Str(r, "nonceHex")), wrapped = Hex.Decode(MiniJson.Str(r, "wrappedHex"));
                if (wrapped.Length <= 16 || nonce.Length != 12) throw new NotRunException("VAULT_LAYOUT_UNKNOWN", name + ": nonce " + nonce.Length + " bytes, wrapped " + wrapped.Length + " bytes; expected 12 and more than 16");
                byte[] ct = Hex.Slice(wrapped, 0, wrapped.Length - 16), tag = Hex.Slice(wrapped, wrapped.Length - 16, 16), pt = new byte[ct.Length];
                try
                {
                    using (System.Security.Cryptography.AesGcm g = new System.Security.Cryptography.AesGcm(mk, 16))
                        g.Decrypt(nonce, ct, tag, pt, Encoding.UTF8.GetBytes(name + "#" + MiniJson.Num(r, "version", 0).ToString("0")));
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    throw new NotRunException("VAULT_LAYOUT_UNKNOWN", name + " does not unwrap with vault/master.key as AES-256-GCM with name#version as additional data");
                }
                found.Add(Hex.Encode(pt));
                if (pt.Length > 32) found.Add(Hex.Encode(Hex.Slice(pt, pt.Length - 32, 32)));
            }
            if (found.Count == 0) throw new FailException("the vault file holds no key whose name starts with " + prefix);
            return found;
        }

        public static List<Dictionary<string, object>> FileAuditRows(Ctx c, HostProc h)
        {
            List<Dictionary<string, object>> rows = new List<Dictionary<string, object>>();
            foreach (object o in (List<object>)VaultDb(c, h, "audit-rows")) rows.Add(MiniJson.AsObject(o));
            return rows;
        }

        public static string TempDir(Ctx c, string name)
        {
            string d = Path.Combine(c.WorkDir, "a17-" + name);
            Directory.CreateDirectory(d);
            return d;
        }
    }
}
