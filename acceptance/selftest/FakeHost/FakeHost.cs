using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Acceptance
{
    /// <summary>
    /// A stand-in for NetSec.Host, built from acceptance/CONTRACT.md section 5 and nothing else. It lets the A17 clauses run with no product:
    /// a faithful fake must pass every clause, and a fake with ONE named defect (a mutation) must fail the clause that owns that defect.
    /// It signs real Ed25519 tokens by running OpenSSL, so the Go referee has a real signature to judge.
    /// </summary>
    public sealed partial class FakeHost : IDisposable
    {
        public readonly int Port;
        public readonly string Token = Guid.NewGuid().ToString("N");
        public readonly string Dir;
        readonly string _mutation, _openssl;
        readonly HttpListener _http = new HttpListener();
        readonly object _gate = new object();
        readonly Dictionary<string, TypeState> _types = new Dictionary<string, TypeState>();
        readonly Dictionary<string, FlowRun> _runs = new Dictionary<string, FlowRun>();
        readonly Dictionary<string, Session> _sessions = new Dictionary<string, Session>();
        bool _showKeys;
        readonly KeyPair _builtinIssuer;
        int _next;

        public FakeHost(string dir, string mutation, string openssl, string vaultScript)
        {
            Dir = dir; _mutation = mutation ?? ""; _openssl = openssl;
            Directory.CreateDirectory(dir);
            VaultInit(vaultScript);
            _showKeys = !M("default-off");
            foreach (string t in A17.AllTypes) _types[t] = new TypeState { TypeId = t };
            _builtinIssuer = NewKey("builtin-issuer");
            Port = Proc.FreePort();
            _http.Prefixes.Add("http://127.0.0.1:" + Port + "/");
            _http.Start();
            Task.Run((Func<Task>)Loop);
        }

        bool M(string name) { return _mutation == name; }

        public void Dispose() { try { _http.Close(); } catch (Exception) { } }

        // ------------------------------------------------------------ state

        sealed class TypeState
        {
            public string TypeId, Mode = "BuiltIn", Provider = "builtin";
            public bool Bound, Verified, KeepHidden;
            public KeyPair Key;               // token.issuer only
            public byte[] Seed;               // the key bytes the lab holds for this type
            public int Version;
            public string State
            {
                get
                {
                    if (Mode != "Mine") return "BuiltIn";
                    return !Bound ? "Unconfigured" : Verified ? "Verified" : "Configured";
                }
            }
        }

        sealed class KeyPair { public string Pem, PublicHex; public byte[] Seed; }

        sealed class FlowRun
        {
            public string RunId, FlowId, State = "Intro", Source;
            public int Seq = 1;
            public bool Checked;
            public List<string> Back = new List<string>();
            public List<Dictionary<string, object>> Errors = new List<Dictionary<string, object>>();
            public List<object> Facts = new List<object>();
            public Dictionary<string, bool> KeepHidden = new Dictionary<string, bool>();
            public Dictionary<string, string> Paths = new Dictionary<string, string>();
            public bool FileBlocked;
        }

        static Dictionary<string, object> D(params object[] kv)
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            for (int i = 0; i + 1 < kv.Length; i += 2) d[(string)kv[i]] = kv[i + 1];
            return d;
        }

        // ------------------------------------------------------------ OpenSSL keys

        KeyPair NewKey(string name)
        {
            string pem = Path.Combine(Dir, name + "-" + (++_next) + ".pem"), o;
            if (Proc.Run(_openssl, "genpkey -algorithm ed25519 -out \"" + pem + "\"", Dir, 30000, out o) != 0) throw new InvalidOperationException("fake: genpkey failed: " + o);
            return ReadKey(pem);
        }

        /// <summary>Reads an Ed25519 private key PEM with OpenSSL. Returns null when OpenSSL cannot read it as one.</summary>
        KeyPair ReadKey(string pem)
        {
            string o, pub = Path.Combine(Dir, "pub-" + (++_next) + ".der"), priv = Path.Combine(Dir, "priv-" + (++_next) + ".der");
            if (Proc.Run(_openssl, "pkey -in \"" + pem + "\" -pubout -outform DER -out \"" + pub + "\"", Dir, 30000, out o) != 0) return null;
            if (Proc.Run(_openssl, "pkey -in \"" + pem + "\" -outform DER -out \"" + priv + "\"", Dir, 30000, out o) != 0) return null;
            byte[] spki = File.ReadAllBytes(pub), pkcs8 = File.ReadAllBytes(priv);
            if (spki.Length != 44 || pkcs8.Length != 48) return null;
            return new KeyPair { Pem = pem, PublicHex = Hex.Encode(Hex.Slice(spki, 12, 32)), Seed = Hex.Slice(pkcs8, 16, 32) };
        }

        static string B64Url(byte[] b) { return Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_'); }

        string Sign(KeyPair key, string payloadJson)
        {
            string head = B64Url(Encoding.ASCII.GetBytes("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}")) + "." + B64Url(Encoding.UTF8.GetBytes(payloadJson));
            string msg = Path.Combine(Dir, "msg-" + (++_next) + ".bin"), sig = msg + ".sig", o;
            File.WriteAllBytes(msg, Encoding.ASCII.GetBytes(head));
            if (Proc.Run(_openssl, "pkeyutl -sign -inkey \"" + key.Pem + "\" -rawin -in \"" + msg + "\" -out \"" + sig + "\"", Dir, 30000, out o) != 0) throw new InvalidOperationException("fake: sign failed: " + o);
            return head + "." + B64Url(File.ReadAllBytes(sig));
        }

        string Fingerprint(byte[] secret)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] d = sha.ComputeHash(secret);
                return "fp:" + Hex.Encode(Hex.Slice(d, M("fingerprint-wrong") ? 8 : 0, 8));
            }
        }

        // ------------------------------------------------------------ the HTTP loop

        async Task Loop()
        {
            while (_http.IsListening)
            {
                HttpListenerContext ctx;
                try { ctx = await _http.GetContextAsync(); } catch (Exception) { return; }
                Task.Run(delegate () { Handle(ctx); });
            }
        }

        static void Write(HttpListenerContext ctx, int status, object body)
        {
            byte[] b = Encoding.UTF8.GetBytes(MiniJson.Write(body));
            ctx.Response.StatusCode = status;
            ctx.Response.ContentType = "application/json";
            ctx.Response.OutputStream.Write(b, 0, b.Length);
            ctx.Response.Close();
        }

        static void Fail(HttpListenerContext ctx, int status, string code, string message) { Write(ctx, status, D("code", code, "message", message, "retryable", false)); }

        bool Authorised(HttpListenerContext ctx, string tokenFromQuery)
        {
            string origin = ctx.Request.Headers["Origin"];
            if (origin != null && origin != "http://localhost:5173" && origin != "http://127.0.0.1:5173") { Fail(ctx, 403, "HOST_ORIGIN_REFUSED", "origin " + origin + " is not allowed"); return false; }
            string auth = ctx.Request.Headers["Authorization"];
            string given = tokenFromQuery ?? (auth != null && auth.StartsWith("Bearer ") ? auth.Substring(7) : null);
            if (given != Token) { Fail(ctx, 401, "HOST_TOKEN_REFUSED", "the token is missing or wrong"); return false; }
            return true;
        }

        void Handle(HttpListenerContext ctx)
        {
            try
            {
                string path = ctx.Request.Url.AbsolutePath, method = ctx.Request.HttpMethod;
                if (path == "/ws")
                {
                    if (!Authorised(ctx, ctx.Request.QueryString["token"])) return;
                    HandleSocket(ctx);
                    return;
                }
                if (!Authorised(ctx, null)) return;
                Dictionary<string, object> body = null;
                if (method == "POST" || method == "PUT")
                {
                    string text = new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEnd();
                    body = text.Length == 0 ? new Dictionary<string, object>() : MiniJson.AsObject(MiniJson.Parse(text));
                }
                lock (_gate) { Route(ctx, method, path, body); }
            }
            catch (Exception ex)
            {
                try { File.AppendAllText(Path.Combine(Dir, "fake-errors.log"), ex + "\n"); } catch (Exception) { }
                try { Fail(ctx, 500, "FAKE_HOST_BUG", ex.ToString()); } catch (Exception) { }
            }
        }

        void Route(HttpListenerContext ctx, string method, string path, Dictionary<string, object> body)
        {
            if (path == "/api/health")
            {
                Dictionary<string, object> h = D("ok", true);
                if (!M("no-health-showkeys")) h["showKeys"] = _showKeys;
                Write(ctx, 200, h);
                return;
            }
            if (path == "/api/lessons")
            {
                List<object> rows = new List<object>();
                for (int n = 1; n <= 11; n++) rows.Add(D("lesson", (double)n, "title", "Lesson " + n, "built", true, "attacks", new List<object>()));
                Write(ctx, 200, rows);
                return;
            }
            if (path == "/api/security" && method == "GET") { Write(ctx, 200, SecurityJson()); return; }
            if (path == "/api/security/readiness") { Write(ctx, 200, ReadinessJson(int.Parse(ctx.Request.QueryString["lesson"] ?? "0"))); return; }
            if (path == "/api/security/show-keys")
            {
                if (method == "PUT") _showKeys = MiniJson.Bool(body, "on", true);
                Write(ctx, 200, D("on", _showKeys));
                return;
            }
            if (path.StartsWith("/api/security/types/"))
            {
                string[] p = path.Substring("/api/security/types/".Length).Split('/');
                TypeState t;
                if (!_types.TryGetValue(p[0], out t)) { Fail(ctx, 404, "SECURITY_TYPE_UNKNOWN", "no type " + p[0]); return; }
                if (p.Length == 2 && p[1] == "mode" && method == "PUT") { t.Mode = MiniJson.Str(body, "mode"); Write(ctx, 200, TypeJson(t)); return; }
                if (p.Length == 2 && p[1] == "key") { KeyReply(ctx, t); return; }
            }
            if (path.StartsWith("/api/security/flows/") && path.EndsWith("/runs") && method == "POST") { StartRun(ctx, path.Split('/')[4]); return; }
            if (path.StartsWith("/api/security/runs/"))
            {
                string[] p = path.Substring("/api/security/runs/".Length).Split('/');
                FlowRun r;
                if (!_runs.TryGetValue(p[0], out r)) { Fail(ctx, 404, "WIZARD_RUN_NOT_FOUND", "no run " + p[0]); return; }
                if (p.Length == 1) { Write(ctx, 200, D("runId", r.RunId, "step", StepJson(r))); return; }
                if (p.Length == 2 && p[1] == "events" && method == "POST") { FlowEvent(ctx, r, body); return; }
            }
            if (path.StartsWith("/api/sessions/"))
            {
                string[] p = path.Substring("/api/sessions/".Length).Split('/');
                Session s;
                if (!_sessions.TryGetValue(p[0], out s)) { Fail(ctx, 404, "SESSION_NOT_FOUND", "no session " + p[0]); return; }
                if (p.Length == 2 && p[1] == "events") { Write(ctx, 200, RenderAll(s, M("off-keeps-hex-in-events") ? true : _showKeys)); return; }
                if (p.Length == 2 && p[1] == "keylog")
                {
                    if (!_showKeys && !M("keylog-served-when-off")) { Fail(ctx, 403, "KEYS_HIDDEN", "Show keys is off, so the key log is not served"); return; }
                    Write(ctx, 200, D("lines", new List<object>()));
                    return;
                }
            }
            bool handled = false;
            Route2Hook(ctx, method, path, body, ref handled);
            if (!handled) Fail(ctx, 404, "HOST_ROUTE_UNKNOWN", method + " " + path);
        }

        partial void Route2Hook(HttpListenerContext ctx, string method, string path, Dictionary<string, object> body, ref bool handled);

        // ------------------------------------------------------------ /api/security

        Dictionary<string, object> TypeJson(TypeState t) { return D("typeId", t.TypeId, "mode", t.Mode, "state", t.State); }

        Dictionary<string, object> SecurityJson()
        {
            List<object> types = new List<object>();
            foreach (string id in A17.AllTypes) types.Add(TypeJson(_types[id]));
            return D("types", types, "showKeys", _showKeys);
        }

        /// <summary>The key bytes a lab holds for a type: the learner's when Mine and bound, else a built-in key fixed by the type name.</summary>
        byte[] KeyBytes(TypeState t)
        {
            if (Active(t) && t.Seed != null) return t.Seed;
            if (t.TypeId == "token.issuer") return _builtinIssuer.Seed;
            using (SHA256 sha = SHA256.Create()) return sha.ComputeHash(Encoding.ASCII.GetBytes("builtin:" + t.TypeId));
        }

        static bool Active(TypeState t) { return t.Mode == "Mine" && t.Bound; }

        void KeyReply(HttpListenerContext ctx, TypeState t)
        {
            try { CourseRead(t, "security-page"); }
            catch (VaultError e) { Fail(ctx, 409, e.Code, e.Message); return; }
            byte[] key = KeyBytes(t);
            bool nonExportable = Active(t) && t.KeepHidden;
            bool showHex = _showKeys && (!nonExportable || M("nonexportable-leaks"));
            if (M("mine-key-route-no-hex") && Active(t)) showHex = false;
            if (M("nonexportable-hides-all") && Active(t)) showHex = false;
            Dictionary<string, object> r = D("typeId", t.TypeId, "version", (double)t.Version, "provider", t.Provider, "fingerprint", Fingerprint(key));
            if (t.TypeId == "token.issuer")
            {
                KeyPair k = ActiveIssuer();
                r["publicHex"] = M("key-route-other-public") ? _builtinIssuer.PublicHex : k.PublicHex;
            }
            if (showHex) r["hex"] = Hex.Encode(key);
            else r["hidden"] = nonExportable ? "non-exportable" : "toggle";
            Write(ctx, 200, r);
        }

        KeyPair ActiveIssuer()
        {
            TypeState t = _types["token.issuer"];
            return Active(t) && t.Key != null ? t.Key : _builtinIssuer;
        }

        // LabCatalog.Needs, as the table in modes-design.md section 1.7.
        static readonly Dictionary<int, string[]> LessonTypes = new Dictionary<int, string[]>
        {
            { 1, new string[] { "lab.aes-key" } },
            { 2, new string[] { "lab.seal-key" } },
            { 4, new string[] { "pki.root-ca", "tls13.server", "tls.trust" } },
            { 5, new string[] { "pki.root-ca", "tls13.server", "tls.trust" } },
            { 6, new string[] { "dukpt.bdk", "dukpt.pad" } },
            { 7, new string[] { "pki.root-ca", "tls11.server", "tls13.server", "tls.trust" } },
            { 8, new string[] { "ssh.host-ed25519", "ssh.host-rsa", "ssh.known-hosts", "ssh.client" } },
            { 9, new string[] { "ssh.host-ed25519", "ssh.known-hosts", "ssh.client", "pki.root-ca", "tls13.server", "tls.trust", "dukpt.bdk", "dukpt.pad" } },
            { 10, new string[] { "pki.root-ca", "tls13.server", "tls13.client", "tls.trust", "token.issuer", "device.enrolment" } },
        };

        static readonly string[] CertFamily = new string[] { "pki.root-ca", "tls.trust", "tls13.server", "tls13.client", "tls11.server" };

        /// <summary>The problems that stop a lab. Each is { typeId, code, detail }. The detail names the type and its flow.</summary>
        List<Dictionary<string, object>> Problems(int lesson)
        {
            List<Dictionary<string, object>> p = new List<Dictionary<string, object>>();
            string[] need;
            if (!LessonTypes.TryGetValue(lesson, out need)) return p;
            foreach (string id in need)
            {
                TypeState t = _types[id];
                if (t.Mode != "Mine") continue;
                if (!t.Bound && !M("ready-runs-anyway")) p.Add(Problem(id, "SECURITY_TYPE_NOT_READY", "the type " + id + " is set to My test key and has no key yet"));
                else if (t.Bound && !t.Verified && !M("proven-not-checked")) p.Add(Problem(id, "SECURITY_TYPE_NOT_PROVEN", "the type " + id + " has a key that no check has proven"));
            }
            List<string> chain = new List<string>();
            foreach (string id in need) if (Array.IndexOf(CertFamily, id) >= 0) chain.Add(id);
            if (chain.Count > 0 && !M("disagree-ignored"))
            {
                int mine = 0;
                foreach (string id in chain) if (_types[id].Mode == "Mine") mine++;
                if (mine > 0 && mine < chain.Count)
                    foreach (string id in chain)
                        if (_types[id].Mode != "Mine") p.Add(Problem(id, "SECURITY_TYPES_DISAGREE", "the type " + id + " is built-in while its partners are My test key"));
            }
            return p;
        }

        Dictionary<string, object> Problem(string typeId, string code, string message)
        {
            message += " (flow " + A17.FlowOf(typeId) + ")";
            if (M("ready-no-name")) message = "a type is not ready";
            if (M("ready-code-wrong")) code = "SECURITY_ERROR";
            return D("typeId", typeId, "code", code, "detail", message);
        }

        Dictionary<string, object> ReadinessJson(int lesson)
        {
            List<Dictionary<string, object>> p = Problems(lesson);
            return D("lesson", (double)lesson, "mayRun", p.Count == 0, "problems", new List<object>(p.ToArray()));
        }
    }
}
