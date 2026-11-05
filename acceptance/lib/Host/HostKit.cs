using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.WebSockets;
using System.Text;
using System.Threading;

namespace Acceptance
{
    /// <summary>
    /// A NetSec.Host process, started the way the app starts it (design section 11, "Processes" item 3), or a Host that another program runs
    /// (the self-test's fake). The suite talks to it over HTTP and WebSocket and links no product code. Net10 only.
    /// </summary>
    public sealed class HostProc : IDisposable
    {
        public Proc P;
        public int Port;
        public string Token = Guid.NewGuid().ToString("N");
        public string LocalAppData, SecurityDir;
        public string Base { get { return "http://127.0.0.1:" + Port; } }

        static void Crumb(string what) { if (Environment.GetEnvironmentVariable("ACC_TRACE") == "1") File.AppendAllText(Path.Combine(Path.GetTempPath(), "acc-crumbs.log"), "[host " + DateTime.Now.ToString("HH:mm:ss") + "] " + what + "\n"); }

        /// <summary>
        /// Starts NetSec.Host on a free port. NETSEC_SECURITY_DIR points at a folder of its own, so a run never reads or writes the learner's
        /// .security/ folder and starts with Show keys ON (design section 6.6). The pinned referees go in by environment.
        /// With the property a17.attach=port,token,securityDir the clauses talk to a Host that is already running (the self-test's fake).
        /// </summary>
        public static HostProc Start(Ctx c, string name, IDictionary<string, string> extraEnv)
        {
            Crumb("HostProc.Start " + name);
            string attach = c.Prop("a17.attach", "");
            if (attach.Length > 0)
            {
                string[] a = attach.Split(',');
                HostProc f = new HostProc();
                f.Port = int.Parse(a[0]); f.Token = a[1]; f.SecurityDir = a.Length > 2 ? a[2] : null;
                return f;
            }
            string dll = c.Prop("host", "");
            if (dll.Length == 0 || !File.Exists(dll)) throw new NotRunException("PRODUCT_MISSING", "NetSec.Host is not built (host=" + dll + ")");
            HostProc h = new HostProc();
            h.Port = Proc.FreePort();
            string root = Path.Combine(c.WorkDir, name);
            h.LocalAppData = Path.Combine(root, "localappdata");
            h.SecurityDir = Path.Combine(root, "security");
            Directory.CreateDirectory(h.LocalAppData);
            Directory.CreateDirectory(h.SecurityDir);
            Dictionary<string, string> env = new Dictionary<string, string>();
            env["LOCALAPPDATA"] = h.LocalAppData;
            env["NETSEC_SECURITY_DIR"] = h.SecurityDir;
            // Design section 11 gives the flags --port and --token. Design section 5 gives the environment variables NETSEC_PORT and NETSEC_TOKEN.
            // The two sections differ, so the suite passes both and a Host that reads either one starts.
            env["NETSEC_PORT"] = h.Port.ToString(); env["NETSEC_TOKEN"] = h.Token;
            string openssl = c.Prop("openssl", @"C:\Program Files\Git\mingw64\bin\openssl.exe");
            if (File.Exists(openssl)) env["NETSEC_OPENSSL"] = openssl;
            string ssh = c.Prop("ssh", @"C:\Windows\System32\OpenSSH\ssh.exe");
            if (File.Exists(ssh)) env["NETSEC_SSH"] = ssh;
            if (extraEnv != null) foreach (KeyValuePair<string, string> kv in extraEnv) env[kv.Key] = kv.Value;
            string args = "--port " + h.Port + " --token " + h.Token;
            h.P = dll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                ? Proc.Start("dotnet", "\"" + dll + "\" " + args, Path.GetDirectoryName(dll), env)
                : Proc.Start(dll, args, Path.GetDirectoryName(dll), env);
            if (!Net.WaitPort(h.Port, 60000)) { string o = h.P.AllOutput; h.P.Dispose(); throw new FailException("the Host did not open port " + h.Port + " in 60 s. Output: " + o); }
            return h;
        }

        public void Dispose() { if (P != null) P.Dispose(); }
    }

    /// <summary>One HTTP answer from the Host, with the JSON body parsed when there is one.</summary>
    public sealed class Reply
    {
        public int Status;
        public string Body;
        public Dictionary<string, object> Json;       // set when the body is a JSON object
        public List<object> Array;                    // set when the body is a JSON array, as GET /api/sessions/{id}/events answers
        public bool Ok { get { return Status >= 200 && Status < 300; } }

        /// <summary>The named code of an error answer: "code" at the top of the body, or inside "error".</summary>
        public string Code
        {
            get
            {
                string c = MiniJson.Str(Json, "code");
                if (c != null) return c;
                Dictionary<string, object> e = MiniJson.Obj(Json, "error");
                return MiniJson.Str(e, "code");
            }
        }

        public override string ToString() { return "HTTP " + Status + " " + (Body ?? "").Substring(0, Math.Min(300, (Body ?? "").Length)); }
    }

    public static class HostHttp
    {
        public const string AllowedOrigin = "http://localhost:5173";

        public static Reply Raw(HostProc h, string method, string path, string body, string token, string origin)
        {
            using (HttpClient http = new HttpClient())
            {
                http.Timeout = TimeSpan.FromSeconds(60);
                HttpRequestMessage req = new HttpRequestMessage(new HttpMethod(method), h.Base + path);
                if (token != null) req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
                if (origin != null) req.Headers.TryAddWithoutValidation("Origin", origin);
                if (body != null) req.Content = new StringContent(body, Encoding.UTF8, "application/json");
                HttpResponseMessage r = http.SendAsync(req).Result;
                Reply reply = new Reply();
                reply.Status = (int)r.StatusCode;
                reply.Body = r.Content.ReadAsStringAsync().Result;
                try { object parsed = MiniJson.Parse(reply.Body); reply.Json = parsed as Dictionary<string, object>; reply.Array = parsed as List<object>; }
                catch (FormatException) { reply.Json = null; reply.Array = null; }
                return reply;
            }
        }

        public static Reply Get(HostProc h, string path) { return Raw(h, "GET", path, null, h.Token, AllowedOrigin); }
        public static Reply Put(HostProc h, string path, string json) { return Raw(h, "PUT", path, json, h.Token, AllowedOrigin); }
        public static Reply Post(HostProc h, string path, string json) { return Raw(h, "POST", path, json, h.Token, AllowedOrigin); }
    }

    /// <summary>One lesson session over the WebSocket, run to its end (or to an error frame).</summary>
    public sealed class SessionRun
    {
        public string SessionId, TransportKind, SessionFile;
        public bool TrainingOnly, ShowKeys;
        public bool ShowKeysReported;
        public List<object> Security;
        public List<Dictionary<string, object>> Events = new List<Dictionary<string, object>>();
        public List<string> Frames = new List<string>();
        public Dictionary<string, object> Finished, Error, Started;
        public string ErrorCode { get { return MiniJson.Str(Error, "code"); } }
    }

    public static class HostSession
    {
        static void Send(ClientWebSocket ws, string text)
        {
            ws.SendAsync(new ArraySegment<byte>(Encoding.UTF8.GetBytes(text)), WebSocketMessageType.Text, true, CancellationToken.None).Wait(15000);
        }

        /// <summary>
        /// session.start in step mode, then session.run, then read frames until session.finished or an error frame (90 s at most).
        /// extraJson is appended inside the start object, for example ,"attackId":"x".
        /// </summary>
        public static SessionRun Run(HostProc h, int lesson, string transport, string extraJson)
        {
            SessionRun run = new SessionRun();
            using (ClientWebSocket ws = new ClientWebSocket())
            {
                ws.Options.SetRequestHeader("Origin", HostHttp.AllowedOrigin);
                ws.ConnectAsync(new Uri("ws://127.0.0.1:" + h.Port + "/ws?token=" + h.Token), CancellationToken.None).Wait(20000);
                if (ws.State != WebSocketState.Open) throw new FailException("the WebSocket to the Host did not open (state " + ws.State + ")");
                Send(ws, "{\"type\":\"session.start\",\"requestId\":\"r1\",\"lesson\":" + lesson + ",\"seed\":20261105,\"mode\":\"step\",\"transport\":\"" + transport + "\"" + (extraJson ?? "") + "}");
                DateTime end = DateTime.UtcNow.AddSeconds(90);
                byte[] buf = new byte[1 << 16];
                while (DateTime.UtcNow < end && run.Finished == null && run.Error == null)
                {
                    MemoryStream ms = new MemoryStream();
                    WebSocketReceiveResult r;
                    CancellationTokenSource cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                    try
                    {
                        do { r = ws.ReceiveAsync(new ArraySegment<byte>(buf), cts.Token).Result; ms.Write(buf, 0, r.Count); } while (!r.EndOfMessage);
                    }
                    catch (Exception) { break; }
                    if (r.MessageType == WebSocketMessageType.Close) break;
                    string text = Encoding.UTF8.GetString(ms.ToArray());
                    run.Frames.Add(text);
                    Dictionary<string, object> m = MiniJson.AsObject(MiniJson.Parse(text));
                    string kind = MiniJson.Str(m, "type") ?? MiniJson.Str(m, "kind");
                    if (kind == "session.started")
                    {
                        run.Started = m;
                        run.SessionId = MiniJson.Str(m, "sessionId"); run.TransportKind = MiniJson.Str(m, "transportKind"); run.SessionFile = MiniJson.Str(m, "sessionFile");
                        run.TrainingOnly = MiniJson.Bool(m, "trainingOnly", false);
                        run.Security = MiniJson.Arr(m, "security");
                        run.ShowKeysReported = m.ContainsKey("showKeys");
                        run.ShowKeys = MiniJson.Bool(m, "showKeys", true);
                        // The lesson waits in step mode. session.run lets it go to the end (design section 5).
                        Send(ws, "{\"type\":\"session.run\",\"requestId\":\"r2\",\"sessionId\":\"" + run.SessionId + "\"}");
                    }
                    else if (kind == "trace") { Dictionary<string, object> ev = MiniJson.Obj(m, "event"); if (ev != null) run.Events.Add(ev); }
                    else if (kind == "session.finished") run.Finished = m;
                    else if (kind == "error") run.Error = m;
                }
                try { ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None).Wait(3000); } catch (Exception) { }
            }
            return run;
        }

        /// <summary>The number of secrets[] entries in the events, and how many carry a hex value.</summary>
        public static void CountSecrets(SessionRun run, out int entries, out int withHex)
        {
            entries = 0; withHex = 0;
            foreach (Dictionary<string, object> ev in run.Events)
            {
                List<object> s = MiniJson.Arr(ev, "secrets");
                if (s == null) continue;
                foreach (object o in s)
                {
                    entries++;
                    Dictionary<string, object> d = MiniJson.AsObject(o);
                    if (!string.IsNullOrEmpty(MiniJson.Str(d, "hex"))) withHex++;
                }
            }
        }
    }
}

namespace Acceptance
{
    public static class HostChecks
    {
        /// <summary>
        /// The suite runs with Show keys ON (modes-design.md section 6.6). A Host that reports showKeys false in /api/health fails the run early
        /// with the named reason SUITE_NEEDS_SHOW_KEYS_ON. A Host that does not report it yet counts as ON, as the design says.
        /// </summary>
        public static void RequireShowKeysOn(HostProc h)
        {
            Reply r = HostHttp.Get(h, "/api/health");
            if (!r.Ok) throw new FailException("GET /api/health got " + r);
            if (r.Json != null && r.Json.ContainsKey("showKeys") && !MiniJson.Bool(r.Json, "showKeys", true))
                throw new FailException("SUITE_NEEDS_SHOW_KEYS_ON", "/api/health reports showKeys false. The suite runs with Show keys ON; only the A17.show-keys clauses turn it off, each in its own Host.");
        }
    }
}
