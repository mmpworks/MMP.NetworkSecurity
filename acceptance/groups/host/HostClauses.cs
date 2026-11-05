using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.WebSockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Acceptance
{
    /// <summary>
    /// A16 (real mode) and D14 (Host origin and token). The Host runs as its own process on 127.0.0.1 and the suite talks to it over
    /// HTTP and WebSocket the way the app does (program-design.md section 5). No product code is linked.
    /// Real mode runs the OS transport (SslStream), shows metadata only and writes no secret bytes. A glass-box session beside it shows
    /// secrets, which proves the scan can see them. OpenSSL, the real peer, writes its own key log. The suite looks for those bytes.
    /// </summary>
    public static class HostClauses
    {
        sealed class HostProc : IDisposable
        {
            public Proc P; public int Port; public string Token = Guid.NewGuid().ToString("N"); public string LocalAppData;
            public string Base { get { return "http://127.0.0.1:" + Port; } }

            public static HostProc Start(Ctx c, string name, IDictionary<string, string> extraEnv)
            {
                string dll = c.Prop("host", "");
                if (dll.Length == 0 || !File.Exists(dll)) throw new NotRunException("PRODUCT_MISSING", "NetSec.Host is not built (host=" + dll + ")");
                HostProc h = new HostProc();
                h.Port = Proc.FreePort();
                h.LocalAppData = Path.Combine(c.WorkDir, name, "localappdata");
                Directory.CreateDirectory(h.LocalAppData);
                Dictionary<string, string> env = new Dictionary<string, string>();
                env["LOCALAPPDATA"] = h.LocalAppData;
                if (extraEnv != null) foreach (KeyValuePair<string, string> kv in extraEnv) env[kv.Key] = kv.Value;
                string args = "--port " + h.Port + " --token " + h.Token;                                  // design section 11, "Processes" item 3
                h.P = dll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                    ? Proc.Start("dotnet", "\"" + dll + "\" " + args, Path.GetDirectoryName(dll), env)
                    : Proc.Start(dll, args, Path.GetDirectoryName(dll), env);
                if (!Net.WaitPort(h.Port, 60000)) { string o = h.P.AllOutput; h.P.Dispose(); throw new FailException("the Host did not open port " + h.Port + " in 60 s. Output: " + o); }
                return h;
            }

            public void Dispose() { P.Dispose(); }
        }

        static HttpResponseMessage Get(HostProc h, string path, string token, string origin)
        {
            using (HttpClient http = new HttpClient())
            {
                HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, h.Base + path);
                if (token != null) req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
                if (origin != null) req.Headers.TryAddWithoutValidation("Origin", origin);
                return http.SendAsync(req).Result;
            }
        }

        [Clause("A16.host.origin-and-token-refused-beside-control")]
        public static string OriginAndToken(Ctx c)
        {
            using (HostProc h = HostProc.Start(c, "a16-origin", null))
            {
                HttpResponseMessage ok = Get(h, "/api/health", h.Token, "http://localhost:5173");
                Check.True(ok.IsSuccessStatusCode, "control request (allowed origin, right token) got HTTP " + (int)ok.StatusCode);
                HttpResponseMessage badToken = Get(h, "/api/health", "not-the-token", "http://localhost:5173");
                string bodyT = badToken.Content.ReadAsStringAsync().Result;
                Check.True(!badToken.IsSuccessStatusCode && bodyT.Contains("HOST_TOKEN_REFUSED"), "a wrong token got HTTP " + (int)badToken.StatusCode + " and body '" + bodyT + "'; expected HOST_TOKEN_REFUSED");
                HttpResponseMessage noToken = Get(h, "/api/health", null, "http://localhost:5173");
                Check.True(!noToken.IsSuccessStatusCode, "a request with no token got HTTP " + (int)noToken.StatusCode);
                HttpResponseMessage badOrigin = Get(h, "/api/health", h.Token, "http://evil.example");
                string bodyO = badOrigin.Content.ReadAsStringAsync().Result;
                Check.True(!badOrigin.IsSuccessStatusCode && bodyO.Contains("HOST_ORIGIN_REFUSED"), "a foreign origin got HTTP " + (int)badOrigin.StatusCode + " and body '" + bodyO + "'; expected HOST_ORIGIN_REFUSED");
                // The WebSocket answers the same way: a bad token never upgrades.
                using (ClientWebSocket ws = new ClientWebSocket())
                {
                    ws.Options.SetRequestHeader("Origin", "http://localhost:5173");
                    bool refused = false;
                    try { ws.ConnectAsync(new Uri("ws://127.0.0.1:" + h.Port + "/ws?token=wrong"), CancellationToken.None).Wait(15000); }
                    catch (Exception) { refused = true; }
                    Check.True(refused || ws.State != WebSocketState.Open, "the WebSocket opened with a wrong token");
                }
                return "control passes; wrong token gives HOST_TOKEN_REFUSED, foreign origin gives HOST_ORIGIN_REFUSED, the WebSocket refuses a wrong token";
            }
        }

        // ---------------------------------------------------------------- sessions over the WebSocket

        sealed class SessionRun
        {
            public string SessionId, TransportKind, SessionFile; public bool TrainingOnly;
            public List<Dictionary<string, object>> Events = new List<Dictionary<string, object>>();
            public List<string> Frames = new List<string>();
            public Dictionary<string, object> Finished, Error;
        }

        static SessionRun RunSession(HostProc h, int lesson, string transport, string extraJson)
        {
            SessionRun run = new SessionRun();
            using (ClientWebSocket ws = new ClientWebSocket())
            {
                ws.Options.SetRequestHeader("Origin", "http://localhost:5173");
                ws.ConnectAsync(new Uri("ws://127.0.0.1:" + h.Port + "/ws?token=" + h.Token), CancellationToken.None).Wait(20000);
                string start = "{\"type\":\"session.start\",\"requestId\":\"r1\",\"lesson\":" + lesson + ",\"seed\":7,\"mode\":\"step\",\"transport\":\"" + transport + "\"" + (extraJson ?? "") + "}";
                ws.SendAsync(new ArraySegment<byte>(Encoding.UTF8.GetBytes(start)), WebSocketMessageType.Text, true, CancellationToken.None).Wait();
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
                        run.SessionId = MiniJson.Str(m, "sessionId"); run.TransportKind = MiniJson.Str(m, "transportKind"); run.SessionFile = MiniJson.Str(m, "sessionFile");
                        // The lesson waits in step mode. session.run lets it go to the end (design section 5).
                        string go = "{\"type\":\"session.run\",\"requestId\":\"r2\",\"sessionId\":\"" + run.SessionId + "\"}";
                        ws.SendAsync(new ArraySegment<byte>(Encoding.UTF8.GetBytes(go)), WebSocketMessageType.Text, true, CancellationToken.None).Wait();
                        object t; run.TrainingOnly = m.TryGetValue("trainingOnly", out t) && t is bool && (bool)t;
                    }
                    else if (kind == "trace") { Dictionary<string, object> ev = MiniJson.Obj(m, "event"); if (ev != null) run.Events.Add(ev); }
                    else if (kind == "session.finished") run.Finished = m;
                    else if (kind == "error") run.Error = m;
                }
                try { ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None).Wait(3000); } catch (Exception) { }
            }
            return run;
        }

        static int SecretCount(SessionRun run)
        {
            int n = 0;
            foreach (Dictionary<string, object> ev in run.Events)
            {
                List<object> s = MiniJson.Arr(ev, "secrets");
                if (s != null) n += s.Count;
            }
            return n;
        }

        [Clause("A16.real-mode.os-transport-writes-no-secret-bytes")]
        public static string RealModeNoSecrets(Ctx c)
        {
            string dir = LivePkiDir(c, "a16-real");
            string key = Path.Combine(dir, "k.pem"), cert = Path.Combine(dir, "c.pem"), refKeylog = Path.Combine(dir, "referee.keylog");
            string openssl = Referees.OpenSsl(c), o;
            if (Proc.Run(openssl, "genpkey -algorithm ed25519 -out \"" + key + "\"", dir, 30000, out o) != 0) throw new FailException(o);
            if (Proc.Run(openssl, "req -new -x509 -key \"" + key + "\" -subj \"/CN=localhost\" -days 2 -addext \"subjectAltName=DNS:localhost\" -out \"" + cert + "\"", dir, 30000, out o) != 0) throw new FailException(o);
            // The real peer is a long-lived OpenSSL server (more than one session). It writes the true secrets to its key log.
            Proc peer = Proc.Start(openssl, "s_server -accept 0 -tls1_3 -rev -cert \"" + cert + "\" -key \"" + key + "\" -keylogfile \"" + refKeylog + "\"");
            using (peer)
            {
                string accept = peer.WaitForLine(delegate (string l) { return l.StartsWith("ACCEPT"); }, 20000);
                if (accept == null) throw new FailException("openssl s_server did not start: " + peer.AllOutput);
                int peerPort = int.Parse(Regex.Match(accept, @"(\d+)\s*$").Groups[1].Value);
                Dictionary<string, string> env = new Dictionary<string, string>();
                env["NETSEC_REAL_PEER"] = "127.0.0.1:" + peerPort;                                      // ASSUMED, see CONTRACT.md
                env["SSL_CERT_FILE"] = cert;
                using (HostProc h = HostProc.Start(c, "a16-real", env))
                {
                    // Control first: a glass-box session shows its secrets, so a scan of the session can see them.
                    SessionRun glass = RunSession(h, 5, "glass", null);
                    Check.True(glass.Error == null, "glass session reported an error: " + (glass.Error == null ? "" : glass.Error.ToString()));
                    Check.True(glass.TrainingOnly && glass.TransportKind == "glass", "glass session did not say trainingOnly with transportKind glass");
                    Check.True(SecretCount(glass) > 0, "the glass-box control session shows no secrets, so the scan cannot prove absence in real mode");
                    HttpResponseMessage glassKeylog = Get(h, "/api/sessions/" + glass.SessionId + "/keylog", h.Token, "http://localhost:5173");
                    Check.True(glassKeylog.IsSuccessStatusCode, "the key log of a glass session got HTTP " + (int)glassKeylog.StatusCode);

                    SessionRun real = RunSession(h, 5, "real", null);
                    Check.True(real.Error == null, "real session reported an error: " + (real.Error == null ? "" : real.Error.ToString()));
                    Check.True(!real.TrainingOnly && real.TransportKind == "os", "real session reported trainingOnly=" + real.TrainingOnly + " transportKind=" + real.TransportKind + "; expected false and os");
                    Check.True(real.Events.Count > 0, "real session sent no trace events");
                    Check.Equal("secrets shown in real mode", 0, SecretCount(real));
                    HttpResponseMessage realKeylog = Get(h, "/api/sessions/" + real.SessionId + "/keylog", h.Token, "http://localhost:5173");
                    Check.True(!realKeylog.IsSuccessStatusCode, "the key log of a real-mode session was served (HTTP " + (int)realKeylog.StatusCode + ")");

                    // Scan: every secret the referee logged, as hex, as lower or upper case, must be absent from frames and session files.
                    Thread.Sleep(1000);
                    List<string> secrets = new List<string>();
                    foreach (string line in OpenSslLines.ReadShared(refKeylog).Split('\n'))
                    {
                        Match m = Regex.Match(line.Trim(), @"^[A-Z0-9_]+ [0-9a-f]{64} (?<s>[0-9a-f]{32,})$");
                        if (m.Success) secrets.Add(m.Groups["s"].Value);
                    }
                    Check.True(secrets.Count >= 5, "the referee key log holds " + secrets.Count + " secrets; the real-mode session did not reach it");
                    StringBuilder everything = new StringBuilder();
                    foreach (string f in real.Frames) everything.Append(f).Append('\n');
                    Check.True(!string.IsNullOrEmpty(real.SessionFile) && File.Exists(real.SessionFile), "session.started.sessionFile is '" + real.SessionFile + "'; the real-mode session wrote no file the scan can read");
                    everything.Append(File.ReadAllText(real.SessionFile)).Append('\n');
                    foreach (string file in Directory.GetFiles(h.LocalAppData, "*", SearchOption.AllDirectories))
                    {
                        if (file.IndexOf(real.SessionId, StringComparison.OrdinalIgnoreCase) >= 0 || file.EndsWith(".ndjson", StringComparison.OrdinalIgnoreCase))
                            everything.Append(File.ReadAllText(file)).Append('\n');
                    }
                    string haystack = everything.ToString().ToLowerInvariant();
                    foreach (string s in secrets)
                        Check.True(!haystack.Contains(s), "a real-mode secret of the referee key log appears in the Host output: " + s.Substring(0, 16) + "..");
                    return "real mode: OS transport, trainingOnly=false, 0 secrets in " + real.Events.Count + " events, key log refused, none of " + secrets.Count + " referee secrets in frames or session files; glass control shows " + SecretCount(glass) + " secrets";
                }
            }
        }

        // ---------------------------------------------------------------- A14, the live half: no dangling binding

        [Clause("A14.tours.no-dangling-binding")]
        public static string NoDanglingBinding(Ctx c)
        {
            string toursDir = Path.Combine(c.RepoRoot, "app", "src", "tours");
            if (!Directory.Exists(toursDir)) throw new NotRunException("PRODUCT_MISSING", "app/src/tours does not exist yet");
            string[] files = Directory.GetFiles(toursDir, "lesson-*.json");
            if (files.Length == 0) throw new NotRunException("PRODUCT_MISSING", "no tour files yet");
            using (HostProc h = HostProc.Start(c, "a14-bindings", null))
            {
                Tally t = new Tally();
                foreach (string file in files)
                {
                    int lesson = int.Parse(Regex.Match(Path.GetFileName(file), @"lesson-(\d+)\.json").Groups[1].Value);
                    object parsed = MiniJson.Parse(File.ReadAllText(file));
                    List<object> steps = parsed as List<object> ?? MiniJson.Arr(MiniJson.AsObject(parsed), "steps");
                    SessionRun run = RunSession(h, lesson, "glass", null);
                    if (run.Error != null) { t.Miss("lesson " + lesson, "the Host answered session.start with an error: " + run.Error.ToString()); continue; }
                    if (run.Events.Count == 0) { t.Miss("lesson " + lesson, "the live session produced no trace events, so no binding can be shown"); continue; }
                    foreach (object so in steps)
                    {
                        Dictionary<string, object> s = MiniJson.AsObject(so);
                        Dictionary<string, object> bind = MiniJson.Obj(s, "bind");
                        if (MiniJson.Str(bind, "kind") != "event") continue;
                        string wantType = MiniJson.Str(bind, "eventType");
                        Dictionary<string, object> match = MiniJson.Obj(bind, "match");
                        bool found = false;
                        foreach (Dictionary<string, object> ev in run.Events)
                        {
                            if (MiniJson.Str(ev, "type") != wantType) continue;
                            bool ok = true;
                            if (match != null)
                                foreach (KeyValuePair<string, object> kv in match)
                                    if (!string.Equals(MiniJson.Str(ev, kv.Key), kv.Value as string, StringComparison.Ordinal)) ok = false;
                            if (ok) { found = true; break; }
                        }
                        t.Expect(MiniJson.Str(s, "id") ?? ("lesson " + lesson), found, "no live event of type '" + wantType + "' fits the step's bind (match " + (match == null ? "none" : "given") + "): the binding dangles");
                    }
                }
                return t.Done();
            }
        }

        static string LivePkiDir(Ctx c, string name)
        {
            string d = Path.Combine(c.WorkDir, name);
            Directory.CreateDirectory(d);
            return d;
        }
    }
}
