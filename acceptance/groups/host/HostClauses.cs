using System;
using System.Collections.Generic;
using System.IO;
using System.Net.WebSockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Acceptance
{
    /// <summary>
    /// A16 (OS transport) and D14 (Host origin and token). The Host runs as its own process on 127.0.0.1 and the suite talks to it over
    /// HTTP and WebSocket the way the app does (program-design.md section 5). No product code is linked.
    /// The OS transport runs SslStream, shows metadata only and writes no secret bytes. A glass-box session beside it shows secrets (with their
    /// hex), which proves the scan can see them. OpenSSL, the outside peer, writes its own key log. The suite looks for those bytes.
    /// SslStream cannot talk to an Ed25519 certificate (modes-design.md section 7.1), so the peer holds an RSA key.
    /// </summary>
    public static class HostClauses
    {
        [Clause("A16.host.origin-and-token-refused-beside-control")]
        public static string OriginAndToken(Ctx c)
        {
            using (HostProc h = HostProc.Start(c, "a16-origin", null))
            {
                Reply ok = HostHttp.Raw(h, "GET", "/api/health", null, h.Token, HostHttp.AllowedOrigin);
                Check.True(ok.Ok, "control request (allowed origin, right token) got " + ok);
                Reply badToken = HostHttp.Raw(h, "GET", "/api/health", null, "not-the-token", HostHttp.AllowedOrigin);
                Check.True(!badToken.Ok && (badToken.Body ?? "").Contains("HOST_TOKEN_REFUSED"), "a wrong token got " + badToken + "; expected HOST_TOKEN_REFUSED");
                Reply noToken = HostHttp.Raw(h, "GET", "/api/health", null, null, HostHttp.AllowedOrigin);
                Check.True(!noToken.Ok, "a request with no token got " + noToken);
                Reply badOrigin = HostHttp.Raw(h, "GET", "/api/health", null, h.Token, "http://evil.example");
                Check.True(!badOrigin.Ok && (badOrigin.Body ?? "").Contains("HOST_ORIGIN_REFUSED"), "a foreign origin got " + badOrigin + "; expected HOST_ORIGIN_REFUSED");
                // The WebSocket answers the same way: a bad token never upgrades.
                using (ClientWebSocket ws = new ClientWebSocket())
                {
                    ws.Options.SetRequestHeader("Origin", HostHttp.AllowedOrigin);
                    bool refused = false;
                    try { ws.ConnectAsync(new Uri("ws://127.0.0.1:" + h.Port + "/ws?token=wrong"), CancellationToken.None).Wait(15000); }
                    catch (Exception) { refused = true; }
                    Check.True(refused || ws.State != WebSocketState.Open, "the WebSocket opened with a wrong token");
                }
                return "control passes; wrong token gives HOST_TOKEN_REFUSED, foreign origin gives HOST_ORIGIN_REFUSED, the WebSocket refuses a wrong token";
            }
        }

        /// <summary>
        /// A slice that is not built yet answers session.start with error code LESSON_NOT_BUILT. That is NOT RUN LESSON_NOT_BUILT, never a FAIL.
        /// A Host that has no OS transport yet answers OS_TRANSPORT_NOT_BUILT (before the rename: REAL_MODE_NOT_BUILT). That is NOT RUN PRODUCT_MISSING.
        /// Any other error stays a FAIL. A secret leak is found by the scan, not here.
        /// </summary>
        static void RequireBuilt(SessionRun run, int lesson)
        {
            string code = run.ErrorCode;
            if (code == "LESSON_NOT_BUILT")
                throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson " + lesson + " as not built yet");
            if (code == "OS_TRANSPORT_NOT_BUILT" || code == "REAL_MODE_NOT_BUILT")
                throw new NotRunException("PRODUCT_MISSING", "the Host has no OS transport yet (" + code + ")");
        }

        [Clause("A16.os-transport.writes-no-secret-bytes")]
        public static string OsTransportNoSecrets(Ctx c)
        {
            string dir = Path.Combine(c.WorkDir, "a16-os");
            Directory.CreateDirectory(dir);
            string key = Path.Combine(dir, "k.pem"), cert = Path.Combine(dir, "c.pem"), refKeylog = Path.Combine(dir, "referee.keylog");
            string openssl = Referees.OpenSsl(c), o;
            // RSA, because Windows SslStream fails the handshake against an Ed25519 server certificate.
            if (Proc.Run(openssl, "genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out \"" + key + "\"", dir, 60000, out o) != 0) throw new FailException(o);
            if (Proc.Run(openssl, "req -new -x509 -key \"" + key + "\" -subj \"/CN=localhost\" -days 2 -addext \"subjectAltName=DNS:localhost\" -out \"" + cert + "\"", dir, 30000, out o) != 0) throw new FailException(o);
            // The outside peer is a long-lived OpenSSL server (more than one session). It writes the true secrets to its key log.
            Proc peer = Proc.Start(openssl, "s_server -accept 0 -tls1_3 -rev -cert \"" + cert + "\" -key \"" + key + "\" -keylogfile \"" + refKeylog + "\"");
            using (peer)
            {
                string accept = peer.WaitForLine(delegate (string l) { return l.StartsWith("ACCEPT"); }, 20000);
                if (accept == null) throw new FailException("openssl s_server did not start: " + peer.AllOutput);
                int peerPort = int.Parse(Regex.Match(accept, @"(\d+)\s*$").Groups[1].Value);
                Dictionary<string, string> env = new Dictionary<string, string>();
                env["NETSEC_OS_PEER"] = "127.0.0.1:" + peerPort;                                       // ASSUMED, see CONTRACT.md
                env["SSL_CERT_FILE"] = cert;                                                           // the custom trust store the product loads (CONTRACT.md)
                using (HostProc h = HostProc.Start(c, "a16-os", env))
                {
                    HostChecks.RequireShowKeysOn(h);
                    // Control first: a glass-box session shows its secrets WITH their hex, so a scan of the session can see them.
                    SessionRun glass = HostSession.Run(h, 5, "glass", null);
                    RequireBuilt(glass, 5);
                    Check.True(glass.Error == null, "glass session reported an error: " + (glass.Frames.Count == 0 ? "" : glass.Frames[glass.Frames.Count - 1]));
                    Check.True(glass.TrainingOnly && glass.TransportKind == "glass", "glass session did not say trainingOnly with transportKind glass");
                    int gEntries, gHex;
                    HostSession.CountSecrets(glass, out gEntries, out gHex);
                    Check.True(gHex > 0, "the glass-box control session shows " + gEntries + " secrets entries and none carries hex, so the scan cannot prove absence on the OS transport");
                    Reply glassKeylog = HostHttp.Get(h, "/api/sessions/" + glass.SessionId + "/keylog");
                    Check.True(glassKeylog.Ok, "the key log of a glass session got " + glassKeylog);

                    SessionRun os = HostSession.Run(h, 5, "os", null);
                    RequireBuilt(os, 5);
                    // A Host that has no OS transport runs the request as a glass session. That is a transport not built, and never a pass.
                    if (os.Error == null && os.TransportKind == "glass") throw new NotRunException("PRODUCT_MISSING", "the Host ran transport os as a glass session: the OS transport is not built");
                    Check.True(os.Error == null, "OS transport session reported an error: " + (os.Frames.Count == 0 ? "" : os.Frames[os.Frames.Count - 1]));
                    Check.True(!os.TrainingOnly && os.TransportKind == "os", "OS transport session reported trainingOnly=" + os.TrainingOnly + " transportKind=" + os.TransportKind + "; expected false and os");
                    Check.True(os.Events.Count > 0, "OS transport session sent no trace events");
                    int oEntries, oHex;
                    HostSession.CountSecrets(os, out oEntries, out oHex);
                    Check.Equal("secrets shown on the OS transport", 0, oEntries);
                    Reply osKeylog = HostHttp.Get(h, "/api/sessions/" + os.SessionId + "/keylog");
                    Check.True(!osKeylog.Ok, "the key log of an OS transport session was served (" + osKeylog + ")");

                    // Scan: every secret the outside peer logged, as hex, must be absent from frames and session files.
                    Thread.Sleep(1000);
                    List<string> secrets = new List<string>();
                    foreach (string line in OpenSslLines.ReadShared(refKeylog).Split('\n'))
                    {
                        Match m = Regex.Match(line.Trim(), @"^[A-Z0-9_]+ [0-9a-f]{64} (?<s>[0-9a-f]{32,})$");
                        if (m.Success) secrets.Add(m.Groups["s"].Value);
                    }
                    Check.True(secrets.Count >= 5, "the outside peer's key log holds " + secrets.Count + " secrets; the OS transport session did not reach it");
                    StringBuilder everything = new StringBuilder();
                    foreach (string f in os.Frames) everything.Append(f).Append('\n');
                    Check.True(!string.IsNullOrEmpty(os.SessionFile) && File.Exists(os.SessionFile), "session.started.sessionFile is '" + os.SessionFile + "'; the OS transport session wrote no file the scan can read");
                    everything.Append(File.ReadAllText(os.SessionFile)).Append('\n');
                    foreach (string file in Directory.GetFiles(h.LocalAppData, "*", SearchOption.AllDirectories))
                    {
                        if (file.IndexOf(os.SessionId, StringComparison.OrdinalIgnoreCase) >= 0 || file.EndsWith(".ndjson", StringComparison.OrdinalIgnoreCase))
                            everything.Append(File.ReadAllText(file)).Append('\n');
                    }
                    string haystack = everything.ToString().ToLowerInvariant();
                    foreach (string s in secrets)
                        Check.True(!haystack.Contains(s), "a secret of the outside peer's key log appears in the Host output: " + s.Substring(0, 16) + "..");
                    return "OS transport: trainingOnly=false, 0 secrets in " + os.Events.Count + " events, key log refused, none of " + secrets.Count + " peer secrets in frames or session files; glass control shows " + gHex + " secrets with hex";
                }
            }
        }

        // ---------------------------------------------------------------- A14, the live half: no dangling binding

        [Clause("A14.tours.no-dangling-binding")]
        public static string NoDanglingBinding(Ctx c)
        {
            string toursDir = Path.Combine(c.RepoRoot, "app", "src", "tours");
            if (!Directory.Exists(toursDir)) throw new NotRunException("PRODUCT_MISSING", "app/src/tours does not exist yet");
            List<string> built = new List<string>();
            foreach (string f in Directory.GetFiles(toursDir, "lesson-*.json"))
                if (int.Parse(Regex.Match(Path.GetFileName(f), @"lesson-(\d+)\.json").Groups[1].Value) >= 1) built.Add(f);      // lesson 0 is the toy lesson, outside the suite
            string[] files = built.ToArray();
            if (files.Length == 0) throw new NotRunException("PRODUCT_MISSING", "no tour files yet");
            using (HostProc h = HostProc.Start(c, "a14-bindings", null))
            {
                HostChecks.RequireShowKeysOn(h);
                Tally t = new Tally();
                int notBuilt = 0;
                foreach (string file in files)
                {
                    int lesson = int.Parse(Regex.Match(Path.GetFileName(file), @"lesson-(\d+)\.json").Groups[1].Value);
                    if (lesson == 20) continue;                       // the vault exercise has its own clause (A17.vault.exercise-walk)
                    object parsed = MiniJson.Parse(File.ReadAllText(file));
                    List<object> steps = parsed as List<object> ?? MiniJson.Arr(MiniJson.AsObject(parsed), "steps");
                    SessionRun run = HostSession.Run(h, lesson, "glass", null);
                    if (run.ErrorCode == "LESSON_NOT_BUILT") { notBuilt++; continue; }
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
                if (notBuilt == files.Length) throw new NotRunException("LESSON_NOT_BUILT", "the Host reports every lesson with a tour file as not built yet");
                return t.Done() + (notBuilt > 0 ? "; " + notBuilt + " lessons not built yet were skipped" : "");
            }
        }
    }
}
