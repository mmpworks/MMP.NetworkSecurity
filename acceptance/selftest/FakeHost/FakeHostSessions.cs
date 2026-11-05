using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Acceptance
{
    // Lesson sessions of the fake Host: events keep the raw secret bytes, and every exit renders them by the Show keys toggle at that moment.
    public sealed partial class FakeHost
    {
        sealed class RawSecret { public string Name, Holder; public byte[] Bytes; public bool NonExportable; public string PublicFingerprint; }

        sealed class SessionEv { public Dictionary<string, object> Base; public List<RawSecret> Secrets = new List<RawSecret>(); }

        sealed class Session { public string Id; public int Lesson; public List<SessionEv> Events = new List<SessionEv>(); public string File; }

        Dictionary<string, object> RenderSecret(RawSecret s, bool showKeys)
        {
            Dictionary<string, object> d = D("name", s.Name, "holder", s.Holder);
            if (s.NonExportable && !M("nonexportable-leaks"))
            {
                d["fingerprint"] = s.PublicFingerprint; d["hidden"] = "non-exportable";
                return d;
            }
            d["fingerprint"] = Fingerprint(s.Bytes);
            if (showKeys) { d["hex"] = Hex.Encode(s.Bytes); return d; }
            d["length"] = (double)s.Bytes.Length;
            if (!M("hidden-missing")) d["hidden"] = "toggle";
            return d;
        }

        Dictionary<string, object> Render(SessionEv e, bool showKeys)
        {
            Dictionary<string, object> r = new Dictionary<string, object>(e.Base);
            List<object> secrets = new List<object>();
            foreach (RawSecret s in e.Secrets) secrets.Add(RenderSecret(s, showKeys));
            r["secrets"] = secrets;
            return r;
        }

        List<object> RenderAll(Session s, bool showKeys)
        {
            List<object> r = new List<object>();
            foreach (SessionEv e in s.Events) r.Add(Render(e, showKeys));
            return r;
        }

        static void SendText(WebSocket ws, object o)
        {
            byte[] b = Encoding.UTF8.GetBytes(MiniJson.Write(o));
            ws.SendAsync(new ArraySegment<byte>(b), WebSocketMessageType.Text, true, CancellationToken.None).Wait(15000);
        }

        void HandleSocket(HttpListenerContext ctx)
        {
            WebSocket ws = ctx.AcceptWebSocketAsync(null).Result.WebSocket;
            byte[] buf = new byte[1 << 16];
            Session session = null;
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
                        int lesson = (int)MiniJson.Num(m, "lesson", -1);
                        if (lesson < 0 || (lesson > 11 && lesson != 20)) { SendText(ws, D("type", "error", "code", "LESSON_NOT_BUILT", "message", "lesson " + lesson + " is not built")); break; }
                        List<Dictionary<string, object>> problems = Problems(lesson);
                        if (problems.Count > 0)
                        {
                            Dictionary<string, object> first = problems[0];
                            SendText(ws, D("type", "error", "requestId", MiniJson.Str(m, "requestId"), "code", MiniJson.Str(first, "code"), "message", MiniJson.Str(first, "detail")));
                            break;
                        }
                        string[] needed;
                        try
                        {
                            if (LessonTypes.TryGetValue(lesson, out needed)) foreach (string id in needed) CourseRead(_types[id], "lesson-" + lesson);
                        }
                        catch (VaultError ve)
                        {
                            SendText(ws, D("type", "error", "requestId", MiniJson.Str(m, "requestId"), "code", ve.Code, "message", ve.Message));
                            break;
                        }
                        session = new Session { Id = "s" + (++_next), Lesson = lesson };
                        if (lesson == 20) BuildExercise(session); else BuildEvents(session, (int)MiniJson.Num(m, "seed", 20261105));
                        _sessions[session.Id] = session;
                        session.File = Path.Combine(Dir, "session-" + session.Id + ".ndjson");
                        bool fileShows = M("off-keeps-hex-in-file") ? true : _showKeys;
                        List<string> lines = new List<string>();
                        foreach (SessionEv e in session.Events) lines.Add(MiniJson.Write(Render(e, fileShows)));
                        File.WriteAllText(session.File, string.Join("\n", lines.ToArray()) + "\n");
                        List<object> sec = new List<object>();
                        foreach (string id in A17.AllTypes) sec.Add(TypeJson(_types[id]));
                        string transport = MiniJson.Str(m, "transport") ?? "glass";
                        SendText(ws, D("type", "session.started", "sessionId", session.Id, "transportKind", transport, "trainingOnly", transport == "glass",
                            "sessionFile", session.File, "showKeys", _showKeys, "security", sec));
                    }
                }
                else if (type == "session.run" && session != null)
                {
                    bool frameShows;
                    lock (_gate) { frameShows = M("off-hex-in-frames") ? true : _showKeys; }
                    foreach (SessionEv e in session.Events) SendText(ws, D("type", "trace", "event", Render(e, frameShows)));
                    SendText(ws, D("type", "session.finished", "sessionId", session.Id, "events", (double)session.Events.Count));
                    break;
                }
            }
            // Close the way a Host does: send Close, then wait for the client's Close. Dropping the socket early lets a reset throw away the last frames.
            try
            {
                ws.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None).Wait(5000);
                CancellationTokenSource wait = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                while (ws.State == WebSocketState.CloseSent)
                    if (ws.ReceiveAsync(new ArraySegment<byte>(buf), wait.Token).Result.MessageType == WebSocketMessageType.Close) break;
            }
            catch (Exception) { }
            try { ws.Dispose(); } catch (Exception) { }
        }

        static byte[] Seeded(int seed, int lesson, int index, int length)
        {
            byte[] b = new byte[length];
            new Random(seed ^ (lesson * 1000 + index)).NextBytes(b);
            return b;
        }

        static string PublicFingerprintOf(byte[] pub)
        {
            using (SHA256 sha = SHA256.Create()) return "SHA256:" + Convert.ToBase64String(sha.ComputeHash(pub)).TrimEnd('=');
        }

        RawSecret Raw(string name, string holder, byte[] bytes) { return new RawSecret { Name = name, Holder = holder, Bytes = bytes }; }

        void Add(Session s, string stream, string type, params RawSecret[] secrets)
        {
            int n = s.Events.Count + 1;
            SessionEv e = new SessionEv { Base = D("type", type, "eventId", "e" + n, "streamId", s.Id + "/" + stream, "streamSeq", (double)n) };
            e.Secrets.AddRange(secrets);
            s.Events.Add(e);
        }

        void BuildEvents(Session s, int seed)
        {
            int lesson = s.Lesson;
            string[] need;
            if (LessonTypes.TryGetValue(lesson, out need) && !M("no-key-in-use"))
            {
                foreach (string id in need)
                {
                    TypeState t = _types[id];
                    byte[] key = KeyBytes(t);
                    RawSecret k = Raw("key." + id, "host", key);
                    k.NonExportable = Active(t) && t.KeepHidden;
                    k.PublicFingerprint = PublicFingerprintOf(key);
                    Add(s, "keys", "key.in-use", k);
                    SessionEv last = s.Events[s.Events.Count - 1];
                    last.Base["typeId"] = id; last.Base["version"] = (double)t.Version; last.Base["provider"] = t.Provider;
                }
            }
            switch (lesson)
            {
                case 1: Add(s, "client", "aes.encrypt", Raw("aes.key", "client", KeyBytes(_types["lab.aes-key"]))); break;
                case 2: Add(s, "client", "seal.tag", Raw("seal.key", "client", KeyBytes(_types["lab.seal-key"]))); break;
                case 3:
                    byte[] shared = Seeded(seed, 3, 1, 32);
                    Add(s, "client", "kex.shared", Raw("kex.shared", "client", shared));
                    Add(s, "server", "kex.shared", Raw("kex.shared", "server", shared));
                    Add(s, "client", "kex.other", Raw("kex.other", "client", Seeded(seed, 3, 2, 32)));
                    break;
                case 4: case 5: case 7: case 9:
                    for (int i = 1; i <= 4; i++) Add(s, "client", "tls.secret", Raw("tls.secret" + i, "client", Seeded(seed, lesson, i, 32)));
                    break;
                case 6:
                    Add(s, "pad", "dukpt.sale", Raw("dukpt.sale-key", "pad", Seeded(seed, 6, 1, 16)));
                    break;
                case 8: Add(s, "client", "ssh.keys", Raw("ssh.session-key", "client", Seeded(seed, 8, 1, 32))); break;
                case 10:
                    KeyPair signer = M("token-wrong-key") ? _builtinIssuer : ActiveIssuer();
                    long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    string token = Sign(signer, "{\"iss\":\"lab\",\"sub\":\"learner\",\"iat\":" + now + ",\"exp\":" + (now + 300) + "}");
                    KeyPair shown = M("pub-in-trace-wrong") ? _builtinIssuer : ActiveIssuer();
                    byte[] tokenBytes = Encoding.ASCII.GetBytes(token), pub = Hex.Decode(shown.PublicHex);
                    Add(s, "issuer", "auth.token-issued", Raw("auth.token", "issuer", tokenBytes), Raw("auth.issuer-public", "issuer", pub),
                        Raw("auth.device-key", "client", KeyBytes(_types["device.enrolment"])));
                    // The token travels in the clear on purpose, and the issuer public key is public: both show on the wire with Show keys OFF.
                    SessionEv wire = s.Events[s.Events.Count - 1];
                    wire.Base["wire"] = Hex.Encode(tokenBytes); wire.Base["plain"] = Hex.Encode(pub);
                    break;
                case 11: Add(s, "target", "timing.lab.started", Raw("lab-secret", "target", Seeded(seed, 11, 1, 4))); break;
                default: Add(s, "lab", "lesson.step"); break;
            }
        }
    }
}
