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

        sealed class SessionEv { public Dictionary<string, object> Base; public List<RawSecret> Secrets = new List<RawSecret>(); public byte[] OffLeak; }

        sealed class Session { public string Id; public int Lesson, Seed; public string FinishCode; public List<SessionEv> Events = new List<SessionEv>(); public string File; }

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
            if (!showKeys && M("off-hex-in-message") && e.Secrets.Count > 0) r["message"] = "key " + Hex.Encode(e.Secrets[0].Bytes);
            if (!showKeys && M("off-hex-in-plain") && e.OffLeak != null) r["plain"] = (string)e.Base["plain"] + Hex.Encode(e.OffLeak);
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
                        if (lesson < 0 || lesson > 11) { SendText(ws, D("type", "error", "code", "LESSON_NOT_BUILT", "message", "lesson " + lesson + " is not built")); break; }
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
                            if (LessonTypes.TryGetValue(lesson, out needed)) foreach (string id in needed) CourseRead(_types[id], "host/lab-" + lesson);
                        }
                        catch (VaultError ve)
                        {
                            SendText(ws, D("type", "error", "requestId", MiniJson.Str(m, "requestId"), "code", ve.Code, "message", ve.Message));
                            break;
                        }
                        session = new Session { Id = "s" + (++_next), Lesson = lesson, Seed = (int)MiniJson.Num(m, "seed", 20261105) };
                        BuildEvents(session, session.Seed);
                        LeakBuiltIn(session);
                        CarryOnWire(session);
                        session.FinishCode = ClockCode(lesson);
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
                    SendForeignSession(ws);
                    foreach (SessionEv e in session.Events) SendText(ws, D("type", "trace", "event", Render(e, frameShows)));
                    SendText(ws, D("type", "session.finished", "sessionId", session.Id, "events", (double)session.Events.Count, "outcome", session.FinishCode == null ? "completed" : "failed", "code", session.FinishCode));
                    break;
                }
                else if (type == "session.attack")
                {
                    HandleAttack(ws, m);
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
            SessionEv e = new SessionEv { Base = D("type", type, "eventId", "e" + n, "actor", stream, "streamId", s.Id + "/" + stream, "streamSeq", (double)n) };
            e.Secrets.AddRange(secrets);
            s.Events.Add(e);
        }

        /// <summary>
        /// Faithful to design 6.2 limit 2: a lab sends a value in the clear that it stores as a secret (a challenge, a token), so its hex is in the wire and plain fields
        /// whatever Show keys says. Without it the byte scan could never meet such a value and its exemption would be untested.
        /// </summary>
        void CarryOnWire(Session s)
        {
            byte[] clear;
            using (SHA256 sha = SHA256.Create()) clear = Hex.Slice(sha.ComputeHash(Encoding.ASCII.GetBytes("clear:" + s.Lesson)), 0, 16);
            AddWire(s, "client", "wire.sent", "SentInTheClear", clear, clear);
            s.Events[s.Events.Count - 1].Secrets.Add(Raw("clear.value", "client", clear));
            foreach (SessionEv e in s.Events) if (e.Secrets.Count > 0 && e.Secrets[0].Name != "clear.value") { s.Events[s.Events.Count - 1].OffLeak = e.Secrets[0].Bytes; break; }
        }

        /// <summary>The defect "foreign-finish-first": another session of the same Host ends on this connection before the run's own frames, with a trace event and a session.finished of its own.</summary>
        void SendForeignSession(WebSocket ws)
        {
            if (!M("foreign-finish-first")) return;
            SendText(ws, D("type", "trace", "event", D("type", "wire.sent", "eventId", "x1", "actor", "server", "streamId", "s-other/server", "streamSeq", 1.0, "wire", "00", "plain", "00")));
            SendText(ws, D("type", "session.finished", "sessionId", "s-other", "events", 1.0, "outcome", "failed", "code", "FOREIGN_SESSION"));
        }

        /// <summary>The defect "builtin-half": one half of the lab keeps a built-in key in silence, so a wire event of a run on the learner's keys carries the built-in bytes of the types the lesson reads.</summary>
        void LeakBuiltIn(Session s)
        {
            string[] need;
            if (!M("builtin-half") || !LessonTypes.TryGetValue(s.Lesson, out need)) return;
            bool mine = false;
            foreach (string id in need) if (Active(_types[id])) mine = true;
            if (!mine) return;
            StringBuilder leak = new StringBuilder();
            foreach (string id in need) leak.Append(Hex.Encode(BuiltInFull(id)));
            foreach (SessionEv e in s.Events)
                if (e.Base.ContainsKey("wire"))
                {
                    e.Base["wire"] = (string)e.Base["wire"] + leak;
                    return;
                }
            if (s.Events.Count > 0) s.Events[s.Events.Count - 1].Base["wire"] = leak.ToString();      // a lesson with no wire event: the last event gets one
        }

        byte[] BuiltInFull(string typeId)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] all = sha.ComputeHash(Encoding.ASCII.GetBytes("builtin:" + typeId));
                return typeId.StartsWith("dukpt.") || typeId.StartsWith("lab.") ? Hex.Slice(all, 0, 16) : all;
            }
        }

        byte[] BuiltInKey(string typeId)
        {
            using (SHA256 sha = SHA256.Create()) return Hex.Slice(sha.ComputeHash(Encoding.ASCII.GetBytes("builtin:" + typeId)), 0, 16);
        }

        void AddWire(Session s, string stream, string type, string message, byte[] wire, byte[] plain)
        {
            Add(s, stream, type);
            SessionEv e = s.Events[s.Events.Count - 1];
            e.Base["message"] = message; e.Base["wire"] = Hex.Encode(wire); e.Base["plain"] = Hex.Encode(plain);
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
                case 1:
                    {
                        byte[] aes = KeyBytes(_types["lab.aes-key"]);
                        Add(s, "client", "aes.key", Raw("aes.key", "client", aes));
                        byte[] picture = new byte[4096];
                        for (int i = 0; i < picture.Length; i++) picture[i] = (byte)(i % 7);
                        byte[] used = M("mac-wrong-key") ? BuiltInKey("lab.aes-key") : aes;
                        byte[] cipher;
                        using (System.Security.Cryptography.Aes a = System.Security.Cryptography.Aes.Create())
                        {
                            a.Key = used; a.Mode = System.Security.Cryptography.CipherMode.ECB; a.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
                            cipher = a.CreateEncryptor().TransformFinalBlock(picture, 0, picture.Length);
                        }
                        AddWire(s, "client", "wire.sent", "PictureEcb", Hex.Concat(new byte[] { 3, 0, 0, 0 }, cipher), picture);
                        break;
                    }
                case 2:
                    {
                        byte[] seal = KeyBytes(_types["lab.seal-key"]);
                        Add(s, "client", "seal.key", Raw("seal.key", "client", seal));
                        byte[] used = M("mac-wrong-key") ? BuiltInKey("lab.seal-key") : seal;
                        byte[] message = Encoding.UTF8.GetBytes("Pay the pump owner 20 dollars.");
                        byte[] hmac;
                        using (System.Security.Cryptography.HMACSHA256 hm = new System.Security.Cryptography.HMACSHA256(used)) hmac = hm.ComputeHash(message);
                        string msgFile = Path.Combine(Dir, "seal-msg-" + (++_next) + ".bin"), o;
                        File.WriteAllBytes(msgFile, message);
                        Proc.Run(_openssl, "mac -cipher AES-128-CBC -macopt hexkey:" + Hex.Encode(used) + " -in \"" + msgFile + "\" CMAC", Dir, 30000, out o);
                        byte[] cmac = Hex.Decode(o.Trim());
                        byte[] len = new byte[] { 0, (byte)message.Length };
                        AddWire(s, "client", "wire.sent", "HmacSealed", Hex.Concat(new byte[] { 3, 0, 0, 0 }, len, message, hmac), message);
                        AddWire(s, "client", "wire.sent", "CmacSealed", Hex.Concat(new byte[] { 4, 0, 0, 0 }, len, message, cmac), message);
                        break;
                    }
                case 3:
                    byte[] shared = Seeded(seed, 3, 1, 32);
                    Add(s, "client", "kex.shared", Raw("kex.shared", "client", shared));
                    Add(s, "server", "kex.shared", Raw("kex.shared", "server", shared));
                    Add(s, "client", "kex.other", Raw("kex.other", "client", Seeded(seed, 3, 2, 32)));
                    break;
                case 4: case 5: case 7: case 9:
                    for (int i = 1; i <= 4; i++) Add(s, "client", "tls.secret", Raw("tls.secret" + i, "client", Seeded(seed, lesson, i, 32)));
                    if (lesson == 4 || lesson == 5) AddCertificateEvent(s, seed);
                    break;
                case 6:
                    byte[] bdk = M("dukpt-pad-constant") ? Hex.Slice(Seeded(seed, 6, 9, 16), 0, 16) : KeyBytes(_types["dukpt.bdk"]);
                    byte[] ikid = Encoding.ASCII.GetBytes("MMPTRAIN");
                    Add(s, "bank", "dukpt.key.derived", Raw("dukpt.bdk", "bank", bdk));
                    Add(s, "bank", "dukpt.key.derived", Raw("dukpt.initial", "bank", DukptReference.InitialKey(bdk, ikid)));
                    for (uint sale = 1; sale <= 4; sale++)
                        Add(s, "bank", "dukpt.key.derived", Raw("dukpt.pinKey." + sale, "bank", DukptReference.WorkingKey(bdk, ikid, sale, 0x1000, 16)));
                    break;
                case 8: Add(s, "client", "ssh.keys", Raw("ssh.session-key", "client", Seeded(seed, 8, 1, 32))); break;
                case 10:
                    KeyPair signer = M("token-wrong-key") ? _builtinIssuer : ActiveIssuer();
                    long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    string token = Sign(signer, "{\"iss\":\"https://pump.training/issuer\",\"aud\":\"https://pump.training/api\",\"sub\":\"learner\",\"iat\":" + now + ",\"exp\":" + (now + 300) + "}");
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
            if (M("mine-run-differs") && s.Events.Count > 1)
                foreach (string id in (LessonTypes.ContainsKey(lesson) ? LessonTypes[lesson] : new string[0]))
                    if (Active(_types[id])) { s.Events.RemoveAt(s.Events.Count - 1); break; }
        }
    }
}
