using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Net.WebSockets;

namespace Acceptance
{
    // Certificates, attack rows and the lab clock of the fake Host. See FakeHost.cs. Every judgement of a certificate goes through OpenSSL.
    public sealed partial class FakeHost
    {
        static readonly string[] LeafCerts = new string[] { "tls13.server", "tls13.client", "tls11.server" };

        static string Q(string p) { return "\"" + p + "\""; }

        sealed class CertFacts { public string SignatureAlgorithm; public DateTime NotBefore, NotAfter; }

        CertFacts ReadCert(string pem)
        {
            string o;
            if (Proc.Run(_openssl, "x509 -in " + Q(pem) + " -noout -text -startdate -enddate", Dir, 30000, out o) != 0) return null;
            CertFacts f = new CertFacts();
            foreach (string line in o.Split('\n'))
            {
                string t = line.Trim();
                if (f.SignatureAlgorithm == null && t.StartsWith("Signature Algorithm:")) f.SignatureAlgorithm = t.Substring("Signature Algorithm:".Length).Trim();
                if (t.StartsWith("notBefore=")) f.NotBefore = ParseDate(t.Substring("notBefore=".Length));
                if (t.StartsWith("notAfter=")) f.NotAfter = ParseDate(t.Substring("notAfter=".Length));
            }
            return f;
        }

        static DateTime ParseDate(string openssl)
        {
            string s = System.Text.RegularExpressions.Regex.Replace(openssl.Replace("GMT", "").Trim(), @"\s+", " ");
            return DateTime.SpecifyKind(DateTime.ParseExact(s, "MMM d HH:mm:ss yyyy", CultureInfo.InvariantCulture), DateTimeKind.Utc);
        }

        /// <summary>What the flow says about one imported certificate file: an unsupported signature on a root, or dates that are not valid now.</summary>
        void CertChecks(FlowRun r, string key, string path)
        {
            if (key.EndsWith(".key") || key.EndsWith(".chain") || key == "tls.trust") return;
            bool isRoot = key == "pki.root-ca";
            if (!isRoot && Array.IndexOf(LeafCerts, key) < 0) return;
            CertFacts f = ReadCert(path);
            if (f == null) { r.Errors.Add(D("code", "KEY_FILE_FORMAT", "severity", "error", "typeId", key, "message", "The file is not a certificate.")); r.FileBlocked = true; return; }
            if (isRoot && !(f.SignatureAlgorithm ?? "").ToUpperInvariant().Contains("ED25519"))
            {
                string code = M("alg-reports-cert-signature") ? "CERT_SIGNATURE" : "CERT_SIGNATURE_ALG_UNSUPPORTED";
                r.Errors.Add(D("code", code, "severity", "error", "typeId", key, "message", "This root is signed with " + f.SignatureAlgorithm + ". The glass engines verify Ed25519 only. Use the OS transport for this root."));
                r.FileBlocked = true;
                return;
            }
            DateTime now = DateTime.UtcNow;
            if (f.NotAfter < now)
            {
                r.Errors.Add(D("code", M("expired-not-named") ? "CHECK_FAILED" : "CERT_EXPIRED", "severity", "error", "typeId", key, "message", "The certificate ran out on " + f.NotAfter.ToString("yyyy-MM-dd") + "."));
                r.FileBlocked = true;
            }
            else if (f.NotBefore > now)
            {
                r.Errors.Add(D("code", "CERT_NOT_YET_VALID", "severity", "error", "typeId", key, "message", "The certificate starts on " + f.NotBefore.ToString("yyyy-MM-dd") + "."));
                r.FileBlocked = true;
            }
        }

        void ApplyCert(FlowRun r, TypeState t, string id, bool imported)
        {
            if (id == "pki.root-ca") t.CanIssue = !imported || r.Paths.ContainsKey("pki.root-ca.key");
            if (!imported || Array.IndexOf(LeafCerts, id) < 0) { t.HasDates = false; return; }
            CertFacts f = ReadCert(r.Paths[id]);
            if (f != null) { t.HasDates = true; t.NotBefore = f.NotBefore; t.NotAfter = f.NotAfter; }
        }

        /// <summary>The flow's check of a leaf against the root the learner gave. It runs openssl verify, so it can fail.</summary>
        bool VerifyChain(string rootPem, string leafPem)
        {
            string o;
            // A check that verifies the root against itself cannot fail, so it proves nothing about the leaf.
            string subject = M("check-self-verifies") ? rootPem : leafPem;
            return Proc.Run(_openssl, "verify -CAfile " + Q(rootPem) + " " + Q(subject), Dir, 30000, out o) == 0;
        }

        /// <summary>The code a lab ends with when an imported certificate is outside its dates on the clock the lab uses.</summary>
        string ClockCode(int lesson)
        {
            string[] need;
            if (!LessonTypes.TryGetValue(lesson, out need)) return null;
            foreach (string id in need)
            {
                TypeState t = _types[id];
                if (!Active(t) || !t.HasDates) continue;
                // An imported certificate is judged on the wall clock. The mutation judges it on the fixed lab clock, as the labs do today.
                DateTime clock = M("clock-fixed") ? (lesson == 10 ? new DateTime(2026, 11, 5, 0, 0, 0, DateTimeKind.Utc) : new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc)) : DateTime.UtcNow;
                if (clock > t.NotAfter) return "CERT_EXPIRED";
                if (clock < t.NotBefore) return "CERT_NOT_YET_VALID";
            }
            return null;
        }

        // ------------------------------------------------------------ attack rows

        bool CanIssueNow { get { return M("attack-always-available") || _types["pki.root-ca"].Mode != "Mine" || _types["pki.root-ca"].CanIssue; } }

        Dictionary<string, object> CertAttack(string id, string code)
        {
            bool can = CanIssueNow && !M("attack-row-unavailable");
            Dictionary<string, object> d = D("attackId", id, "kind", "cert", "expectCode", code, "expectCheck", "certificate chain", "available", can);
            if (!can) d["whyNot"] = "ATTACK_NEEDS_CA_KEY";
            return d;
        }

        List<object> LessonsJson()
        {
            // As the real Host since Richard's contract change: the list holds lessons 0 to 11. Lesson 0's row matches GET /api/lessons/0.
            List<object> rows = new List<object> { D("lesson", 0.0, "title", "Lesson 0", "built", true, "attacks", new List<object>()) };
            for (int n = 1; n <= 11; n++)
            {
                List<object> attacks = new List<object>();
                if (n == 4)
                {
                    attacks.Add(CertAttack("L4-expired-cert", "CERT_EXPIRED"));
                    attacks.Add(CertAttack("L4-wrong-name", "CERT_NAME"));
                    attacks.Add(D("attackId", "L4-flip-cert-byte", "kind", "flip-byte", "expectCode", "CERT_SIGNATURE", "expectCheck", "certificate chain", "field", "certSerial", "available", true));
                }
                if (n == 10) attacks.Add(CertAttack("L10-wrong-client-name", "CERT_NAME"));
                rows.Add(D("lesson", (double)n, "title", "Lesson " + n, "built", true, "attacks", attacks));
            }
            return rows;
        }

        // ------------------------------------------------------------ the certificate event of lessons 4 and 5, and its fork

        void AddCertificateEvent(Session s, int seed)
        {
            byte[] wire = Seeded(seed, s.Lesson, 77, 64);
            AddWire(s, "server", "wire.sent", "Certificate", wire, new byte[0]);
            SessionEv e = s.Events[s.Events.Count - 1];
            e.Base["fields"] = new List<object>
            {
                D("name", "certHeader", "offset", 0.0, "length", 28.0, "kind", "header", "visibleToWire", true, "gloss", "The start of the certificate."),
                D("name", "certSerial", "offset", 28.0, "length", 8.0, "kind", "id", "visibleToWire", true, "gloss", "The serial number."),
                D("name", "certSignature", "offset", 36.0, "length", -1.0, "kind", "signature", "visibleToWire", true, "gloss", "The signature of the issuer."),
            };
        }

        void FlipCertByte(Session fork)
        {
            foreach (SessionEv e in fork.Events)
                if ((e.Base.ContainsKey("message") ? e.Base["message"] as string : null) == "Certificate")
                {
                    byte[] wire = Hex.Decode((string)e.Base["wire"]);
                    int pos = M("attack-wrong-field") ? 50 : 30;               // 30 lies in certSerial, 50 in certSignature
                    wire[pos] ^= 0x01;
                    e.Base["wire"] = Hex.Encode(wire);
                    return;
                }
        }

        /// <summary>session.attack: a fork of a session with one attack row applied. Sends session.started, session.forked, the events, and session.finished with the row's code.</summary>
        bool HandleAttack(WebSocket ws, Dictionary<string, object> m)
        {
            lock (_gate)
            {
                Session parent;
                string pid = MiniJson.Str(m, "sessionId") ?? "", aid = MiniJson.Str(m, "attackId");
                if (!_sessions.TryGetValue(pid, out parent)) { SendText(ws, D("type", "error", "requestId", MiniJson.Str(m, "requestId"), "code", "SESSION_NOT_FOUND", "message", "No session to fork.")); return false; }
                if (aid == "L1-use-ecb")
                {
                    Session ecb = new Session { Id = "s" + (++_next), Lesson = parent.Lesson, Seed = parent.Seed, EcbFork = true };
                    BuildEvents(ecb, parent.Seed);
                    byte[] ecbKey = RunKey(ecb), ecbText = Encoding.ASCII.GetBytes("Pump four is ok.");
                    AddWire(ecb, "client", "wire.sent", "TextEcb", Hex.Decode(new RefAes(ecbKey).Encrypt(ecbText).Output), ecbText);
                    _sessions[ecb.Id] = ecb;
                    ecb.File = Path.Combine(Dir, "session-" + ecb.Id + ".ndjson");
                    File.WriteAllText(ecb.File, "\n");
                    SendText(ws, D("type", "session.started", "sessionId", ecb.Id, "transportKind", "glass", "trainingOnly", true, "sessionFile", ecb.File, "showKeys", _showKeys));
                    SendText(ws, D("type", "session.forked", "sessionId", ecb.Id, "parentId", parent.Id, "attackId", aid));
                    foreach (SessionEv e in ecb.Events) SendText(ws, D("type", "trace", "event", Render(e, _showKeys)));
                    SendText(ws, D("type", "session.finished", "sessionId", ecb.Id, "outcome", "accepted", "code", "LAB_OK"));
                    return true;
                }
                string certCode = aid == "L4-expired-cert" ? "CERT_EXPIRED" : aid == "L4-wrong-name" || aid == "L10-wrong-client-name" ? "CERT_NAME" : null;
                if (certCode != null)
                {
                    // A certificate row: the fork ends caught by the chain check with the row's code, as the real Host does.
                    Session cf = new Session { Id = "s" + (++_next), Lesson = parent.Lesson, Seed = parent.Seed };
                    BuildEvents(cf, parent.Seed);
                    _sessions[cf.Id] = cf;
                    cf.File = Path.Combine(Dir, "session-" + cf.Id + ".ndjson");
                    File.WriteAllText(cf.File, "\n");
                    SendText(ws, D("type", "session.started", "sessionId", cf.Id, "transportKind", "glass", "trainingOnly", true, "sessionFile", cf.File, "showKeys", _showKeys));
                    SendText(ws, D("type", "session.forked", "sessionId", cf.Id, "parentId", parent.Id, "attackId", aid));
                    foreach (SessionEv e in cf.Events) SendText(ws, D("type", "trace", "event", Render(e, _showKeys)));
                    SendText(ws, D("type", "session.finished", "sessionId", cf.Id, "outcome", "caught", "code", M("attack-finish-other-code") ? "CERT_UNKNOWN_CRITICAL" : certCode, "check", M("attack-finish-no-check") ? null : "certificate chain"));
                    return true;
                }
                if (aid != "L4-flip-cert-byte") { SendText(ws, D("type", "error", "requestId", MiniJson.Str(m, "requestId"), "code", "ATTACK_NOT_FOUND", "message", "No such attack, or that byte cannot be flipped.")); return false; }
                Session fork = new Session { Id = "s" + (++_next), Lesson = parent.Lesson, Seed = parent.Seed };
                BuildEvents(fork, parent.Seed);
                FlipCertByte(fork);
                fork.FinishCode = "CERT_SIGNATURE";
                _sessions[fork.Id] = fork;
                fork.File = Path.Combine(Dir, "session-" + fork.Id + ".ndjson");
                File.WriteAllText(fork.File, "\n");
                SendText(ws, D("type", "session.started", "sessionId", fork.Id, "transportKind", "glass", "trainingOnly", true, "sessionFile", fork.File, "showKeys", _showKeys));
                SendText(ws, D("type", "session.forked", "sessionId", fork.Id, "parentId", parent.Id, "attackId", aid));
                SendForeignSession(ws);
                foreach (SessionEv e in fork.Events) SendText(ws, D("type", "trace", "event", Render(e, _showKeys)));
                SendText(ws, D("type", "session.finished", "sessionId", fork.Id, "outcome", "caught", "code", fork.FinishCode, "check", "certificate chain"));
                return true;
            }
        }
    }
}
