using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using NetSec.Io;

namespace Acceptance
{
    /// <summary>
    /// A5 and A6: the glass TLS 1.3 engine, reached through Probe (design section 11), against OpenSSL 3.5.7 and Go crypto/tls, with X25519 and X25519MLKEM768.
    /// The referee reports the negotiated group, so the group is the referee's word and not ours.
    /// The certificates and keys come from TrainingPki.Export, and OpenSSL verifies them (anchor).
    /// The server role needs Probe.Listen. A cut role (roles.json tls13.server) reports NOT RUN ROLE_CUT by name, set by run.ps1 before this program starts.
    /// </summary>
    public static class Tls13LiveClauses
    {
        static string OsslGroup(KexGroup g) { return g == KexGroup.X25519 ? "X25519" : "X25519MLKEM768"; }
        static string GoGroup(KexGroup g) { return g == KexGroup.X25519 ? "x25519" : "x25519mlkem768"; }

        static ProbeRequest Client(int port, KexGroup group)
        {
            ProbeRequest r = ProbeKit.Request(WireProtocol.Tls13, port, "localhost");
            r.Group = group;
            r.Send = Encoding.ASCII.GetBytes("hello\n");
            return r;
        }

        // ---------------------------------------------------------------- PKI anchor

        [Clause("A5.pki.leaf-verifies-under-openssl", PerBuild = true)]
        public static string LeafVerifiesUnderOpenSsl(Ctx c)
        {
            PkiDir p = PkiDir.Export(c, "a5-pki");
            string output;
            Check.True(LivePki.OpenSslVerifies(c, p.Dir, p.Root, p.Cert, "localhost", out output), "openssl verify refused the TLS leaf from TrainingPki.Export: " + output.Trim());
            // Control pair: the same certificate fails for another name, and a certificate the CA never signed fails.
            string bad;
            Check.True(!LivePki.OpenSslVerifies(c, p.Dir, p.Root, p.Cert, "not-the-name.example", out bad), "openssl accepted the certificate for a name it does not carry");
            string rogueCert, rogueKey;
            LivePki.SelfSignedServer(c, LivePki.Dir(c, "a5-pki-rogue"), "localhost", out rogueCert, out rogueKey);
            Check.True(!LivePki.OpenSslVerifies(c, p.Dir, p.Root, rogueCert, "localhost", out bad), "openssl accepted a self-signed certificate against the training root");
            return "OpenSSL accepts the leaf, refuses a wrong name, refuses a certificate the training CA never signed";
        }

        // ---------------------------------------------------------------- client role

        static string ClientVsOpenSsl(Ctx c, KexGroup group, string stem, bool compareKeyLog)
        {
            PkiDir p = PkiDir.Export(c, stem);
            string keylog = Path.Combine(p.Dir, "server.keylog");
            using (OpenSslPeer server = OpenSslPeer.StartServer(c, "-tls1_3 -groups " + OsslGroup(group) + " -cert \"" + p.Cert + "\" -key \"" + p.Key + "\" -keylogfile \"" + keylog + "\""))
            {
                ProbeResult r = ProbeKit.Connect(Client(server.Port, group), "glass TLS 1.3 client against OpenSSL");
                Check.True(r.Completed, "glass TLS 1.3 client against OpenSSL stopped: " + r.CheckName + " [" + r.Code + "]");
                string got = Encoding.ASCII.GetString(r.Received ?? new byte[0]);
                Check.True(got.Contains("olleh"), "echo from OpenSSL -rev was '" + got.Trim() + "'");
                Check.True(server.WaitFor(@"Peer Temp Key:", 15000) != null, "OpenSSL did not report a key exchange group. Output: " + server.Output);
                string reported = OpenSslLines.ServerGroup(server.Output);
                Check.Equal("group reported by OpenSSL", OsslGroup(group), reported);
                Check.Equal("protocol reported by OpenSSL", "TLSv1.3", OpenSslLines.Protocol(server.Output));
                if (compareKeyLog) CompareKeyLog(r, keylog);
                return "handshake, echo, group " + reported + " reported by OpenSSL" + (compareKeyLog ? ", key log equal on the 4 shared labels" : "");
            }
        }

        // Go writes these 4 lines. OpenSSL writes the same 4 plus EXPORTER_SECRET and a comment line, so the comparison runs on the 4 shared labels
        // (acceptance/referees/README.md, "Known limits").
        static readonly string[] SharedLabels = { "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0" };

        /// <summary>A6: the key log lines the product returns equal the referee's key log for the same client random.</summary>
        static void CompareKeyLog(ProbeResult r, string keylogPath)
        {
            Check.True(r.KeyLog != null && r.KeyLog.Length > 0, "ProbeResult.KeyLog is empty");
            Dictionary<string, string> ours = new Dictionary<string, string>();
            string clientRandom = null;
            foreach (string line in r.KeyLog)
            {
                Match m = Regex.Match(line.Trim(), @"^(?<label>[A-Z0-9_]+) (?<random>[0-9a-fA-F]{64}) (?<secret>[0-9a-fA-F]+)$");
                if (!m.Success) throw new FailException("a KeyLog line is not NSS format 'LABEL clientRandomHex secretHex': " + line);
                if (clientRandom == null) clientRandom = m.Groups["random"].Value.ToLowerInvariant();
                else if (clientRandom != m.Groups["random"].Value.ToLowerInvariant()) throw new FailException("KeyLog lines carry two different client randoms");
                ours[m.Groups["label"].Value] = m.Groups["secret"].Value.ToLowerInvariant();
            }
            Dictionary<string, string> theirs = new Dictionary<string, string>();
            DateTime end = DateTime.UtcNow.AddSeconds(10);
            while (DateTime.UtcNow < end)
            {
                theirs = OpenSslLines.KeyLog(keylogPath, clientRandom);
                if (theirs.Count >= SharedLabels.Length) break;
                System.Threading.Thread.Sleep(100);
            }
            Check.True(theirs.Count > 0, "OpenSSL key log has no line for the client random " + clientRandom);
            Tally t = new Tally();
            foreach (string label in SharedLabels)
            {
                if (!theirs.ContainsKey(label)) { t.Miss(label, "OpenSSL key log has no such line"); continue; }
                if (!ours.ContainsKey(label)) { t.Miss(label, "ProbeResult.KeyLog has no such line"); continue; }
                t.Expect(label, ours[label] == theirs[label].ToLowerInvariant(), "ours " + ours[label].Substring(0, 16) + ".. theirs " + theirs[label].Substring(0, 16) + "..");
            }
            t.Done();
        }

        [Clause("A5.client.openssl.x25519", PerBuild = true)]
        public static string ClientOpenSslX25519(Ctx c) { return ClientVsOpenSsl(c, KexGroup.X25519, "a5-client-openssl-x25519", false); }

        [Clause("A5.client.openssl.x25519mlkem768", PerBuild = true)]
        public static string ClientOpenSslHybrid(Ctx c) { return ClientVsOpenSsl(c, KexGroup.X25519MlKem768, "a5-client-openssl-hybrid", false); }

        [Clause("A6.keylog.openssl.x25519", PerBuild = true)]
        public static string KeyLogX25519(Ctx c) { return ClientVsOpenSsl(c, KexGroup.X25519, "a6-keylog-x25519", true); }

        [Clause("A6.keylog.openssl.x25519mlkem768", PerBuild = true)]
        public static string KeyLogHybrid(Ctx c) { return ClientVsOpenSsl(c, KexGroup.X25519MlKem768, "a6-keylog-hybrid", true); }

        static string ClientVsGo(Ctx c, KexGroup group, string stem)
        {
            PkiDir p = PkiDir.Export(c, stem);
            using (GoPeer go = GoPeer.StartListening(c, "tlspeer", "-mode server -listen 127.0.0.1:0 -naccept 1 -groups " + GoGroup(group) + " -cert \"" + p.Cert + "\" -key \"" + p.Key + "\""))
            {
                ProbeResult r = ProbeKit.Connect(Client(go.Port, group), "glass TLS 1.3 client against Go crypto/tls");
                Check.True(r.Completed, "glass TLS 1.3 client against Go crypto/tls stopped: " + r.CheckName + " [" + r.Code + "]");
                Check.True(Encoding.ASCII.GetString(r.Received ?? new byte[0]).Contains("hello"), "Go echo was '" + Encoding.ASCII.GetString(r.Received ?? new byte[0]).Trim() + "'");
                Dictionary<string, object> hs = go.WaitEvent("handshake", 15000);
                Check.True(hs != null, "tlspeer printed no handshake event. Output: " + go.Output);
                Check.Equal("group reported by Go", OsslGroup(group), MiniJson.Str(hs, "curveID"));
                Check.Equal("version reported by Go", "TLS 1.3", MiniJson.Str(hs, "version"));
                return "handshake and echo, Go reports " + MiniJson.Str(hs, "version") + " " + MiniJson.Str(hs, "curveID");
            }
        }

        [Clause("A5.client.go.x25519", PerBuild = true)]
        public static string ClientGoX25519(Ctx c) { return ClientVsGo(c, KexGroup.X25519, "a5-client-go-x25519"); }

        [Clause("A5.client.go.x25519mlkem768", PerBuild = true)]
        public static string ClientGoHybrid(Ctx c) { return ClientVsGo(c, KexGroup.X25519MlKem768, "a5-client-go-hybrid"); }

        // ---------------------------------------------------------------- client: untrusted chain, beside a passing control

        [Clause("A5.client.openssl.untrusted-chain-refused", PerBuild = true)]
        public static string UntrustedChain(Ctx c)
        {
            PkiDir p = PkiDir.Export(c, "a5-untrusted");
            // Control: the certificate the training CA signed. It must open.
            using (OpenSslPeer good = OpenSslPeer.StartServer(c, "-tls1_3 -groups X25519 -cert \"" + p.Cert + "\" -key \"" + p.Key + "\""))
            {
                ProbeResult ok = ProbeKit.Connect(Client(good.Port, KexGroup.X25519), "control (training CA certificate)");
                Check.True(ok.Completed, "control run (training CA certificate) stopped: " + ok.CheckName + " [" + ok.Code + "]");
            }
            // Attack: a self-signed certificate. One thing differs: who signed the certificate.
            string rogueCert, rogueKey;
            LivePki.SelfSignedServer(c, LivePki.Dir(c, "a5-untrusted-rogue"), "localhost", out rogueCert, out rogueKey);
            using (OpenSslPeer bad = OpenSslPeer.StartServer(c, "-tls1_3 -groups X25519 -cert \"" + rogueCert + "\" -key \"" + rogueKey + "\""))
            {
                ProbeResult r = ProbeKit.Connect(Client(bad.Port, KexGroup.X25519), "attack (self-signed certificate)");
                Check.True(!r.Completed, "the client completed a handshake with a certificate no trusted CA signed");
                Check.Equal("failed check code", "CHAIN_NO_ANCHOR", r.Code);
                return "control opens, self-signed certificate refused with CHAIN_NO_ANCHOR";
            }
        }

        // ---------------------------------------------------------------- server role (cut role: roles.json tls13.server)

        static string ServerVsReferee(Ctx c, KexGroup group, string stem, bool useGo)
        {
            PkiDir p = PkiDir.Export(c, stem);
            ProbeRequest req = ProbeKit.Request(WireProtocol.Tls13, 0, "localhost");
            req.Group = group;
            req.Send = Encoding.ASCII.GetBytes("world\n");
            ProbeListener listener = Probe.Listen(req);
            Check.True(listener != null && listener.Port > 0, "Probe.Listen returned no port");
            Proc peer;
            if (useGo)
                peer = GoPeer.Start(c, "tlspeer", "-mode client -connect 127.0.0.1:" + listener.Port + " -groups " + GoGroup(group) + " -ca \"" + p.Root + "\" -server-name localhost").P;
            else
            {
                peer = OpenSslPeer.StartClient(c, "-connect 127.0.0.1:" + listener.Port + " -tls1_3 -groups " + OsslGroup(group) + " -servername localhost -CAfile \"" + p.Root + "\" -verify_return_error -verify_hostname localhost -brief").P;
            }
            using (peer)
            {
                peer.WriteLine("hello");
                ProbeResult r = Futs.Get(listener.Result, 60000, "glass TLS 1.3 server");
                Check.True(r.Completed, "glass TLS 1.3 server stopped: " + r.CheckName + " [" + r.Code + "]. Referee output: " + peer.AllOutput);
                Check.True(Encoding.ASCII.GetString(r.Received ?? new byte[0]).Contains("hello"), "the server received '" + Encoding.ASCII.GetString(r.Received ?? new byte[0]).Trim() + "' and not hello");
                string seen = peer.WaitForLine(delegate (string l) { return l.Contains("world"); }, 15000);
                Check.True(seen != null, "the referee client never printed 'world'. Output: " + peer.AllOutput);
                string report = peer.AllOutput;
                string seenGroup;
                if (useGo)
                {
                    Match gm = Regex.Match(report, "\"curveID\":\"(?<g>[^\"]+)\"");
                    seenGroup = gm.Success ? gm.Groups["g"].Value : null;
                }
                else
                {
                    seenGroup = OpenSslLines.ClientGroup(report);
                    Check.True(report.Contains("Verification: OK"), "the referee did not verify our certificate chain. Output: " + report);
                }
                Check.Equal("group reported by the referee client", OsslGroup(group), seenGroup);
                return "server role: handshake, data both ways, referee reports group " + OsslGroup(group);
            }
        }

        [Clause("A5.server.openssl.x25519", PerBuild = true)]
        public static string ServerOpenSslX25519(Ctx c) { return ServerVsReferee(c, KexGroup.X25519, "a5-server-openssl-x25519", false); }

        [Clause("A5.server.openssl.x25519mlkem768", PerBuild = true)]
        public static string ServerOpenSslHybrid(Ctx c) { return ServerVsReferee(c, KexGroup.X25519MlKem768, "a5-server-openssl-hybrid", false); }

        [Clause("A5.server.go.x25519", PerBuild = true)]
        public static string ServerGoX25519(Ctx c) { return ServerVsReferee(c, KexGroup.X25519, "a5-server-go-x25519", true); }

        [Clause("A5.server.go.x25519mlkem768", PerBuild = true)]
        public static string ServerGoHybrid(Ctx c) { return ServerVsReferee(c, KexGroup.X25519MlKem768, "a5-server-go-hybrid", true); }
    }
}
