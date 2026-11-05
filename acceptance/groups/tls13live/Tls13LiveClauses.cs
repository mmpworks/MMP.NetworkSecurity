using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Pki;
using NetSec.Trace;

namespace Acceptance
{
    /// <summary>
    /// A5 and A6: the glass TLS 1.3 engine against OpenSSL 3.5.7 and Go crypto/tls, with X25519 and X25519MLKEM768.
    /// The referee reports the negotiated group, so the group is the referee's word and not ours.
    /// The glass client trusts the training CA. The server certificates come from TrainingCa and OpenSSL verifies them (anchor).
    /// Roles that are cut (roles.json) report NOT RUN ROLE_CUT by name, set by run.ps1 before this program starts.
    /// </summary>
    public static class Tls13LiveClauses
    {
        sealed class Setup
        {
            public string Dir, RootPem, CertPem, KeyPem;
            public TrainingCa Ca;
        }

        static Setup Prepare(Ctx c, string name)
        {
            Setup s = new Setup();
            s.Dir = LivePki.Dir(c, name);
            s.Ca = new TrainingCa(new TrainingKeySource());
            s.RootPem = LivePki.WriteRoot(s.Dir, s.Ca);
            LivePki.Ed25519Server(c, s.Dir, s.Ca, "localhost", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30), out s.CertPem, out s.KeyPem);
            return s;
        }

        static string OsslGroup(KexGroup g) { return g == KexGroup.X25519 ? "X25519" : "X25519MLKEM768"; }
        static string GoGroup(KexGroup g) { return g == KexGroup.X25519 ? "x25519" : "x25519mlkem768"; }

        // ---------------------------------------------------------------- PKI anchor

        [Clause("A5.pki.leaf-verifies-under-openssl", PerBuild = true)]
        public static string LeafVerifiesUnderOpenSsl(Ctx c)
        {
            Setup s = Prepare(c, "a5-pki");
            string output;
            bool ok = LivePki.OpenSslVerifies(c, s.Dir, s.RootPem, s.CertPem, "localhost", out output);
            Check.True(ok, "openssl verify refused a certificate from TrainingCa: " + output.Trim());
            // Control pair: the same certificate must fail for another name, and an expired one must fail.
            string bad;
            Check.True(!LivePki.OpenSslVerifies(c, s.Dir, s.RootPem, s.CertPem, "not-the-name.example", out bad), "openssl accepted the certificate for a name it does not carry");
            string expiredCert, expiredKey;
            LivePki.Ed25519Server(c, LivePki.Dir(c, "a5-pki-expired"), s.Ca, "localhost", DateTime.UtcNow.AddDays(-30), DateTime.UtcNow.AddDays(-1), out expiredCert, out expiredKey);
            Check.True(!LivePki.OpenSslVerifies(c, s.Dir, s.RootPem, expiredCert, "localhost", out bad), "openssl accepted an expired certificate from TrainingCa; the CA must write the dates it was given");
            return "OpenSSL accepts the leaf, refuses a wrong name, refuses an expired leaf";
        }

        // ---------------------------------------------------------------- client role

        static string ClientVsOpenSsl(Ctx c, KexGroup group, string stem, bool compareKeyLog)
        {
            Setup s = Prepare(c, stem);
            string keylog = Path.Combine(s.Dir, "server.keylog");
            using (OpenSslPeer server = OpenSslPeer.StartServer(c, "-tls1_3 -groups " + OsslGroup(group) + " -cert \"" + s.CertPem + "\" -key \"" + s.KeyPem + "\" -keylogfile \"" + keylog + "\""))
            {
                Handshake h = Live.OpenClient(WireProtocol.Tls13, group, SshSuite.Modern, server.Port, "localhost", null, 5001, stem);
                Check.True(h.Opened, "glass TLS 1.3 client against OpenSSL: " + h.Describe());
                string got = Live.Exchange(h.Channel, "hello\n", "olleh", 15000);
                Check.True(got.Contains("olleh"), "echo from OpenSSL -rev was '" + got.Trim() + "'");
                Futs.Done(h.Channel.Close(), 5000, "close");
                Check.True(server.WaitFor(@"Peer Temp Key:", 15000) != null, "OpenSSL did not report a key exchange group. Output: " + server.Output);
                string reported = OpenSslLines.ServerGroup(server.Output);
                Check.Equal("group reported by OpenSSL", OsslGroup(group), reported);
                Check.Equal("protocol reported by OpenSSL", "TLSv1.3", OpenSslLines.Protocol(server.Output));
                if (compareKeyLog) CompareKeyLog(h, keylog);
                return "handshake, echo, group " + reported + " reported by OpenSSL" + (compareKeyLog ? ", key log equal" : "");
            }
        }

        static readonly string[] NssLabels = { "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET" };
        /// <summary>A6: the secrets in our trace equal the referee's key log for the same client random.</summary>
        static void CompareKeyLog(Handshake h, string keylogPath)
        {
            string clientRandom = OpenSslLines.ClientRandomOf(h.Link.Sent);
            Check.True(clientRandom != null, "first bytes we sent are not a TLS ClientHello record");
            Dictionary<string, string> theirs = new Dictionary<string, string>();
            DateTime end = DateTime.UtcNow.AddSeconds(10);
            while (DateTime.UtcNow < end)
            {
                theirs = OpenSslLines.KeyLog(keylogPath, clientRandom);
                if (theirs.Count >= NssLabels.Length) break;
                System.Threading.Thread.Sleep(100);
            }
            Check.True(theirs.Count > 0, "OpenSSL key log has no line for our client random " + clientRandom);
            Dictionary<string, string> ours = new Dictionary<string, string>();
            foreach (TraceSecret ts in h.Sink.AllSecrets) ours[ts.Name] = Hex.Encode(ts.Bytes);
            Tally t = new Tally();
            foreach (string label in NssLabels)
            {
                if (!theirs.ContainsKey(label)) { t.Miss(label, "OpenSSL key log has no such line"); continue; }
                if (!ours.ContainsKey(label)) { t.Miss(label, "our trace has no secret with this name. Secret names in the trace must be the NSS key log labels"); continue; }
                t.Expect(label, ours[label] == theirs[label], "ours " + ours[label].Substring(0, 16) + ".. theirs " + theirs[label].Substring(0, 16) + "..");
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
            Setup s = Prepare(c, stem);
            using (GoPeer go = GoPeer.StartListening(c, "tlspeer", "-mode server -listen 127.0.0.1:0 -groups " + GoGroup(group) + " -cert \"" + s.CertPem + "\" -key \"" + s.KeyPem + "\""))
            {
                Handshake h = Live.OpenClient(WireProtocol.Tls13, group, SshSuite.Modern, go.Port, "localhost", null, 5002, stem);
                Check.True(h.Opened, "glass TLS 1.3 client against Go crypto/tls: " + h.Describe());
                string got = Live.Exchange(h.Channel, "hello\n", "hello", 15000);
                Futs.Done(h.Channel.Close(), 5000, "close");
                string state = go.P.WaitForLine(delegate (string l) { return l.StartsWith("STATE "); }, 15000);
                Check.True(state != null, "tlspeer printed no STATE line. Output: " + go.Output);
                Match m = Regex.Match(state, @"group=(?<g>\S+)");
                Check.True(m.Success, "STATE line has no group=: " + state);
                Check.Equal("group reported by Go", OsslGroup(group), m.Groups["g"].Value);
                Check.True(state.Contains("version=TLS13") || state.Contains("version=0x0304"), "Go reported a version other than TLS 1.3: " + state);
                return "handshake and echo, " + state;
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
            Setup s = Prepare(c, "a5-untrusted");
            // Control: the certificate the training CA signed. It must open.
            using (OpenSslPeer good = OpenSslPeer.StartServer(c, "-tls1_3 -groups X25519 -cert \"" + s.CertPem + "\" -key \"" + s.KeyPem + "\""))
            {
                Handshake ok = Live.OpenClient(WireProtocol.Tls13, KexGroup.X25519, SshSuite.Modern, good.Port, "localhost", null, 5003, "a5-untrusted-control");
                Check.True(ok.Opened, "control run (training CA certificate) failed: " + ok.Describe());
                Futs.Done(ok.Channel.Close(), 5000, "close");
            }
            // Attack: a self-signed certificate. One thing differs: who signed the certificate.
            string rogueCert, rogueKey;
            LivePki.SelfSignedServer(c, LivePki.Dir(c, "a5-untrusted-rogue"), "localhost", out rogueCert, out rogueKey);
            using (OpenSslPeer bad = OpenSslPeer.StartServer(c, "-tls1_3 -groups X25519 -cert \"" + rogueCert + "\" -key \"" + rogueKey + "\""))
            {
                Handshake h = Live.OpenClient(WireProtocol.Tls13, KexGroup.X25519, SshSuite.Modern, bad.Port, "localhost", null, 5004, "a5-untrusted-attack");
                Check.True(!h.Opened, "the client opened a channel to a server with a certificate no trusted CA signed");
                Check.Equal("failed check code", "CHAIN_NO_ANCHOR", h.FailedCode);
                return "control opens, self-signed certificate refused with CHAIN_NO_ANCHOR";
            }
        }

        // ---------------------------------------------------------------- server role (cut role: roles.json tls13.server)

        static string ServerVsReferee(Ctx c, KexGroup group, string stem, bool useGo)
        {
            Setup s = Prepare(c, stem);
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            try
            {
                string argsC = "-connect 127.0.0.1:" + port + " -tls1_3 -groups " + OsslGroup(group) + " -servername localhost -CAfile \"" + s.RootPem + "\" -verify_return_error -verify_hostname localhost -brief";
                Proc peer;
                GoPeer go = null;
                if (useGo)
                {
                    go = GoPeer.Start(c, "tlspeer", "-mode client -connect 127.0.0.1:" + port + " -groups " + GoGroup(group) + " -ca \"" + s.RootPem + "\" -servername localhost -send hello");
                    peer = go.P;
                }
                else
                {
                    peer = OpenSslPeer.StartClient(c, argsC).P;
                    peer.WriteLine("hello");
                }
                using (peer)
                {
                    IAsyncResult ar = listener.BeginAcceptSocket(null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(20000)) throw new FailException("the referee client never connected. Output: " + peer.AllOutput);
                    Socket accepted = listener.EndAcceptSocket(ar);
                    Handshake h = Live.OpenServer(WireProtocol.Tls13, group, SshSuite.Modern, accepted, 5005, stem);
                    Check.True(h.Opened, "glass TLS 1.3 server: " + h.Describe() + ". Referee output: " + peer.AllOutput);
                    string got = Live.Exchange(h.Channel, null, "hello", 15000);
                    Futs.Done(h.Channel.Send(0, Encoding.ASCII.GetBytes("world\n")), 5000, "send");
                    string seen = peer.WaitForLine(delegate (string l) { return l.Contains("world"); }, 15000);
                    Check.True(seen != null, "the referee client never printed 'world'. Output: " + peer.AllOutput);
                    string report = peer.AllOutput;
                    string seenGroup = OpenSslLines.ClientGroup(report);
                    if (seenGroup == null) { Match gm = Regex.Match(report, @"group=(?<g>\S+)"); seenGroup = gm.Success ? gm.Groups["g"].Value : null; }
                    Check.Equal("group reported by the referee client", OsslGroup(group), seenGroup);
                    if (!useGo) Check.True(report.Contains("Verification: OK"), "the referee did not verify our certificate chain. Output: " + report);
                    Futs.Done(h.Channel.Close(), 5000, "close");
                    return "server role: handshake, data both ways, referee reports group " + OsslGroup(group);
                }
            }
            finally { listener.Stop(); }
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
