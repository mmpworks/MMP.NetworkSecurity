using System;
using System.IO;
using System.Text;
using NetSec.Io;

namespace Acceptance
{
    /// <summary>
    /// A7: the glass TLS 1.1 client, reached through Probe (design section 11), against OpenSSL 3.5.7 for a named RSA key transport suite
    /// and a named ECDHE CBC suite (Suite is the IANA name); alert 70 from a modern server beside a passing control (the same client against the legacy server);
    /// and the downgrade sentinel seen by a TLS 1.3 client that offers only TLS 1.1 (OfferOnlyTls11), beside a passing control.
    /// The lab forces the weak suite on purpose (accuracy rule 3). A default run would pick the best case.
    /// The sentinel bytes come from the tap referee, which sits between the client and the server, so the wire evidence is outside the product.
    /// </summary>
    public static class Tls11Clauses
    {
        static string LegacyServerArgs(PkiDir p, string openSslCipher)
        {
            return "-tls1_1 -cipher " + openSslCipher + ":@SECLEVEL=0 -cert \"" + p.RsaCert + "\" -key \"" + p.RsaKey + "\"";
        }

        static ProbeRequest Tls11Client(int port, string ianaSuite)
        {
            ProbeRequest r = ProbeKit.Request(WireProtocol.Tls11, port, "localhost");
            r.Suite = ianaSuite;
            r.Send = Encoding.ASCII.GetBytes("hello\n");
            return r;
        }

        static string Tls11Against(Ctx c, string ianaSuite, string openSslCipher, string stem)
        {
            PkiDir p = PkiDir.Export(c, stem);
            using (OpenSslPeer server = OpenSslPeer.StartServer(c, LegacyServerArgs(p, openSslCipher)))
            {
                ProbeResult r = ProbeKit.Connect(Tls11Client(server.Port, ianaSuite), "glass TLS 1.1 client against OpenSSL (" + openSslCipher + ")");
                Check.True(r.Completed, "glass TLS 1.1 client against OpenSSL (" + openSslCipher + ") stopped: " + r.CheckName + " [" + r.Code + "]");
                string got = Encoding.ASCII.GetString(r.Received ?? new byte[0]);
                Check.True(got.Contains("olleh"), "echo from OpenSSL -rev was '" + got.Trim() + "'");
                Check.True(server.WaitFor(@"Ciphersuite:", 15000) != null, "OpenSSL printed no Ciphersuite line. Output: " + server.Output);
                Check.Equal("protocol reported by OpenSSL", "TLSv1.1", OpenSslLines.Protocol(server.Output));
                Check.Equal("suite reported by OpenSSL", openSslCipher, OpenSslLines.Ciphersuite(server.Output));
                Check.Equal("suite reported by the product", ianaSuite, r.Suite);
                return "TLS 1.1 handshake and echo, OpenSSL reports TLSv1.1 and " + openSslCipher;
            }
        }

        [Clause("A7.tls11.openssl.rsa-transport", PerBuild = true)]
        public static string RsaTransport(Ctx c) { return Tls11Against(c, "TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA", "a7-rsa-transport"); }

        [Clause("A7.tls11.openssl.ecdhe-cbc", PerBuild = true)]
        public static string EcdheCbc(Ctx c) { return Tls11Against(c, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE-RSA-AES128-SHA", "a7-ecdhe-cbc"); }

        // ---------------------------------------------------------------- alert 70

        [Clause("A7.alert70.modern-server-beside-legacy-control", PerBuild = true)]
        public static string Alert70(Ctx c)
        {
            PkiDir p = PkiDir.Export(c, "a7-alert70");
            // Control: the same client, same suite, against a server that speaks TLS 1.1. It must open.
            using (OpenSslPeer legacy = OpenSslPeer.StartServer(c, LegacyServerArgs(p, "AES128-SHA")))
            {
                ProbeResult ok = ProbeKit.Connect(Tls11Client(legacy.Port, "TLS_RSA_WITH_AES_128_CBC_SHA"), "control against the TLS 1.1 server");
                Check.True(ok.Completed, "control run against the TLS 1.1 server stopped: " + ok.CheckName + " [" + ok.Code + "]");
            }
            // Attack: one thing differs, the server only speaks TLS 1.3. OpenSSL answers a TLS 1.1 hello with alert 70 (protocol_version).
            using (OpenSslPeer modern = OpenSslPeer.StartServer(c, "-tls1_3 -cert \"" + p.Cert + "\" -key \"" + p.Key + "\""))
            {
                ProbeResult r = ProbeKit.Connect(Tls11Client(modern.Port, "TLS_RSA_WITH_AES_128_CBC_SHA"), "attack (TLS 1.3-only server)");
                Check.True(!r.Completed, "the TLS 1.1 client completed a handshake with a TLS 1.3-only server");
                Check.Equal("alert received from the server", "70", r.AlertReceived.ToString());
                return "control opens against TLS 1.1; the TLS 1.3-only server answers with alert 70 (protocol_version)";
            }
        }

        // ---------------------------------------------------------------- downgrade sentinel

        static ProbeRequest Tls13Client(int port, bool offerOnlyTls11)
        {
            ProbeRequest r = ProbeKit.Request(WireProtocol.Tls13, port, "localhost");
            r.Group = KexGroup.X25519;
            r.OfferOnlyTls11 = offerOnlyTls11;
            return r;
        }

        [Clause("A7.downgrade-sentinel.tls13-client-beside-control", PerBuild = true)]
        public static string DowngradeSentinel(Ctx c)
        {
            PkiDir p = PkiDir.Export(c, "a7-sentinel");
            // The server speaks TLS 1.3 and TLS 1.1. It holds an Ed25519 certificate for 1.3 and an RSA certificate for 1.1.
            string args = "-cipher ALL:@SECLEVEL=0 -min_protocol TLSv1.1 -cert \"" + p.Cert + "\" -key \"" + p.Key + "\" -dcert \"" + p.RsaCert + "\" -dkey \"" + p.RsaKey + "\"";
            // Control: the client offers TLS 1.3. It gets TLS 1.3.
            using (OpenSslPeer control = OpenSslPeer.StartServer(c, args))
            {
                ProbeResult ok = ProbeKit.Connect(Tls13Client(control.Port, false), "control (no downgrade)");
                Check.True(ok.Completed, "control run (client offers TLS 1.3) stopped: " + ok.CheckName + " [" + ok.Code + "]");
            }
            // Attack: the client offers TLS 1.1 only. The server takes the downgrade and writes DOWNGRD in its random. A TLS 1.3 client must see it.
            using (OpenSslPeer attacked = OpenSslPeer.StartServer(c, args))
            {
                string hop = Path.Combine(p.Dir, "hop.hex");
                using (GoPeer tap = GoPeer.StartListening(c, "tap", "-listen 127.0.0.1:0 -to 127.0.0.1:" + attacked.Port + " -log \"" + hop + "\" -naccept 1"))
                {
                    ProbeResult r = ProbeKit.Connect(Tls13Client(tap.Port, true), "attack (client offers only TLS 1.1)");
                    Check.True(!r.Completed, "the TLS 1.3 client accepted a downgrade to an older protocol");
                    Check.Equal("failed check code", "TLS13_DOWNGRADE_SENTINEL", r.Code);
                    // Independent evidence from the wire: the ServerHello random ends with DOWNGRD 00 (RFC 8446 section 4.1.3).
                    TapLog log = TapLog.Read(hop);
                    byte[] got = log.ServerToClient;
                    Check.True(got.Length > 43 && got[0] == 0x16 && got[5] == 0x02, "the first record from the server is not a ServerHello");
                    string tail = Hex.Encode(Hex.Slice(got, 11 + 24, 8));
                    Check.Equal("last 8 bytes of ServerHello.random", "444f574e47524400", tail);
                    return "control opens as TLS 1.3; a hello that offers only TLS 1.1 gives TLS13_DOWNGRADE_SENTINEL and the server random ends in DOWNGRD";
                }
            }
        }
    }
}
