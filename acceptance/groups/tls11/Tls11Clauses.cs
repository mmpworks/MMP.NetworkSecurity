using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Pki;

namespace Acceptance
{
    /// <summary>
    /// A7: the glass TLS 1.1 client against OpenSSL 3.5.7 for a named RSA key transport suite and a named ECDHE CBC suite;
    /// alert 70 from a modern server beside a passing control (the same client against the legacy server);
    /// and the downgrade sentinel seen by a TLS 1.3 client, beside a passing control.
    /// The lab forces the weak suite on purpose (accuracy rule 3). A default run would pick the best case.
    /// </summary>
    public static class Tls11Clauses
    {
        sealed class Setup
        {
            public string Dir, RootPem, RsaCert, RsaKey, EdCert, EdKey;
            public TrainingCa Ca;
        }

        static Setup Prepare(Ctx c, string name, bool withEd25519)
        {
            Setup s = new Setup();
            s.Dir = LivePki.Dir(c, name);
            s.Ca = new TrainingCa(new TrainingKeySource());
            s.RootPem = LivePki.WriteRoot(s.Dir, s.Ca);
            LivePki.RsaServer(c, s.Dir, s.Ca, "localhost", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30), out s.RsaCert, out s.RsaKey);
            if (withEd25519)
                LivePki.Ed25519Server(c, s.Dir, s.Ca, "localhost", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30), out s.EdCert, out s.EdKey);
            return s;
        }

        static string LegacyServerArgs(Setup s, string openSslCipher)
        {
            return "-tls1_1 -cipher " + openSslCipher + ":@SECLEVEL=0 -cert \"" + s.RsaCert + "\" -key \"" + s.RsaKey + "\"";
        }

        static string Tls11Against(Ctx c, Tls11Suite suite, string openSslCipher, string stem)
        {
            Setup s = Prepare(c, stem, false);
            using (OpenSslPeer server = OpenSslPeer.StartServer(c, LegacyServerArgs(s, openSslCipher)))
            {
                Handshake h = Live.OpenClient(WireProtocol.Tls11, KexGroup.X25519, SshSuite.Modern, suite, server.Port, "localhost", null, 7001, stem);
                Check.True(h.Opened, "glass TLS 1.1 client against OpenSSL (" + openSslCipher + "): " + h.Describe());
                string got = Live.Exchange(h.Channel, "hello\n", "olleh", 15000);
                Futs.Done(h.Channel.Close(), 5000, "close");
                Check.True(server.WaitFor(@"Ciphersuite:", 15000) != null, "OpenSSL printed no Ciphersuite line. Output: " + server.Output);
                Check.Equal("protocol reported by OpenSSL", "TLSv1.1", OpenSslLines.Protocol(server.Output));
                Check.Equal("suite reported by OpenSSL", openSslCipher, OpenSslLines.Ciphersuite(server.Output));
                return "TLS 1.1 handshake and echo, OpenSSL reports TLSv1.1 and " + openSslCipher;
            }
        }

        [Clause("A7.tls11.openssl.rsa-transport", PerBuild = true)]
        public static string RsaTransport(Ctx c) { return Tls11Against(c, Tls11Suite.RsaAes128CbcSha, "AES128-SHA", "a7-rsa-transport"); }

        [Clause("A7.tls11.openssl.ecdhe-cbc", PerBuild = true)]
        public static string EcdheCbc(Ctx c) { return Tls11Against(c, Tls11Suite.EcdheRsaAes128CbcSha, "ECDHE-RSA-AES128-SHA", "a7-ecdhe-cbc"); }

        // ---------------------------------------------------------------- alert 70

        [Clause("A7.alert70.modern-server-beside-legacy-control", PerBuild = true)]
        public static string Alert70(Ctx c)
        {
            Setup s = Prepare(c, "a7-alert70", true);
            // Control: the same client, same suite, against a server that speaks TLS 1.1. It must open.
            using (OpenSslPeer legacy = OpenSslPeer.StartServer(c, LegacyServerArgs(s, "AES128-SHA")))
            {
                Handshake ok = Live.OpenClient(WireProtocol.Tls11, KexGroup.X25519, SshSuite.Modern, Tls11Suite.RsaAes128CbcSha, legacy.Port, "localhost", null, 7002, "a7-alert70-control");
                Check.True(ok.Opened, "control run against the TLS 1.1 server failed: " + ok.Describe());
                Futs.Done(ok.Channel.Close(), 5000, "close");
            }
            // Attack: one thing differs, the server only speaks TLS 1.3. OpenSSL answers a TLS 1.1 hello with alert 70 (protocol_version).
            using (OpenSslPeer modern = OpenSslPeer.StartServer(c, "-tls1_3 -cert \"" + s.EdCert + "\" -key \"" + s.EdKey + "\""))
            {
                Handshake h = Live.OpenClient(WireProtocol.Tls11, KexGroup.X25519, SshSuite.Modern, Tls11Suite.RsaAes128CbcSha, modern.Port, "localhost", null, 7003, "a7-alert70-attack");
                Check.True(!h.Opened, "the TLS 1.1 client opened a channel to a TLS 1.3-only server");
                Check.Equal("failed check code", "TLS11_ALERT_PROTOCOL_VERSION", h.FailedCode);
                return "control opens against TLS 1.1; TLS 1.3-only server gives TLS11_ALERT_PROTOCOL_VERSION";
            }
        }

        // ---------------------------------------------------------------- downgrade sentinel

        /// <summary>Rewrites the supported_versions extension of the ClientHello so it offers TLS 1.1 (0x0302) in place of TLS 1.3 (0x0304). Lengths do not change.</summary>
        sealed class DowngradeHook : ITamperHook
        {
            public bool Fired;
            public TamperResult Apply(TamperPoint point, string streamId, long streamSeq, string message, byte[] bytes)
            {
                if (point != TamperPoint.Wire || message != "ClientHello") return TamperResult.Unchanged;
                byte[] b = (byte[])bytes.Clone();
                int p = 5 + 4 + 2 + 32;                                    // record header, handshake header, legacy_version, random
                p += 1 + b[p];                                             // session id
                p += 2 + ((b[p] << 8) | b[p + 1]);                         // cipher suites
                p += 1 + b[p];                                             // compression methods
                int extEnd = p + 2 + ((b[p] << 8) | b[p + 1]);
                p += 2;
                while (p + 4 <= extEnd)
                {
                    int type = (b[p] << 8) | b[p + 1], len = (b[p + 2] << 8) | b[p + 3];
                    if (type == 0x002b)
                    {
                        int listLen = b[p + 4];
                        for (int i = 0; i + 1 < listLen; i += 2)
                            if (b[p + 5 + i] == 0x03 && b[p + 5 + i + 1] == 0x04) { b[p + 5 + i + 1] = 0x02; Fired = true; }
                        return TamperResult.Replace(b);
                    }
                    p += 4 + len;
                }
                return TamperResult.Unchanged;
            }
        }

        [Clause("A7.downgrade-sentinel.tls13-client-beside-control", PerBuild = true)]
        public static string DowngradeSentinel(Ctx c)
        {
            Setup s = Prepare(c, "a7-sentinel", true);
            // The server speaks TLS 1.3 and TLS 1.1. It holds an Ed25519 certificate for 1.3 and an RSA certificate for 1.1.
            string args = "-cipher ALL:@SECLEVEL=0 -min_protocol TLSv1.1 -cert \"" + s.EdCert + "\" -key \"" + s.EdKey + "\" -dcert \"" + s.RsaCert + "\" -dkey \"" + s.RsaKey + "\"";
            // Control: nobody touches the hello. A TLS 1.3 client gets TLS 1.3.
            using (OpenSslPeer control = OpenSslPeer.StartServer(c, args))
            {
                Handshake ok = Live.OpenClient(WireProtocol.Tls13, KexGroup.X25519, SshSuite.Modern, control.Port, "localhost", null, 7004, "a7-sentinel-control");
                Check.True(ok.Opened, "control run (no rewrite) failed: " + ok.Describe());
                Futs.Done(ok.Channel.Close(), 5000, "close");
            }
            // Attack: a machine in the middle rewrites the hello to offer TLS 1.1 only. The server takes the downgrade and writes DOWNGRD in its random.
            DowngradeHook hook = new DowngradeHook();
            using (OpenSslPeer attacked = OpenSslPeer.StartServer(c, args))
            {
                Handshake h = Live.OpenClient(WireProtocol.Tls13, KexGroup.X25519, SshSuite.Modern, attacked.Port, "localhost", hook, 7005, "a7-sentinel-attack");
                Check.True(hook.Fired, "the test rewrite never found a supported_versions entry for TLS 1.3 in the ClientHello, so the attack did not run");
                Check.True(!h.Opened, "the TLS 1.3 client accepted a downgrade to an older protocol");
                Check.Equal("failed check code", "TLS13_DOWNGRADE_SENTINEL", h.FailedCode);
                // Independent evidence from the wire: the ServerHello random ends with DOWNGRD 00 (RFC 8446 section 4.1.3).
                byte[] got = h.Link.Received;
                Check.True(got.Length > 43 && got[0] == 0x16 && got[5] == 0x02, "the first record from the server is not a ServerHello");
                string tail = Hex.Encode(Hex.Slice(got, 11 + 24, 8));
                Check.Equal("last 8 bytes of ServerHello.random", "444f574e47524400", tail);
                return "control opens as TLS 1.3; rewritten hello gives TLS13_DOWNGRADE_SENTINEL and the server random ends in DOWNGRD";
            }
        }
    }
}
