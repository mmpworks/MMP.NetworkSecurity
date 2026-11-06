using System.Text;
using NetSec.Io;

namespace Acceptance
{
    /// <summary>
    /// A18: what the TLS 1.3 engine leaves out, against a real peer (docs/conformance-matrix.md row 4). Each clause pairs with the on-screen line A18.screen.l5-tls13-leaves-out:
    /// if the engine gains the item, this clause fails, so the line cannot go stale without a red. Each runs a control first, so a dead listener cannot pass.
    /// </summary>
    public static class A18Tls13Refusals
    {
        const string BaseArgs = "-tls1_3 -servername localhost";

        /// <summary>The glass server, on X25519, against an OpenSSL client with these extra arguments.</summary>
        static ProbeResult ServerAgainst(Ctx c, PkiDir p, string extra, out string peerOutput)
        {
            ProbeRequest req = ProbeKit.Request(WireProtocol.Tls13, 0, "localhost");
            req.Group = KexGroup.X25519;
            req.Send = Encoding.ASCII.GetBytes("world\n");
            ProbeListener listener = Probe.Listen(req);
            Check.True(listener != null && listener.Port > 0, "Probe.Listen returned no port");
            using (Proc peer = OpenSslPeer.StartClient(c, "-connect 127.0.0.1:" + listener.Port + " " + BaseArgs + " -CAfile \"" + p.Root + "\" " + extra).P)
            {
                peer.WriteLine("hello");
                ProbeResult r = Futs.Get(listener.Result, 60000, "glass TLS 1.3 server against OpenSSL " + extra);
                peerOutput = peer.AllOutput;
                return r;
            }
        }

        static string ServerRefuses(Ctx c, string stem, string extra, string code, string what)
        {
            PkiDir p = PkiDir.Export(c, stem);
            string output;
            ProbeResult control = ServerAgainst(c, p, "-groups X25519", out output);
            Check.True(control.Completed, "control: an X25519 client should connect, and stopped: " + control.CheckName + " [" + control.Code + "]. OpenSSL output: " + output);
            ProbeResult r = ServerAgainst(c, p, extra, out output);
            Check.True(!r.Completed, "the glass server completed a session with a client that offers " + what + ". The engine now supports this, so the on-screen line A18.screen.l5-tls13-leaves-out needs a change");
            Check.Equal("refusal code", code, r.Code);
            return "control connects; a client offering " + what + " gets " + code;
        }

        [Clause("A18.refuse.tls13.server-p256-only", PerBuild = true)]
        public static string ServerP256Only(Ctx c) { return ServerRefuses(c, "a18-t13-p256", "-groups P-256", "TLS13_NO_COMMON_GROUP", "P-256 only"); }

        /// <summary>The client lists X25519 too, and sends a key share for P-256 only. A full server would answer with HelloRetryRequest.</summary>
        [Clause("A18.refuse.tls13.server-no-hello-retry", PerBuild = true)]
        public static string ServerNoHelloRetry(Ctx c) { return ServerRefuses(c, "a18-t13-hrr", "-groups P-256:X25519", "TLS13_HRR_UNSUPPORTED", "a P-256 share first, with X25519 listed"); }

        [Clause("A18.refuse.tls13.server-rsa-ecdsa-signatures", PerBuild = true)]
        public static string ServerRsaEcdsa(Ctx c) { return ServerRefuses(c, "a18-t13-sig", "-groups X25519 -sigalgs rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp256r1_sha256", "TLS13_NO_COMMON_SIGNATURE", "RSA and ECDSA signatures only"); }

        [Clause("A18.refuse.tls13.server-chacha20", PerBuild = true)]
        public static string ServerChaCha(Ctx c) { return ServerRefuses(c, "a18-t13-chacha", "-groups X25519 -ciphersuites TLS_CHACHA20_POLY1305_SHA256", "TLS13_NO_COMMON_SUITE", "ChaCha20 only"); }

        [Clause("A18.refuse.tls13.client-p256-only-server", PerBuild = true)]
        public static string ClientP256Server(Ctx c)
        {
            PkiDir p = PkiDir.Export(c, "a18-t13-client");
            ProbeRequest Make(int port)
            {
                ProbeRequest r = ProbeKit.Request(WireProtocol.Tls13, port, "localhost");
                r.Group = KexGroup.X25519;
                r.Send = Encoding.ASCII.GetBytes("hello\n");
                return r;
            }
            string common = "-tls1_3 -cert \"" + p.Cert + "\" -key \"" + p.Key + "\" -rev ";
            using (OpenSslPeer good = OpenSslPeer.StartServer(c, common + "-groups X25519"))
            {
                ProbeResult ok = ProbeKit.Connect(Make(good.Port), "control: glass client against an X25519 server");
                Check.True(ok.Completed, "control: an X25519 server should connect, and stopped: " + ok.CheckName + " [" + ok.Code + "]");
            }
            using (OpenSslPeer bad = OpenSslPeer.StartServer(c, common + "-groups P-256"))
            {
                ProbeResult r = ProbeKit.Connect(Make(bad.Port), "glass client against a P-256 only server");
                Check.True(!r.Completed, "the glass client completed a session with a P-256 only server. The on-screen line A18.screen.l5-tls13-leaves-out needs a change");
                return "control connects; a P-256 only server stops the glass client: " + r.CheckName + " [" + r.Code + "]";
            }
        }
    }
}
