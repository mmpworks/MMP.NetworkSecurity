using System.Text.RegularExpressions;
using NetSec.Io;

namespace Acceptance
{
    /// <summary>A18: what the TLS 1.1 engine leaves out, against OpenSSL (docs/conformance-matrix.md row 7). Each clause pairs with the on-screen line A18.screen.l7-tls11-leaves-out.</summary>
    public static class A18Tls11Refusals
    {
        const string Suite = "TLS_RSA_WITH_AES_128_CBC_SHA";

        sealed class Session { public ProbeResult Result; public string Output; }

        static Session Run(Ctx c, PkiDir p, string openSslArgs)
        {
            ProbeRequest req = ProbeKit.Request(WireProtocol.Tls11, 0, "localhost");
            req.Suite = Suite;
            ProbeListener listener = Probe.Listen(req);
            Check.True(listener != null && listener.Port > 0, "Probe.Listen returned no port");
            using (Proc client = OpenSslPeer.StartClient(c, "-tls1_1 -CAfile \"" + p.Root + "\" -connect 127.0.0.1:" + listener.Port + " " + openSslArgs).P)
            {
                client.WriteLine("hello");
                Session s = new Session();
                s.Result = Futs.Get(listener.Result, 60000, "glass TLS 1.1 server");
                client.WaitForLine(delegate (string l) { return l.Contains("Verify return code"); }, 10000);
                s.Output = client.AllOutput;
                return s;
            }
        }

        /// <summary>OpenSSL 3.5.7 here has no DES-CBC3-SHA ("no cipher match"), so it cannot offer the suite. Go can, so Go is the client for this clause and for its control.</summary>
        static Session GoClient(Ctx c, PkiDir p, string goSuite)
        {
            ProbeRequest req = ProbeKit.Request(WireProtocol.Tls11, 0, "localhost");
            req.Suite = Suite;
            ProbeListener listener = Probe.Listen(req);
            Check.True(listener != null && listener.Port > 0, "Probe.Listen returned no port");
            using (GoPeer go = GoPeer.Start(c, "tlspeer", "-mode client -connect 127.0.0.1:" + listener.Port + " -groups x25519 -ca \"" + p.Root + "\" -server-name localhost -tls11-suite " + goSuite))
            {
                go.P.WriteLine("hello");
                Session s = new Session();
                s.Result = Futs.Get(listener.Result, 60000, "glass TLS 1.1 server against Go");
                s.Output = go.P.AllOutput;
                return s;
            }
        }

        [Clause("A18.refuse.tls11.3des-suite", PerBuild = true)]
        public static string TripleDes(Ctx c)
        {
            PkiDir p = PkiDir.Export(c, "a18-t11-3des");
            Session control = GoClient(c, p, "TLS_RSA_WITH_AES_128_CBC_SHA");
            Check.True(control.Result.Completed, "control: Go on TLS_RSA_WITH_AES_128_CBC_SHA should connect, and stopped: " + control.Result.CheckName + " [" + control.Result.Code + "]. Go output: " + control.Output);
            Session s = GoClient(c, p, "TLS_RSA_WITH_3DES_EDE_CBC_SHA");
            Check.True(!s.Result.Completed, "the glass TLS 1.1 server completed a session on the 3DES suite. The on-screen line A18.screen.l7-tls11-leaves-out needs a change");
            return "control connects; Go offering only the 3DES suite stops the server: " + s.Result.CheckName + " [" + s.Result.Code + "]";
        }

        /// <summary>A server that can resume names a session or a ticket. This one names neither, so OpenSSL has nothing to offer back. Reconnecting would need a second session on the same listener, and Probe.Listen answers one.</summary>
        [Clause("A18.refuse.tls11.no-resumption", PerBuild = true)]
        public static string NoResumption(Ctx c)
        {
            PkiDir p = PkiDir.Export(c, "a18-t11-resume");
            Session s = Run(c, p, "-cipher AES128-SHA:@SECLEVEL=0");
            Check.True(s.Result.Completed, "the session should connect, and stopped: " + s.Result.CheckName + " [" + s.Result.Code + "]");
            Check.True(Regex.IsMatch(s.Output, @"New,"), "OpenSSL did not report a new session. Output: " + s.Output);
            Check.True(!s.Output.Contains("TLS session ticket"), "the server sent a session ticket. The on-screen line A18.screen.l7-tls11-leaves-out needs a change. Output: " + s.Output);
            Match id = Regex.Match(s.Output, @"Session-ID:[ \t]*(?<id>[0-9A-Fa-f]*)");
            Check.True(id.Success, "OpenSSL printed no Session-ID line. Output: " + s.Output);
            Check.True(id.Groups["id"].Value.Length == 0, "the server named session " + id.Groups["id"].Value + ", so it may resume. The on-screen line A18.screen.l7-tls11-leaves-out needs a change");
            return "the server names no session and sends no ticket, so a client has nothing to resume";
        }

        [Clause("A18.refuse.tls11.no-client-certificate-request", PerBuild = true)]
        public static string NoClientCertRequest(Ctx c)
        {
            PkiDir p = PkiDir.Export(c, "a18-t11-cert");
            Session s = Run(c, p, "-cipher AES128-SHA:@SECLEVEL=0");
            Check.True(s.Result.Completed, "the session should connect, and stopped: " + s.Result.CheckName + " [" + s.Result.Code + "]");
            Check.True(s.Output.Contains("No client certificate CA names sent"), "OpenSSL does not report 'No client certificate CA names sent', so the server may ask for a client certificate. The on-screen line A18.screen.l7-tls11-leaves-out needs a change. Output: " + s.Output);
            return "OpenSSL reports that the server asks for no client certificate";
        }
    }
}
