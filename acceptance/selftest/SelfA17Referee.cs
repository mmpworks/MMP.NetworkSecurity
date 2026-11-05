using System;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// A17.referee.tls13-client-go-with-intermediate needs a glass client on a learner's key, which today's Core cannot start. What the clause leans on can still be proved without it:
    /// Go crypto/tls, as the server, accepts a client certificate whose intermediate is sent after the leaf, and refuses the leaf alone. Go plays both ends here.
    /// </summary>
    public static class SelfA17Referee
    {
        [Clause("SELF.a17-intermediate-referee-bites")]
        public static string IntermediateRefereeBites(Ctx c)
        {
            TestPki pki = TestPki.Make(c, "referee-inter", new TestPki.Options { Intermediate = true });
            string serverArgs = "-mode server -listen 127.0.0.1:0 -naccept 1 -groups x25519 -cert \"" + pki.ServerPem + "\" -key \"" + pki.ServerKey + "\" -require-client-cert -ca \"" + pki.RootPem + "\"";
            string withChain, leafOnly;
            using (GoPeer server = GoPeer.StartListening(c, "tlspeer", serverArgs))
            using (GoPeer client = GoPeer.Start(c, "tlspeer", "-mode client -connect 127.0.0.1:" + server.Port + " -groups x25519 -ca \"" + pki.RootPem + "\" -server-name localhost -cert \"" + pki.ClientChainPem + "\" -key \"" + pki.ClientKey + "\""))
            {
                client.P.WriteLine("hello");
                Check.True(server.WaitEvent("handshake", 20000) != null, "Go refused a client certificate that came with its intermediate. Output: " + server.Output + client.Output);
                withChain = "accepted";
            }
            using (GoPeer server = GoPeer.StartListening(c, "tlspeer", serverArgs))
            using (GoPeer client = GoPeer.Start(c, "tlspeer", "-mode client -connect 127.0.0.1:" + server.Port + " -groups x25519 -ca \"" + pki.RootPem + "\" -server-name localhost -cert \"" + pki.ClientPem + "\" -key \"" + pki.ClientKey + "\""))
            {
                client.P.WriteLine("hello");
                Check.True(server.WaitEvent("handshake", 8000) == null, "control: Go accepted a client leaf whose intermediate was not sent. Output: " + server.Output + client.Output);
                Check.True(server.Output.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0 || server.Output.IndexOf("CERT", StringComparison.OrdinalIgnoreCase) >= 0 || client.Output.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0,
                    "control: Go refused the leaf alone but printed no error. Output: " + server.Output + client.Output);
                leafOnly = "refused";
            }
            return "Go crypto/tls as the server: the client leaf with its intermediate is " + withChain + ", the leaf alone is " + leafOnly;
        }
    }
}
