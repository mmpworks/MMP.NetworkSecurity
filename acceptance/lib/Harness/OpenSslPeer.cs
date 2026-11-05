using System;
using System.Text.RegularExpressions;

namespace Acceptance
{

    /// <summary>An OpenSSL s_server or s_client child. Parses the lines the referee prints.</summary>
    public sealed class OpenSslPeer : IDisposable
    {
        public readonly Proc P;
        public int Port;
        OpenSslPeer(Proc p) { P = p; }

        /// <summary>Starts `openssl s_server -accept 0 ... -naccept 1 -rev` and waits for the ACCEPT line.</summary>
        public static OpenSslPeer StartServer(Ctx c, string args)
        {
            Proc p = Proc.Start(Referees.OpenSsl(c), "s_server -accept 0 -naccept 1 -rev " + args);
            OpenSslPeer peer = new OpenSslPeer(p);
            string accept = p.WaitForLine(delegate (string s) { return s.StartsWith("ACCEPT"); }, 20000);
            if (accept == null) { string o = p.AllOutput; p.Dispose(); throw new FailException("openssl s_server did not print ACCEPT. Output: " + o); }
            Match m = Regex.Match(accept, @"(?<port>\d+)\s*$");
            peer.Port = int.Parse(m.Groups["port"].Value);
            return peer;
        }

        public static OpenSslPeer StartClient(Ctx c, string args)
        {
            return new OpenSslPeer(Proc.Start(Referees.OpenSsl(c), "s_client " + args));
        }

        /// <summary>Waits until the referee has printed a line that matches the pattern. Returns the match or null.</summary>
        public Match WaitFor(string pattern, int timeoutMs)
        {
            string line = P.WaitForLine(delegate (string s) { return Regex.IsMatch(s, pattern); }, timeoutMs);
            return line == null ? null : Regex.Match(line, pattern);
        }

        public string Output { get { return P.AllOutput; } }
        public void Dispose() { P.Dispose(); }
    }
}
