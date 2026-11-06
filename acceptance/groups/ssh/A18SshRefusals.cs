using NetSec.Io;
using NetSec.Keys;

namespace Acceptance
{
    /// <summary>
    /// A18: what the SSH engine leaves out, against Go x/crypto/ssh (docs/conformance-matrix.md rows 9 and 10). Each clause pairs with the on-screen line A18.screen.l8-ssh-leaves-out.
    /// The glass server meets a Go client. The Go client offers only the one item, or asks for the one step, and a control with the same client connects first.
    /// </summary>
    public static class A18SshRefusals
    {
        const string ModernClient = "-kex curve25519-sha256 -cipher aes128-ctr -mac hmac-sha2-256";

        sealed class Run { public ProbeResult Result; public string Output; }

        static Run Against(Ctx c, PkiDir p, string goArgs) { return Against(c, p, goArgs, null); }

        /// <summary>The engine's result can arrive before Go prints its error, so a clause that judges Go's words names the line to wait for.</summary>
        static Run Against(Ctx c, PkiDir p, string goArgs, string waitLine)
        {
            ProbeRequest req = ProbeKit.Request(WireProtocol.Ssh, 0, "127.0.0.1");
            req.SshSuite = SshSuite.Modern;
            ProbeListener listener = Probe.Listen(req);
            Check.True(listener != null && listener.Port > 0, "Probe.Listen returned no port");
            string known = System.IO.Path.Combine(p.Dir, "known_hosts_" + listener.Port);
            string keyLine;
            Proc.Run(Referees.SshKeygen(c), "-y -f \"" + p.HostKey + "\"", p.Dir, 30000, out keyLine);
            string[] parts = keyLine.Trim().Split(' ');
            System.IO.File.WriteAllText(known, "[127.0.0.1]:" + listener.Port + " " + parts[0] + " " + parts[1] + "\n");
            using (GoPeer go = GoPeer.Start(c, "sshpeer", "-mode client -connect 127.0.0.1:" + listener.Port + " -known-host \"" + known + "\" -identity \"" + p.UserKey + "\" -exec \"echo hello\" " + goArgs))
            {
                Run r = new Run();
                r.Result = Futs.Get(listener.Result, 60000, "glass SSH server against Go");
                if (waitLine != null) go.P.WaitForLine(delegate (string l) { return l.Contains(waitLine); }, 10000);
                r.Output = go.P.AllOutput;
                return r;
            }
        }

        static string Refused(Ctx c, string stem, string goArgs, string code, string what)
        {
            PkiDir p = PkiDir.Export(c, stem);
            OpenSshKey.RestrictToCurrentUser(p.UserKey);
            OpenSshKey.RestrictToCurrentUser(p.HostKey);
            Run control = Against(c, p, ModernClient);
            Check.True(control.Result.Completed, "control: a modern Go client should connect, and stopped: " + control.Result.CheckName + " [" + control.Result.Code + "]. Go output: " + control.Output);
            Run r = Against(c, p, goArgs);
            Check.True(!r.Result.Completed, "the glass SSH server completed a session with a client that offers " + what + ". The on-screen line A18.screen.l8-ssh-leaves-out needs a change");
            Check.Equal("refusal code", code, r.Result.Code);
            return "control connects; a client offering " + what + " gets " + code;
        }

        [Clause("A18.refuse.ssh.3des-cbc", PerBuild = true)]
        public static string TripleDes(Ctx c) { return Refused(c, "a18-ssh-3des", "-kex curve25519-sha256 -cipher 3des-cbc -mac hmac-sha2-256", "SSH_NO_COMMON_ALG", "only 3des-cbc"); }

        [Clause("A18.refuse.ssh.group1", PerBuild = true)]
        public static string Group1(Ctx c) { return Refused(c, "a18-ssh-group1", "-kex diffie-hellman-group1-sha1 -cipher aes128-ctr -mac hmac-sha2-256", "SSH_NO_COMMON_ALG", "only diffie-hellman-group1-sha1"); }

        [Clause("A18.refuse.ssh.dss", PerBuild = true)]
        public static string Dss(Ctx c) { return Refused(c, "a18-ssh-dss", ModernClient + " -host-key-alg ssh-dss", "SSH_NO_COMMON_ALG", "only ssh-dss host keys"); }

        [Clause("A18.refuse.ssh.rekey-stops-by-name", PerBuild = true)]
        public static string Rekey(Ctx c) { return Refused(c, "a18-ssh-rekey", ModernClient + " -rekey-bytes 256", "SSH_REKEY_UNSUPPORTED", "a key re-exchange"); }

        /// <summary>
        /// The engine names only publickey in its reply to the first auth request. So a client that holds only a password has no method left, sends no password, and hangs up, and the engine reads PEER_CLOSED_EARLY.
        /// So the judge here is the peer: Go must say 'attempted methods [none]', which means it never tried the password. A server that offers passwords and rejects this one gives '[none password]' with the same closing words.
        /// </summary>
        [Clause("A18.refuse.ssh.password-login", PerBuild = true)]
        public static string Password(Ctx c)
        {
            PkiDir p = PkiDir.Export(c, "a18-ssh-password");
            OpenSshKey.RestrictToCurrentUser(p.UserKey);
            OpenSshKey.RestrictToCurrentUser(p.HostKey);
            Run control = Against(c, p, ModernClient);
            Check.True(control.Result.Completed, "control: a modern Go client should connect, and stopped: " + control.Result.CheckName + " [" + control.Result.Code + "]. Go output: " + control.Output);
            Run r = Against(c, p, ModernClient + " -password-only training", "unable to authenticate");
            Check.True(!r.Result.Completed, "the glass SSH server completed a session with a password login. The on-screen line A18.screen.l8-ssh-leaves-out needs a change");
            Check.True(r.Output.Contains("attempted methods [none]"), "Go did not say 'attempted methods [none]', so it may have tried the password. The on-screen line A18.screen.l8-ssh-leaves-out needs a change. Go output: " + r.Output);
            return "control connects; the server offers no password method, so a password-only client cannot log in. The engine reads " + r.Result.Code;
        }
    }
}
