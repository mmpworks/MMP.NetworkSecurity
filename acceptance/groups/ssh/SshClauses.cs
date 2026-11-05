using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using MMP.AsyncProxy;
using NetSec.Io;
using NetSec.Keys;

namespace Acceptance
{
    /// <summary>
    /// A8: the glass SSH client runs one exec and one tunnel against a Go x/crypto/ssh server (the sshpeer referee), on the
    /// modern suite and on the legacy suite (diffie-hellman-group14-sha1, aes128-cbc, hmac-sha1, old RSA host key).
    /// A changed host key gives a named error beside a passing control. Windows ssh.exe works against our server (role ssh.server).
    /// The referee prints one NEGOTIATED line per connection, so the algorithms in use are the referee's word.
    /// Command lines and output lines: acceptance/referee-contract.md.
    /// </summary>
    public static class SshClauses
    {
        sealed class Keys
        {
            public string Dir, HostEd, HostRsa, Attacker, Authorized, ClientPem;
        }

        static Keys Prepare(Ctx c, string name)
        {
            Keys k = new Keys();
            k.Dir = LivePki.Dir(c, name);
            TrainingKeySource src = new TrainingKeySource();
            ITrainingKey host = src.Find(KeyIds.SshHostEd25519), attacker = src.Find(KeyIds.AttackerEd25519), client = src.Find(KeyIds.SshClient), rsa = src.Find(KeyIds.SshHostRsa);
            k.HostEd = Path.Combine(k.Dir, "host_ed25519");
            File.WriteAllText(k.HostEd, OpenSshKey.PrivatePem(host.CopyMaterial(), host.CopyPublic(), "ssh host"));
            k.Attacker = Path.Combine(k.Dir, "attacker_ed25519");
            File.WriteAllText(k.Attacker, OpenSshKey.PrivatePem(attacker.CopyMaterial(), attacker.CopyPublic(), "attacker"));
            k.HostRsa = Path.Combine(k.Dir, "host_rsa");
            File.WriteAllText(k.HostRsa, LivePki.Pem("PRIVATE KEY", rsa.CopyMaterial()));      // ASSUMED: RSA material is PKCS#8 DER
            k.Authorized = Path.Combine(k.Dir, "user.pub");
            File.WriteAllText(k.Authorized, OpenSshKey.AuthorizedLine(client.CopyPublic(), "training"));
            k.ClientPem = Path.Combine(k.Dir, "client_ed25519");
            File.WriteAllText(k.ClientPem, OpenSshKey.PrivatePem(client.CopyMaterial(), client.CopyPublic(), "training"));
            return k;
        }

        static string PeerArgs(Keys k, SshSuite suite, string hostKey, int tunnelPort)
        {
            string common = "-listen 127.0.0.1:0 -authorized \"" + k.Authorized + "\" -allow-tunnel 127.0.0.1:" + tunnelPort + " -host-key \"" + hostKey + "\"";
            return suite == SshSuite.Modern
                ? common + " -kex curve25519-sha256 -cipher aes128-ctr -mac hmac-sha2-256"
                : common + " -kex diffie-hellman-group14-sha1 -cipher aes128-cbc -mac hmac-sha1";
        }

        static ISshChannel AsSsh(Handshake h)
        {
            ISshChannel ssh = h.Channel as ISshChannel;
            if (ssh == null) throw new NotRunException("PRODUCT_MISSING", "the SSH channel does not implement NetSec.Io.ISshChannel (OpenExec, OpenTunnel). See CONTRACT.md");
            return ssh;
        }

        static string ReadChannel(ISecureChannel ch, int channel, string expect, int ms)
        {
            StringBuilder got = new StringBuilder();
            DateTime end = DateTime.UtcNow.AddMilliseconds(ms);
            while (got.ToString().IndexOf(expect, StringComparison.Ordinal) < 0)
            {
                int left = (int)(end - DateTime.UtcNow).TotalMilliseconds;
                if (left <= 0) throw new FailException("channel " + channel + ": expected '" + expect.Trim() + "', read '" + got.ToString().Trim() + "'");
                IFuture<AppChunk> f = ch.Receive();
                if (!f.Wait(left)) throw new FailException("channel " + channel + ": expected '" + expect.Trim() + "', read '" + got.ToString().Trim() + "', then silence");
                if (f.IsFaulted) throw new FailException("receive failed: " + f.Exception);
                AppChunk chunk = f.Result;
                if (chunk == null || chunk.Bytes == null) break;
                if (chunk.Channel != channel) continue;
                if (chunk.Bytes.Length == 0) break;                          // end of channel
                got.Append(Encoding.ASCII.GetString(chunk.Bytes));
            }
            return got.ToString();
        }

        static string Negotiated(GoPeer peer, SshSuite suite)
        {
            string line = peer.P.WaitForLine(delegate (string l) { return l.StartsWith("NEGOTIATED "); }, 15000);
            Check.True(line != null, "sshpeer printed no NEGOTIATED line. Output: " + peer.Output);
            if (suite == SshSuite.Modern)
                Check.True(line.Contains("kex=curve25519-sha256") && line.Contains("cipher=aes128-ctr") && line.Contains("mac=hmac-sha2-256") && line.Contains("hostkey=ssh-ed25519"), "modern suite not negotiated: " + line);
            else
                Check.True(line.Contains("kex=diffie-hellman-group14-sha1") && line.Contains("cipher=aes128-cbc") && line.Contains("mac=hmac-sha1") && line.Contains("hostkey=ssh-rsa"), "legacy suite not negotiated: " + line);
            return line;
        }

        static string ExecAndTunnel(Ctx c, SshSuite suite, bool doExec, bool doTunnel, string stem)
        {
            Keys k = Prepare(c, stem);
            using (EchoServer echo = new EchoServer())
            using (GoPeer peer = GoPeer.StartListening(c, "sshpeer", PeerArgs(k, suite, suite == SshSuite.Modern ? k.HostEd : k.HostRsa, echo.Port)))
            {
                Handshake h = Live.OpenClient(WireProtocol.Ssh, KexGroup.X25519, suite, peer.Port, "127.0.0.1", null, 8001, stem);
                Check.True(h.Opened, "glass SSH client (" + suite + ") against Go x/crypto/ssh: " + h.Describe());
                ISshChannel ssh = AsSsh(h);
                string what = "";
                if (doExec)
                {
                    int ch = Futs.Get(ssh.OpenExec("echo hello"), 15000, "open exec");
                    string got = ReadChannel(ssh, ch, "EXEC:echo hello", 15000);
                    what += "exec returned '" + got.Trim() + "'; ";
                }
                if (doTunnel)
                {
                    int ch = Futs.Get(ssh.OpenTunnel("127.0.0.1", echo.Port), 15000, "open tunnel");
                    Futs.Done(ssh.Send(ch, Encoding.ASCII.GetBytes("ping-through-tunnel")), 10000, "tunnel send");
                    ReadChannel(ssh, ch, "ping-through-tunnel", 15000);
                    Check.True(echo.Connections >= 1, "the echo server never saw a connection, so the bytes did not travel through the tunnel");
                    what += "tunnel echoed " + echo.BytesEchoed + " bytes; ";
                }
                Futs.Done(ssh.Close(), 5000, "close");
                string neg = Negotiated(peer, suite);
                return what + neg;
            }
        }

        [Clause("A8.ssh.modern.exec", PerBuild = true)]
        public static string ModernExec(Ctx c) { return ExecAndTunnel(c, SshSuite.Modern, true, false, "a8-modern-exec"); }

        [Clause("A8.ssh.modern.tunnel", PerBuild = true)]
        public static string ModernTunnel(Ctx c) { return ExecAndTunnel(c, SshSuite.Modern, false, true, "a8-modern-tunnel"); }

        [Clause("A8.ssh.legacy.exec", PerBuild = true)]
        public static string LegacyExec(Ctx c) { return ExecAndTunnel(c, SshSuite.Legacy, true, false, "a8-legacy-exec"); }

        [Clause("A8.ssh.legacy.tunnel", PerBuild = true)]
        public static string LegacyTunnel(Ctx c) { return ExecAndTunnel(c, SshSuite.Legacy, false, true, "a8-legacy-tunnel"); }

        [Clause("A8.ssh.hostkey-changed-beside-control", PerBuild = true)]
        public static string HostKeyChanged(Ctx c)
        {
            Keys k = Prepare(c, "a8-hostkey");
            using (EchoServer echo = new EchoServer())
            {
                // Control: the host key the client expects.
                using (GoPeer good = GoPeer.StartListening(c, "sshpeer", PeerArgs(k, SshSuite.Modern, k.HostEd, echo.Port)))
                {
                    Handshake ok = Live.OpenClient(WireProtocol.Ssh, KexGroup.X25519, SshSuite.Modern, good.Port, "127.0.0.1", null, 8002, "a8-hostkey-control");
                    Check.True(ok.Opened, "control run (expected host key) failed: " + ok.Describe());
                    Futs.Done(ok.Channel.Close(), 5000, "close");
                }
                // Attack: one thing differs, the server presents a different host key.
                using (GoPeer rogue = GoPeer.StartListening(c, "sshpeer", PeerArgs(k, SshSuite.Modern, k.Attacker, echo.Port)))
                {
                    Handshake h = Live.OpenClient(WireProtocol.Ssh, KexGroup.X25519, SshSuite.Modern, rogue.Port, "127.0.0.1", null, 8003, "a8-hostkey-attack");
                    Check.True(!h.Opened, "the client opened a channel to a server with a changed host key");
                    Check.Equal("failed check code", "SSH_HOST_KEY_CHANGED", h.FailedCode);
                    return "control opens; changed host key gives SSH_HOST_KEY_CHANGED";
                }
            }
        }

        // ---------------------------------------------------------------- Windows ssh.exe against our server (role ssh.server)

        [Clause("A8.ssh.exe-to-glass-server", PerBuild = true)]
        public static string SshExeToGlassServer(Ctx c)
        {
            string sshExe = Referees.SshExe(c);
            Keys k = Prepare(c, "a8-sshexe");
            OpenSshKey.RestrictToCurrentUser(k.ClientPem);
            string known = Path.Combine(k.Dir, "known_hosts");
            File.WriteAllText(known, "");
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            try
            {
                string args = "-F NUL -o BatchMode=yes -o UserKnownHostsFile=\"" + known + "\" -o StrictHostKeyChecking=no -o ConnectTimeout=20 -i \"" + k.ClientPem + "\" -p " + port + " training@127.0.0.1 echo hello";
                using (Proc ssh = Proc.Start(sshExe, args))
                {
                    IAsyncResult ar = listener.BeginAcceptSocket(null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(20000)) throw new FailException("ssh.exe never connected. Output: " + ssh.AllOutput);
                    Socket accepted = listener.EndAcceptSocket(ar);
                    Handshake h = Live.OpenServer(WireProtocol.Ssh, KexGroup.X25519, SshSuite.Modern, accepted, 8004, "a8-sshexe");
                    Check.True(h.Opened, "glass SSH server: " + h.Describe() + ". ssh.exe output: " + ssh.AllOutput);
                    Check.True(ssh.WaitExit(30000), "ssh.exe did not finish. Output: " + ssh.AllOutput);
                    Check.True(ssh.ExitCode == 0, "ssh.exe exited " + ssh.ExitCode + ". Output: " + ssh.AllOutput);
                    Check.True(ssh.AllOutput.Contains("hello"), "ssh.exe did not print 'hello'. Output: " + ssh.AllOutput);
                    return "ssh.exe ran 'echo hello' on our server and printed: " + ssh.AllOutput.Trim();
                }
            }
            finally { listener.Stop(); }
        }
    }
}
