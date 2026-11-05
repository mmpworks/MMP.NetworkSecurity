using System;
using System.IO;
using System.Text;
using NetSec.Io;
using NetSec.Keys;

namespace Acceptance
{
    /// <summary>
    /// A8: the glass SSH client, reached through Probe (design section 11), runs one exec and one tunnel against a Go x/crypto/ssh server
    /// (the sshpeer referee), on the modern suite and on the legacy suite (diffie-hellman-group14-sha1, aes128-cbc, hmac-sha1, old RSA host key).
    /// A changed host key gives SSH_HOST_KEY_CHANGED beside a passing control. Windows ssh.exe works against our server (role ssh.server).
    /// The referee prints one handshake event per connection, so the algorithms in use are the referee's word.
    /// The known_hosts line comes from ssh-keygen -y on the key file the product exported, so the expected key has no product code in it.
    /// Command lines and event fields: acceptance/referees/README.md.
    /// </summary>
    public static class SshClauses
    {
        static string PeerArgs(PkiDir p, SshSuite suite, string hostKey, int tunnelPort)
        {
            string common = "-listen 127.0.0.1:0 -naccept 1 -authorized \"" + p.UserPub + "\" -allow-tunnel 127.0.0.1:" + tunnelPort + " -host-key \"" + hostKey + "\"";
            return suite == SshSuite.Modern
                ? common + " -kex curve25519-sha256 -cipher aes128-ctr -mac hmac-sha2-256"
                : common + " -kex diffie-hellman-group14-sha1 -cipher aes128-cbc -mac hmac-sha1 -host-key-alg ssh-rsa";
        }

        /// <summary>Writes a known_hosts file for host:port from the private key file, using ssh-keygen -y (the referee's reading of the key).</summary>
        static string KnownHosts(Ctx c, string dir, string keyFile, int port, string name)
        {
            string keygen = Referees.SshKeygen(c);
            OpenSshKey.RestrictToCurrentUser(keyFile);
            string output;
            int code = Proc.Run(keygen, "-y -f \"" + keyFile + "\"", dir, 30000, out output);
            Check.True(code == 0 && output.Trim().StartsWith("ssh-"), "ssh-keygen -y refused " + keyFile + ": " + output.Trim());
            string[] parts = output.Trim().Split(' ');
            string path = Path.Combine(dir, name);
            File.WriteAllText(path, "[127.0.0.1]:" + port + " " + parts[0] + " " + parts[1] + "\n");
            return path;
        }

        static ProbeRequest Client(int port, SshSuite suite, string knownHosts)
        {
            ProbeRequest r = ProbeKit.Request(WireProtocol.Ssh, port, "127.0.0.1");
            r.SshSuite = suite;
            r.KnownHostsFile = knownHosts;
            r.ClientKeyId = KeyIds.SshClient;
            return r;
        }

        static void Negotiated(GoPeer peer, SshSuite suite)
        {
            Dictionary_Event hs = new Dictionary_Event(peer.WaitEvent("handshake", 15000));
            Check.True(hs.Value != null, "sshpeer printed no handshake event. Output: " + peer.Output);
            if (suite == SshSuite.Modern)
            {
                Check.Equal("kex", "curve25519-sha256", hs.S("kex"));
                Check.Equal("cipher", "aes128-ctr", hs.S("cipherC2S"));
                Check.Equal("mac", "hmac-sha2-256", hs.S("macC2S"));
                Check.Equal("host key", "ssh-ed25519", hs.S("hostKey"));
            }
            else
            {
                Check.Equal("kex", "diffie-hellman-group14-sha1", hs.S("kex"));
                Check.Equal("cipher", "aes128-cbc", hs.S("cipherC2S"));
                Check.Equal("mac", "hmac-sha1", hs.S("macC2S"));
                Check.Equal("host key", "ssh-rsa", hs.S("hostKey"));
            }
        }

        sealed class Dictionary_Event
        {
            public readonly System.Collections.Generic.Dictionary<string, object> Value;
            public Dictionary_Event(System.Collections.Generic.Dictionary<string, object> v) { Value = v; }
            public string S(string key) { return MiniJson.Str(Value, key); }
        }

        static string ExecOrTunnel(Ctx c, SshSuite suite, bool exec, string stem)
        {
            PkiDir p = PkiDir.Export(c, stem);
            string hostKey = suite == SshSuite.Modern ? p.HostKey : p.RsaHostKey;
            using (EchoServer echo = new EchoServer())
            using (GoPeer peer = GoPeer.StartListening(c, "sshpeer", PeerArgs(p, suite, hostKey, echo.Port)))
            {
                ProbeRequest req = Client(peer.Port, suite, KnownHosts(c, p.Dir, hostKey, peer.Port, "known_hosts"));
                if (exec) req.ExecCommand = "echo hello";
                else { req.TunnelTo = "127.0.0.1:" + echo.Port; req.Send = Encoding.ASCII.GetBytes("ping-through-tunnel"); }
                ProbeResult r = ProbeKit.Connect(req, "glass SSH client (" + suite + ") against Go x/crypto/ssh");
                Check.True(r.Completed, "glass SSH client (" + suite + ") against Go x/crypto/ssh stopped: " + r.CheckName + " [" + r.Code + "]");
                string got = Encoding.ASCII.GetString(r.Received ?? new byte[0]);
                if (exec) Check.True(got.Contains("hello"), "exec returned '" + got.Trim() + "'");
                else
                {
                    Check.True(got.Contains("ping-through-tunnel"), "the tunnel returned '" + got.Trim() + "'");
                    Check.True(echo.Connections >= 1, "the echo server never saw a connection, so the bytes did not travel through the tunnel");
                }
                Negotiated(peer, suite);
                return (exec ? "exec returned '" + got.Trim() + "'" : "tunnel echoed " + echo.BytesEchoed + " bytes") + "; referee confirms the " + suite + " suite";
            }
        }

        [Clause("A8.ssh.modern.exec", PerBuild = true)]
        public static string ModernExec(Ctx c) { return ExecOrTunnel(c, SshSuite.Modern, true, "a8-modern-exec"); }

        [Clause("A8.ssh.modern.tunnel", PerBuild = true)]
        public static string ModernTunnel(Ctx c) { return ExecOrTunnel(c, SshSuite.Modern, false, "a8-modern-tunnel"); }

        [Clause("A8.ssh.legacy.exec", PerBuild = true)]
        public static string LegacyExec(Ctx c) { return ExecOrTunnel(c, SshSuite.Legacy, true, "a8-legacy-exec"); }

        [Clause("A8.ssh.legacy.tunnel", PerBuild = true)]
        public static string LegacyTunnel(Ctx c) { return ExecOrTunnel(c, SshSuite.Legacy, false, "a8-legacy-tunnel"); }

        [Clause("A8.ssh.hostkey-changed-beside-control", PerBuild = true)]
        public static string HostKeyChanged(Ctx c)
        {
            PkiDir p = PkiDir.Export(c, "a8-hostkey");
            // The rogue key comes from ssh-keygen, so the attacker's key has no product code in it.
            string rogue = Path.Combine(p.Dir, "rogue_ed25519");
            foreach (string old in new string[] { rogue, rogue + ".pub" }) if (File.Exists(old)) File.Delete(old);      // ssh-keygen asks before it overwrites
            string output;
            int code = Proc.Run(Referees.SshKeygen(c), "-q -t ed25519 -N \"\" -f \"" + rogue + "\"", p.Dir, 30000, out output);
            Check.True(code == 0, "ssh-keygen could not make the rogue key: " + output.Trim());
            using (EchoServer echo = new EchoServer())
            {
                // Control: the host key the client expects.
                using (GoPeer good = GoPeer.StartListening(c, "sshpeer", PeerArgs(p, SshSuite.Modern, p.HostKey, echo.Port)))
                {
                    ProbeRequest req = Client(good.Port, SshSuite.Modern, KnownHosts(c, p.Dir, p.HostKey, good.Port, "known_hosts_control"));
                    req.ExecCommand = "echo hello";
                    ProbeResult ok = ProbeKit.Connect(req, "control (expected host key)");
                    Check.True(ok.Completed, "control run (expected host key) stopped: " + ok.CheckName + " [" + ok.Code + "]");
                }
                // Attack: one thing differs, the server presents a different host key. known_hosts still names the expected key.
                using (GoPeer bad = GoPeer.StartListening(c, "sshpeer", PeerArgs(p, SshSuite.Modern, rogue, echo.Port)))
                {
                    string known = Path.Combine(p.Dir, "known_hosts_attack");
                    string expected = File.ReadAllText(KnownHosts(c, p.Dir, p.HostKey, bad.Port, "known_hosts_attack_src"));
                    File.WriteAllText(known, expected);
                    ProbeRequest req = Client(bad.Port, SshSuite.Modern, known);
                    req.ExecCommand = "echo hello";
                    ProbeResult r = ProbeKit.Connect(req, "attack (changed host key)");
                    Check.True(!r.Completed, "the client completed a session with a server that has a changed host key");
                    Check.Equal("failed check code", "SSH_HOST_KEY_CHANGED", r.Code);
                    return "control opens; changed host key gives SSH_HOST_KEY_CHANGED";
                }
            }
        }

        // ---------------------------------------------------------------- Windows ssh.exe against our server (role ssh.server)

        [Clause("A8.ssh.exe-to-glass-server", PerBuild = true)]
        public static string SshExeToGlassServer(Ctx c)
        {
            string sshExe = Referees.SshExe(c);
            PkiDir p = PkiDir.Export(c, "a8-sshexe");
            OpenSshKey.RestrictToCurrentUser(p.UserKey);
            string known = Path.Combine(p.Dir, "known_hosts");
            File.WriteAllText(known, "");
            ProbeRequest req = ProbeKit.Request(WireProtocol.Ssh, 0, "127.0.0.1");
            req.SshSuite = SshSuite.Modern;
            ProbeListener listener = Probe.Listen(req);
            Check.True(listener != null && listener.Port > 0, "Probe.Listen returned no port");
            string args = "-F NUL -o BatchMode=yes -o UserKnownHostsFile=\"" + known + "\" -o StrictHostKeyChecking=no -o ConnectTimeout=20 -i \"" + p.UserKey + "\" -p " + listener.Port + " training@127.0.0.1 echo hello";
            using (Proc ssh = Proc.Start(sshExe, args))
            {
                ProbeResult r = Futs.Get(listener.Result, 60000, "glass SSH server");
                Check.True(r.Completed, "glass SSH server stopped: " + r.CheckName + " [" + r.Code + "]. ssh.exe output: " + ssh.AllOutput);
                Check.True(ssh.WaitExit(30000), "ssh.exe did not finish. Output: " + ssh.AllOutput);
                Check.True(ssh.ExitCode == 0, "ssh.exe exited " + ssh.ExitCode + ". Output: " + ssh.AllOutput);
                Check.True(ssh.AllOutput.Contains("hello"), "ssh.exe did not print 'hello'. Output: " + ssh.AllOutput);
                return "ssh.exe ran 'echo hello' on our server and printed: " + ssh.AllOutput.Trim();
            }
        }
    }
}
