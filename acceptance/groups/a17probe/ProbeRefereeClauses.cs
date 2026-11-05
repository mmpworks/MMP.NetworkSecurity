using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using NetSec.Io;
using NetSec.Keys;

namespace Acceptance
{
    /// <summary>
    /// A17, slices V4 and V5: the learner's key judged from outside. The glass engines run on a CredentialSet the suite builds from files it made itself
    /// (modes-design.md section 3.3: ProbeRequest.Credentials and CredentialSet.FromFiles). OpenSSL, Go crypto/tls, ssh.exe and Go x/crypto/ssh are the other end.
    /// The product's own check is a help to the learner and no evidence here.
    /// The two members are reached by reflection, so this group compiles against a NetSec.Core that has not added them yet, and then every clause reads
    /// NOT RUN PRODUCT_MISSING by name. With --prop a17probe.training=1 the clauses use the training files and no Credentials, which proves the referee wiring
    /// on today's engines (the same keys as A5, A7 and A8, so it adds no verdict to M).
    /// </summary>
    public static class ProbeRefereeClauses
    {
        static bool Training(Ctx c) { return c.Prop("a17probe.training", "") == "1"; }

        // ---------------------------------------------------------------- the two members of the design, by reflection

        static object FromFiles(string dir)
        {
            Type t = typeof(ProbeRequest).Assembly.GetType("NetSec.Keys.CredentialSet");
            MethodInfo m = t == null ? null : t.GetMethod("FromFiles", BindingFlags.Public | BindingFlags.Static, null, new Type[] { typeof(string) }, null);
            if (m == null) throw new NotRunException("PRODUCT_MISSING", "NetSec.Core has no CredentialSet.FromFiles yet (modes-design.md section 3.3)");
            try { return m.Invoke(null, new object[] { dir }); }
            catch (TargetInvocationException ex) { throw new FailException("CredentialSet.FromFiles(" + dir + ") threw: " + ex.InnerException); }
        }

        static void Use(ProbeRequest r, object set)
        {
            if (set == null) return;
            FieldInfo f = typeof(ProbeRequest).GetField("Credentials");
            if (f == null) throw new NotRunException("PRODUCT_MISSING", "ProbeRequest has no Credentials yet (modes-design.md section 3.3)");
            f.SetValue(r, set);
        }

        // ---------------------------------------------------------------- keys the suite made

        sealed class TlsKeys { public string Root, WrongRoot, Dir, Srv, SrvKey; public object Set; }

        static TlsKeys MakeTls(Ctx c, string stem)
        {
            TlsKeys k = new TlsKeys();
            TestPki other = TestPki.Make(c, stem + "-other", new TestPki.Options { Client = false });
            k.WrongRoot = other.RootPem;
            if (Training(c))
            {
                PkiDir p = PkiDir.Export(c, stem);
                k.Root = p.Root; k.Srv = p.Cert; k.SrvKey = p.Key; k.Dir = p.Dir;
                return k;
            }
            TestPki pki = TestPki.Make(c, stem, new TestPki.Options());
            k.Root = pki.RootPem; k.Srv = pki.ServerPem; k.SrvKey = pki.ServerKey;
            k.Dir = pki.CredentialsDir(c, stem, false);
            k.Set = FromFiles(k.Dir);
            return k;
        }

        static string Keygen(Ctx c, string dir, string args)
        {
            string o;
            if (Proc.Run(Referees.SshKeygen(c), args, dir, 60000, out o) != 0) throw new FailException("ssh-keygen " + args + " failed: " + o.Trim());
            return o;
        }

        sealed class SshKeys { public string Dir, HostKey, UserKey, UserPub, OtherHostKey, OtherUserPub; public object Set; }

        static SshKeys MakeSsh(Ctx c, string stem)
        {
            SshKeys k = new SshKeys();
            if (Training(c))
            {
                PkiDir p = PkiDir.Export(c, stem);
                k.Dir = p.Dir; k.HostKey = p.HostKey; k.UserKey = p.UserKey; k.UserPub = p.UserPub;
            }
            else
            {
                k.Dir = LivePki.Dir(c, "a17probe-" + stem + "-creds");
                k.HostKey = Path.Combine(k.Dir, "host.key"); k.UserKey = Path.Combine(k.Dir, "user.key"); k.UserPub = Path.Combine(k.Dir, "user.pub");
                Keygen(c, k.Dir, "-q -t ed25519 -N \"\" -f \"" + k.HostKey + "\"");
                Keygen(c, k.Dir, "-q -t ed25519 -N \"\" -f \"" + k.UserKey + "\"");
                File.Copy(k.UserKey + ".pub", k.UserPub, true);
            }
            // A second host key and a second user key, for the controls.
            string other = LivePki.Dir(c, "a17probe-" + stem + "-other");
            k.OtherHostKey = Path.Combine(other, "host.key");
            Keygen(c, other, "-q -t ed25519 -N \"\" -f \"" + k.OtherHostKey + "\"");
            string otherUser = Path.Combine(other, "user.key");
            Keygen(c, other, "-q -t ed25519 -N \"\" -f \"" + otherUser + "\"");
            k.OtherUserPub = otherUser + ".pub";
            foreach (string f in new string[] { k.HostKey, k.UserKey, k.OtherHostKey, otherUser }) OpenSshKey.RestrictToCurrentUser(f);
            if (!Training(c)) k.Set = FromFiles(k.Dir);
            return k;
        }

        /// <summary>A known_hosts file for host:port from a private key file, by ssh-keygen -y (the referee's reading of the key).</summary>
        static string KnownHosts(Ctx c, string dir, string keyFile, int port, string name)
        {
            string output;
            int code = Proc.Run(Referees.SshKeygen(c), "-y -f \"" + keyFile + "\"", dir, 30000, out output);
            Check.True(code == 0 && output.Trim().StartsWith("ssh-"), "ssh-keygen -y refused " + keyFile + ": " + output.Trim());
            string[] parts = output.Trim().Split(' ');
            string path = Path.Combine(dir, name);
            File.WriteAllText(path, "[127.0.0.1]:" + port + " " + parts[0] + " " + parts[1] + "\n");
            return path;
        }

        // ---------------------------------------------------------------- TLS 1.3 server, judged by OpenSSL

        [Clause("A17.referee.tls13-server-openssl")]
        public static string Tls13ServerOpenssl(Ctx c)
        {
            TlsKeys k = MakeTls(c, "a17-t13srv");
            string good = Serve(c, k, k.Root, true), bad = Serve(c, k, k.WrongRoot, false);
            return "OpenSSL verifies the glass TLS 1.3 server's certificate under the root the suite made (" + good + ") and refuses it under another root (" + bad + ")";
        }

        static string Serve(Ctx c, TlsKeys k, string ca, bool expectOk)
        {
            ProbeRequest req = ProbeKit.Request(WireProtocol.Tls13, 0, "localhost");
            req.Group = KexGroup.X25519;
            req.Send = Encoding.ASCII.GetBytes("world\n");
            Use(req, k.Set);
            ProbeListener listener = Probe.Listen(req);
            Check.True(listener != null && listener.Port > 0, "Probe.Listen returned no port");
            using (Proc peer = OpenSslPeer.StartClient(c, "-connect 127.0.0.1:" + listener.Port + " -tls1_3 -groups X25519 -servername localhost -CAfile \"" + ca + "\" -verify_return_error -verify_hostname localhost -brief").P)
            {
                peer.WriteLine("hello");
                if (expectOk)
                {
                    ProbeResult r = Futs.Get(listener.Result, 60000, "glass TLS 1.3 server");
                    Check.True(r.Completed, "glass TLS 1.3 server stopped: " + r.CheckName + " [" + r.Code + "]. OpenSSL output: " + peer.AllOutput);
                    Check.True(Encoding.ASCII.GetString(r.Received ?? new byte[0]).Contains("hello"), "the server received no hello");
                    Check.True(peer.WaitForLine(delegate (string l) { return l.Contains("world"); }, 15000) != null, "OpenSSL never printed 'world'. Output: " + peer.AllOutput);
                    Check.True(peer.AllOutput.Contains("Verification: OK"), "OpenSSL did not verify the server certificate under the suite's root. Output: " + peer.AllOutput);
                    return "Verification: OK";
                }
                // Control: the same server under a root that did not sign its certificate. OpenSSL stops the handshake.
                peer.WaitForLine(delegate (string l) { return l.IndexOf("verify error", StringComparison.OrdinalIgnoreCase) >= 0 || l.Contains("Verification error"); }, 20000);
                string report = peer.AllOutput;
                Check.True(!report.Contains("Verification: OK"), "control: OpenSSL verified the certificate under a root that never signed it. Output: " + report);
                Check.True(report.IndexOf("verify error", StringComparison.OrdinalIgnoreCase) >= 0 || report.Contains("Verification error"), "control: OpenSSL named no verify error. Output: " + report);
                return "verify error under the other root";
            }
        }

        // ---------------------------------------------------------------- TLS 1.1 server, judged by OpenSSL

        [Clause("A17.referee.tls11-server-openssl")]
        public static string Tls11ServerOpenssl(Ctx c)
        {
            TlsKeys k = MakeTls(c, "a17-t11srv");
            ProbeRequest req = ProbeKit.Request(WireProtocol.Tls11, 0, "localhost");
            req.Suite = "TLS_RSA_WITH_AES_128_CBC_SHA";
            Use(req, k.Set);
            ProbeListener listener = Probe.Listen(req);
            Check.True(listener != null && listener.Port > 0, "Probe.Listen returned no port");
            string rootFile = Training(c) ? k.Root : k.Root;
            using (Proc client = OpenSslPeer.StartClient(c, "-tls1_1 -cipher AES128-SHA:@SECLEVEL=0 -CAfile \"" + rootFile + "\" -verify_return_error -verify_hostname localhost -connect 127.0.0.1:" + listener.Port).P)
            {
                client.WriteLine("hello");
                ProbeResult r = Futs.Get(listener.Result, 60000, "glass TLS 1.1 server");
                Check.True(r.Completed, "glass TLS 1.1 server stopped: " + r.CheckName + " [" + r.Code + "]. OpenSSL output: " + client.AllOutput);
                Check.True(Encoding.ASCII.GetString(r.Received ?? new byte[0]).Contains("hello"), "the server received no hello");
                client.WaitForLine(delegate (string l) { return l.Contains("Verify return code"); }, 20000);
                string output = client.AllOutput;
                Check.True(System.Text.RegularExpressions.Regex.IsMatch(output, @"Protocol\s*:\s*TLSv1\.1"), "OpenSSL did not report TLSv1.1. Output: " + output);
                Check.True(output.Contains("Verify return code: 0 (ok)"), "OpenSSL did not verify the server certificate under the suite's root. Output: " + output);
            }
            // Control: the same server under a root that did not sign its certificate.
            ProbeRequest req2 = ProbeKit.Request(WireProtocol.Tls11, 0, "localhost");
            req2.Suite = "TLS_RSA_WITH_AES_128_CBC_SHA";
            Use(req2, k.Set);
            ProbeListener l2 = Probe.Listen(req2);
            using (Proc bad = OpenSslPeer.StartClient(c, "-tls1_1 -cipher AES128-SHA:@SECLEVEL=0 -CAfile \"" + k.WrongRoot + "\" -verify_return_error -verify_hostname localhost -connect 127.0.0.1:" + l2.Port).P)
            {
                bad.WriteLine("hello");
                bad.WaitForLine(delegate (string l) { return l.IndexOf("verify error", StringComparison.OrdinalIgnoreCase) >= 0 || l.Contains("Verify return code"); }, 20000);
                Check.True(!bad.AllOutput.Contains("Verify return code: 0 (ok)"), "control: OpenSSL verified the TLS 1.1 certificate under a root that never signed it. Output: " + bad.AllOutput);
            }
            return "OpenSSL reports TLSv1.1 and verify code 0 for the learner's RSA key under the suite's root, and refuses it under another root";
        }

        // ---------------------------------------------------------------- TLS 1.3 client with an intermediate, judged by Go crypto/tls

        [Clause("A17.referee.tls13-client-go-with-intermediate")]
        public static string Tls13ClientGoWithIntermediate(Ctx c)
        {
            if (Training(c)) throw new NotRunException("NOT_APPLICABLE", "the training PKI has no intermediate CA; this clause has no self-proof mode");
            TestPki pki = TestPki.Make(c, "a17-t13cli", new TestPki.Options { Intermediate = true });
            string with = pki.CredentialsDir(c, "a17-t13cli-with", true), leafOnly = pki.CredentialsDir(c, "a17-t13cli-leaf", false);
            object setWith = FromFiles(with), setLeaf = FromFiles(leafOnly);

            // With the intermediate sent after the leaf, Go accepts the client certificate.
            string serverArgs = "-mode server -listen 127.0.0.1:0 -naccept 1 -groups x25519 -cert \"" + pki.ServerPem + "\" -key \"" + pki.ServerKey + "\" -require-client-cert -ca \"" + pki.RootPem + "\"";
            using (GoPeer go = GoPeer.StartListening(c, "tlspeer", serverArgs))
            {
                ProbeRequest req = ProbeKit.Request(WireProtocol.Tls13, go.Port, "localhost");
                req.Group = KexGroup.X25519;
                req.Send = Encoding.ASCII.GetBytes("hello\n");
                Use(req, setWith);
                ProbeResult r = ProbeKit.Connect(req, "glass TLS 1.3 client with a client certificate and its intermediate");
                Check.True(r.Completed, "the glass client with leaf and intermediate was refused by Go: " + r.CheckName + " [" + r.Code + "]. Go output: " + go.Output);
                Check.True(go.WaitEvent("handshake", 15000) != null, "tlspeer printed no handshake event. Output: " + go.Output);
            }
            // Control: the leaf alone. Go cannot build the chain to the root and refuses the client.
            using (GoPeer go = GoPeer.StartListening(c, "tlspeer", serverArgs))
            {
                ProbeRequest req = ProbeKit.Request(WireProtocol.Tls13, go.Port, "localhost");
                req.Group = KexGroup.X25519;
                req.Send = Encoding.ASCII.GetBytes("hello\n");
                Use(req, setLeaf);
                ProbeResult r = ProbeKit.Connect(req, "glass TLS 1.3 client with a leaf only");
                Check.True(!r.Completed, "control: Go accepted a client leaf whose intermediate was not sent");
            }
            return "Go crypto/tls accepts the glass client's certificate when its intermediate is sent after the leaf, and refuses the leaf alone";
        }

        // ---------------------------------------------------------------- SSH host key, judged by ssh.exe

        [Clause("A17.referee.ssh-host-ssh-exe")]
        public static string SshHostSshExe(Ctx c)
        {
            string sshExe = Referees.SshExe(c);
            SshKeys k = MakeSsh(c, "a17-sshhost");
            string good = RunSshExe(c, sshExe, k, k.HostKey, true), bad = RunSshExe(c, sshExe, k, k.OtherHostKey, false);
            return "ssh.exe, pinned to the learner's host key, " + good + "; pinned to another key it " + bad;
        }

        static string RunSshExe(Ctx c, string sshExe, SshKeys k, string pinnedKey, bool expectOk)
        {
            ProbeRequest req = ProbeKit.Request(WireProtocol.Ssh, 0, "127.0.0.1");
            req.SshSuite = SshSuite.Modern;
            Use(req, k.Set);
            ProbeListener listener = Probe.Listen(req);
            Check.True(listener != null && listener.Port > 0, "Probe.Listen returned no port");
            string known = KnownHosts(c, k.Dir, pinnedKey, listener.Port, "known_hosts_" + (expectOk ? "good" : "other"));
            string args = "-F NUL -o BatchMode=yes -o UserKnownHostsFile=\"" + known + "\" -o StrictHostKeyChecking=yes -o ConnectTimeout=20 -i \"" + k.UserKey + "\" -p " + listener.Port + " training@127.0.0.1 echo hello";
            using (Proc ssh = Proc.Start(sshExe, args))
            {
                if (expectOk)
                {
                    ProbeResult r = Futs.Get(listener.Result, 60000, "glass SSH server");
                    Check.True(r.Completed, "glass SSH server stopped: " + r.CheckName + " [" + r.Code + "]. ssh.exe output: " + ssh.AllOutput);
                    Check.True(ssh.WaitExit(30000) && ssh.ExitCode == 0, "ssh.exe exited " + ssh.ExitCode + " against the learner's host key. Output: " + ssh.AllOutput);
                    Check.True(ssh.AllOutput.Contains("hello"), "ssh.exe did not print hello. Output: " + ssh.AllOutput);
                    return "ran echo hello";
                }
                Check.True(ssh.WaitExit(40000), "control: ssh.exe did not finish. Output: " + ssh.AllOutput);
                Check.True(ssh.ExitCode != 0, "control: ssh.exe went on although the pinned host key is another key. Output: " + ssh.AllOutput);
                Check.True(ssh.AllOutput.IndexOf("Host key verification failed", StringComparison.OrdinalIgnoreCase) >= 0 || ssh.AllOutput.IndexOf("IDENTIFICATION HAS CHANGED", StringComparison.OrdinalIgnoreCase) >= 0,
                    "control: ssh.exe failed, but not on the host key. Output: " + ssh.AllOutput);
                return "stopped on the host key";
            }
        }

        // ---------------------------------------------------------------- SSH client key, judged by Go x/crypto/ssh

        [Clause("A17.referee.ssh-client-go")]
        public static string SshClientGo(Ctx c)
        {
            SshKeys k = MakeSsh(c, "a17-sshcli");
            string goHost = Path.Combine(LivePki.Dir(c, "a17probe-gohost"), "gohost.key");
            Keygen(c, Path.GetDirectoryName(goHost), "-q -t ed25519 -N \"\" -f \"" + goHost + "\"");
            string good = ClientVsGo(c, k, goHost, k.UserPub, true), bad = ClientVsGo(c, k, goHost, k.OtherUserPub, false);
            return "Go x/crypto/ssh " + good + " the glass client's key, and " + bad + " a Go server that authorizes another key";
        }

        static string ClientVsGo(Ctx c, SshKeys k, string goHost, string authorizedPub, bool expectOk)
        {
            string args = "-listen 127.0.0.1:0 -naccept 1 -authorized \"" + authorizedPub + "\" -host-key \"" + goHost + "\" -kex curve25519-sha256 -cipher aes128-ctr -mac hmac-sha2-256";
            using (GoPeer peer = GoPeer.StartListening(c, "sshpeer", args))
            {
                ProbeRequest req = ProbeKit.Request(WireProtocol.Ssh, peer.Port, "127.0.0.1");
                req.SshSuite = SshSuite.Modern;
                req.KnownHostsFile = KnownHosts(c, k.Dir, goHost, peer.Port, "known_hosts_go_" + (expectOk ? "good" : "other"));
                req.ClientKeyId = KeyIds.SshClient;
                req.ExecCommand = "echo hello";
                Use(req, k.Set);
                ProbeResult r = ProbeKit.Connect(req, "glass SSH client against Go x/crypto/ssh");
                if (expectOk)
                {
                    Check.True(r.Completed, "the glass SSH client with the learner's key was refused by Go: " + r.CheckName + " [" + r.Code + "]. Go output: " + peer.Output);
                    Check.True(Encoding.ASCII.GetString(r.Received ?? new byte[0]).Contains("hello"), "exec returned '" + Encoding.ASCII.GetString(r.Received ?? new byte[0]).Trim() + "'");
                    Check.True(peer.WaitEvent("handshake", 15000) != null, "sshpeer printed no handshake event. Output: " + peer.Output);
                    return "accepts";
                }
                Check.True(!r.Completed, "control: Go accepted a client key it did not authorize");
                return "refuses";
            }
        }
    }
}
