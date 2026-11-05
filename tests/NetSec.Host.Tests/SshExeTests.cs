using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using MMP.AsyncProxy;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Platform;
using NetSec.Ssh;
using NetSec.Trace;
using Xunit;

namespace NetSec.Host.Tests
{
    /// <summary>
    /// Windows ssh.exe against our server, past what A8 asks: the legacy suite, and a tunnel through -W. OpenSSH refuses ssh-rsa unless told, so the
    /// flags turn on each old name. A pinned ssh.exe that has gone fails here. It does not skip, because a skip hides a lost referee.
    /// </summary>
    public class SshExeTests
    {
        const string SshExe = @"C:\Windows\System32\OpenSSH\ssh.exe";
        const string LegacyFlags = "-o KexAlgorithms=diffie-hellman-group14-sha1 -o Ciphers=aes128-cbc -o MACs=hmac-sha1 -o HostKeyAlgorithms=ssh-rsa";
        const string ModernFlags = "-o KexAlgorithms=curve25519-sha256 -o Ciphers=aes128-ctr -o MACs=hmac-sha2-256 -o HostKeyAlgorithms=ssh-ed25519";

        static string KeyFolder()
        {
            string dir = Path.Combine(Path.GetTempPath(), "netsec-ssh-" + Guid.NewGuid().ToString("N"));
            TrainingPki.Export(dir);
            Process icacls = Process.Start(new ProcessStartInfo("icacls", "\"" + Path.Combine(dir, "user.key") + "\" /inheritance:r /grant:r \"" + Environment.UserName + ":R\"") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true })!;
            icacls.StandardOutput.ReadToEnd();
            icacls.WaitForExit();
            Assert.Equal(0, icacls.ExitCode);
            return dir;
        }

        static Process Ssh(string dir, int port, string flags, string tail, bool stdin)
        {
            string args = "-F NUL -o BatchMode=yes -o UserKnownHostsFile=\"" + Path.Combine(dir, "known_hosts") + "\" -o StrictHostKeyChecking=no -o ConnectTimeout=20 " + flags
                + " -i \"" + Path.Combine(dir, "user.key") + "\" -p " + port + " training@127.0.0.1 " + tail;
            return Process.Start(new ProcessStartInfo(SshExe, args) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = stdin, CreateNoWindow = true })!;
        }

        [Theory]
        [InlineData(SshSuite.Modern, ModernFlags)]
        [InlineData(SshSuite.Legacy, LegacyFlags)]
        public void Ssh_exe_runs_a_command_on_our_server(SshSuite suite, string flags)
        {
            string dir = KeyFolder();
            ProbeListener listener = Probe.Listen(new ProbeRequest { Protocol = WireProtocol.Ssh, Host = "127.0.0.1", SshSuite = suite, Seed = 11 });
            using Process ssh = Ssh(dir, listener.Port, flags, "echo hello", false);
            string output = ssh.StandardOutput.ReadToEnd();
            string errors = ssh.StandardError.ReadToEnd();
            Assert.True(ssh.WaitForExit(30000), "ssh.exe did not finish");
            Assert.True(ssh.ExitCode == 0, "ssh.exe exited " + ssh.ExitCode + ": " + errors);
            Assert.Equal("hello\n", output.Replace("\r\n", "\n"));
            Assert.True(listener.Result.Wait(30000), "the server did not finish");
            Assert.True(listener.Result.Result.Completed, listener.Result.Result.Code + " " + listener.Result.Result.CheckName);
            Assert.Equal("on", listener.Result.Result.Events.Single(e => e.Type == "ssh.kex.strict").Message);
        }

        /// <summary>
        /// Our server leaves the strict KEX marker out, so OpenSSH must run the old rules with it: no sequence reset, on either side. This is outside
        /// code on the old device's path, from one side only. No peer without its own marker exists on this machine: docs/lesson-ssh-names.md.
        /// </summary>
        [Theory]
        [InlineData(SshSuite.Modern, ModernFlags)]
        [InlineData(SshSuite.Legacy, LegacyFlags)]
        public void Ssh_exe_runs_a_command_on_our_server_with_strict_kex_off(SshSuite suite, string flags)
        {
            string dir = KeyFolder();
            LinkListener socket = new LinkListener(new IPEndPoint(IPAddress.Loopback, 0));
            IFuture<SocketLink> accepted = socket.Accept();
            using Process ssh = Ssh(dir, socket.Port, flags, "echo hello", false);
            Assert.True(accepted.Wait(30000), "ssh.exe did not connect");
            socket.Close();

            TrainingKeySource keys = new TrainingKeySource();
            SshServerOptions options = SshSetup.Server(keys, suite, new SeededRandom(21), null);
            options.NoStrictKex = true;
            ListSink sink = new ListSink();
            GlassSshSession server = new GlassSshSession(SshEngine.Server(options, new TraceStream("s", "s", "s", null, "server", new MonotonicClock()), null, "client"), accepted.Result, sink, new FreeRunGate(), null, 30000, null, null);
            server.Run();

            string output = ssh.StandardOutput.ReadToEnd();
            string errors = ssh.StandardError.ReadToEnd();
            Assert.True(ssh.WaitForExit(30000), "ssh.exe did not finish");
            Assert.True(ssh.ExitCode == 0, "ssh.exe exited " + ssh.ExitCode + ": " + errors);
            Assert.Equal("hello\n", output.Replace("\r\n", "\n"));
            Assert.True(server.Finished.Wait(30000), "the server did not finish");
            Assert.Null(server.Finished.Result.Error);
            Assert.Equal("off", sink.Events.Single(e => e.Type == "ssh.kex.strict").Message);
        }

        [Fact]
        public void Ssh_exe_carries_bytes_through_a_tunnel_on_our_server_and_the_allow_list_holds()
        {
            string dir = KeyFolder();
            TcpListener echo = new TcpListener(IPAddress.Loopback, 0);
            echo.Start();
            int echoPort = ((IPEndPoint)echo.LocalEndpoint).Port;
            Thread echoThread = new Thread(() =>
            {
                using TcpClient peer = echo.AcceptTcpClient();
                NetworkStream stream = peer.GetStream();
                byte[] buffer = new byte[256];
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0) stream.Write(buffer, 0, read);
            }) { IsBackground = true };
            echoThread.Start();

            ProbeListener listener = Probe.Listen(new ProbeRequest { Protocol = WireProtocol.Ssh, Host = "127.0.0.1", SshSuite = SshSuite.Modern, TunnelTo = "127.0.0.1:" + echoPort, Seed = 12 });
            using (Process ssh = Ssh(dir, listener.Port, ModernFlags, "-W 127.0.0.1:" + echoPort, true))
            {
                ssh.StandardInput.Write("ping\n");
                ssh.StandardInput.Flush();
                string reply = ssh.StandardOutput.ReadLine() ?? "";
                Assert.Equal("ping", reply);
                ssh.StandardInput.Close();
                Assert.True(ssh.WaitForExit(30000), "ssh.exe did not finish");
            }
            Assert.True(listener.Result.Wait(30000), "the server did not finish");
            echo.Stop();

            ProbeListener strict = Probe.Listen(new ProbeRequest { Protocol = WireProtocol.Ssh, Host = "127.0.0.1", SshSuite = SshSuite.Modern, Seed = 13 });
            using (Process refused = Ssh(dir, strict.Port, ModernFlags, "-W 127.0.0.1:" + echoPort, true))
            {
                string errors = refused.StandardError.ReadToEnd();
                Assert.True(refused.WaitForExit(30000), "ssh.exe did not finish");
                Assert.NotEqual(0, refused.ExitCode);
                Assert.Contains("administratively prohibited", errors);
            }
            Assert.True(strict.Result.Wait(30000), "the server did not finish");
        }
    }
}
