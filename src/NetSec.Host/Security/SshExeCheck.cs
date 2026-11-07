using System.Diagnostics;
using System.Net;
using MMP.AsyncProxy;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Platform;
using NetSec.Ssh;
using NetSec.Trace;

namespace NetSec.Host.Security;

/// <summary>
/// The my-ssh check (modes-design.md section 8). Windows ssh.exe connects to the course's own SSH server, which holds the learner's keys, with
/// StrictHostKeyChecking=yes and a pin made from the learner's host key, and runs echo hello. Each check also runs a control that ssh.exe must refuse:
/// a pin of another host key, or another user key. The key file ssh.exe reads is a copy for one reader, and it is deleted after the run.
/// </summary>
public sealed class SshExeCheck(Func<string, string?> env)
{
    public const string Judge = "ssh.exe", Says = "checked-with-ssh-exe";
    const string Pinned = @"C:\Windows\System32\OpenSSH\ssh.exe", Host = "127.0.0.1", Hello = "hello";
    const string Modern = "-o KexAlgorithms=curve25519-sha256 -o Ciphers=aes128-ctr -o MACs=hmac-sha2-256 -o HostKeyAlgorithms=ssh-ed25519";
    const string Legacy = "-o KexAlgorithms=diffie-hellman-group14-sha1 -o Ciphers=aes128-cbc -o MACs=hmac-sha1 -o HostKeyAlgorithms=ssh-rsa";
    const int WaitMs = 30_000;

    // What ssh.exe prints when it refuses each control. Any other failure proves nothing about the key.
    const string HostKeyRefused = "REMOTE HOST IDENTIFICATION HAS CHANGED", UserKeyRefused = "Permission denied (publickey)";

    public string? Locate()
    {
        string? set = env("NETSEC_SSH");
        if (!string.IsNullOrEmpty(set)) return File.Exists(set) ? set : null;
        return File.Exists(Pinned) ? Pinned : null;
    }

    /// <summary>One check per type. A host key type runs its own suite; ssh.known-hosts and ssh.client run the modern one.</summary>
    public CheckFact Check(string typeId, CredentialSet mine, string dir)
    {
        string? ssh = Locate();
        if (ssh is null) return new CheckFact(typeId, Judge, Says, "ssh.exe", "", false, "REFEREE_MISSING", "The course cannot find ssh.exe. Set NETSEC_SSH to its path.");
        SshSuite suite = typeId == SecurityTypes.SshHostRsa ? SshSuite.Legacy : SshSuite.Modern;
        ITrainingKey userKey = mine.Find(KeyIds.SshClient), builtIn = new TrainingKeySource().Find(KeyIds.SshClient);
        bool clientCheck = typeId == SecurityTypes.SshClient;

        Attempt good = Run(ssh, suite, mine, mine, userKey, dir, "good");
        if (good.Code == OpenSslTool.CouldNotStart) return new CheckFact(typeId, Judge, Says, good.Shown, good.Output, false, "REFEREE_MISSING", "ssh.exe could not start.");
        if (good.Code != 0 || !good.Output.Contains(Hello, StringComparison.Ordinal))
            return new CheckFact(typeId, Judge, Says, good.Shown, good.Output, false, "CHECK_FAILED", "ssh.exe did not run a command on the course's server with these keys.");

        Attempt control = clientCheck
            ? Run(ssh, suite, mine, mine, builtIn, dir, "other-user")
            : Run(ssh, suite, mine, new TrainingKeySource(), userKey, dir, "other-pin");
        string refusal = clientCheck ? UserKeyRefused : HostKeyRefused;
        if (control.Code == 0 || !control.Output.Contains(refusal, StringComparison.OrdinalIgnoreCase))
            return new CheckFact(typeId, Judge, Says, good.Shown, good.Output, false, "CHECK_FAILED", "ssh.exe did not refuse the control, so this run proves nothing about the key.", control.Shown, control.Output);
        return new CheckFact(typeId, Judge, Says, good.Shown, good.Output, true, null, null, control.Shown, control.Output);
    }

    sealed record Attempt(int Code, string Output, string Shown);

    /// <summary>serverKeys hold the host key the server shows. pinKeys give the host key the pin names. userKey signs for the client.</summary>
    static Attempt Run(string ssh, SshSuite suite, ITrainingKeySource serverKeys, ITrainingKeySource pinKeys, ITrainingKey userKey, string dir, string name)
    {
        string userFile = Path.Combine(dir, name + ".key"), pinFile = Path.Combine(dir, name + "-known_hosts");
        File.WriteAllText(userFile, OpenSshFile.Ed25519Private(userKey, "learner"));
        try
        {
            if (!ToOneReader(userFile)) return new Attempt(OpenSslTool.CouldNotStart, "icacls could not limit the key file to one reader", "icacls");
            LinkListener socket = new(new IPEndPoint(IPAddress.Loopback, 0));
            int port = socket.Port;
            File.WriteAllText(pinFile, SshSetup.KnownHostLine(pinKeys, suite, Host, port));
            IFuture<SocketLink> accepted = socket.Accept();
            string flags = suite == SshSuite.Legacy ? Legacy : Modern;
            string tail = $" -i \"{{0}}\" -p {port} {SshSetup.DefaultUser}@{Host} echo {Hello}";
            string head = $"-F NUL -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=\"{pinFile}\" -o ConnectTimeout=20 {flags}";
            string shown = "ssh.exe " + head.Replace(dir + Path.DirectorySeparatorChar, "") + string.Format(tail, name + ".key");
            using Process? process = TryStart(new ProcessStartInfo(ssh, head + string.Format(tail, userFile)) { WorkingDirectory = dir, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true });
            if (process is null)
            {
                socket.Close();
                return new Attempt(OpenSslTool.CouldNotStart, "ssh.exe could not start", shown);
            }
            GlassSshSession? server = null;
            if (accepted.Wait(WaitMs))
            {
                SshServerOptions options = SshSetup.Server(serverKeys, suite, new OsRandom(), null);
                server = new GlassSshSession(SshEngine.Server(options, new TraceStream("check", "check", "check", null, "server", new MonotonicClock()), null, "client"),
                    accepted.Result, new ListSink(), new FreeRunGate(), null, WaitMs, null, null);
                server.Run();
            }
            socket.Close();
            Task<string> errors = process.StandardError.ReadToEndAsync();
            string output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(WaitMs))
            {
                process.Kill();
                return new Attempt(OpenSslTool.TimedOut, "ssh.exe did not finish in 30 s", shown);
            }
            server?.Finished.Wait(WaitMs);
            return new Attempt(process.ExitCode, (output + errors.Result).Trim(), shown);
        }
        finally
        {
            // A copy of the learner's private key leaves the store only for this run.
            File.Delete(userFile);
        }
    }

    static bool ToOneReader(string file)
    {
        using Process? icacls = TryStart(new ProcessStartInfo("icacls", $"\"{file}\" /inheritance:r /grant:r \"{Environment.UserName}:R\"") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true });
        if (icacls is null) return false;
        icacls.StandardOutput.ReadToEnd();
        return icacls.WaitForExit(WaitMs) && icacls.ExitCode == 0;
    }

    static Process? TryStart(ProcessStartInfo info)
    {
        try { return Process.Start(info); }
        catch (System.ComponentModel.Win32Exception) { return null; }
    }
}
