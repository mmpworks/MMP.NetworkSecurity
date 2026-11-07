using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Pki;
using NetSec.Platform;
using NetSec.Ssh;

namespace NetSec.Host.Security;

/// <summary>
/// The my-ssh check (modes-design.md section 8). Windows ssh.exe connects to the course's own SSH server, which holds the learner's keys, with
/// StrictHostKeyChecking=yes and a pin made from the learner's host key, and runs echo hello. Each check also runs a control that ssh.exe must refuse:
/// a pin of another host key, or another user key. The key file ssh.exe reads is a copy for one reader, and it is deleted after the run.
/// </summary>
public sealed class SshExeCheck(Func<string, string?> env, int waitMs = SshExeCheck.DefaultWaitMs)
{
    public const string Judge = "ssh.exe", Says = "checked-with-ssh-exe";
    const string Pinned = @"C:\Windows\System32\OpenSSH\ssh.exe", Host = "127.0.0.1", Hello = "hello";
    const string Modern = "-o KexAlgorithms=curve25519-sha256 -o Ciphers=aes128-ctr -o MACs=hmac-sha2-256 -o HostKeyAlgorithms=ssh-ed25519";
    const string Legacy = "-o KexAlgorithms=diffie-hellman-group14-sha1 -o Ciphers=aes128-cbc -o MACs=hmac-sha1 -o HostKeyAlgorithms=ssh-rsa";
    public const int DefaultWaitMs = 20_000;

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

    /// <summary>
    /// The server is the course's own probe listener (Probe.Listen), on the learner's set. pinKeys give the host key the pin names, and userKey signs
    /// for the client. Every wait has a limit, so one run ends inside 2 x waitMs.
    /// </summary>
    Attempt Run(string ssh, SshSuite suite, CredentialSet server, ITrainingKeySource pinKeys, ITrainingKey userKey, string dir, string name)
    {
        string userFile = Path.Combine(dir, name + ".key"), pinFile = Path.Combine(dir, name + "-known_hosts");
        File.WriteAllText(userFile, "");
        try
        {
            // The ACL comes first, on the empty file, so the key bytes never sit under the folder's inherited ACL.
            if (!ToOneReader(userFile)) return new Attempt(OpenSslTool.CouldNotStart, "icacls could not limit the key file to one reader", "icacls");
            File.WriteAllText(userFile, OpenSshFile.Ed25519Private(userKey, "learner"));
            ProbeListener listener = Probe.Listen(new ProbeRequest { Protocol = WireProtocol.Ssh, Host = Host, SshSuite = suite, Credentials = server });
            File.WriteAllText(pinFile, SshSetup.KnownHostLine(pinKeys, suite, Host, listener.Port));
            string flags = suite == SshSuite.Legacy ? Legacy : Modern;
            string tail = $" -i \"{{0}}\" -p {listener.Port} {SshSetup.DefaultUser}@{Host} echo {Hello}";
            // -n: ssh.exe reads no stdin. Without it, ssh.exe inherits the Host's stdin, a pipe from whoever started the Host, and a run could wait on it.
            string head = $"-n -F NUL -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=\"{pinFile}\" -o ConnectTimeout=10 {flags}";
            string shown = "ssh.exe " + head.Replace(dir + Path.DirectorySeparatorChar, "") + string.Format(tail, name + ".key");
            Attempt done = RunSsh(ssh, head + string.Format(tail, userFile), dir, shown);
            if (!listener.Result.Wait(waitMs)) EndListener(listener.Port);
            return done;
        }
        finally
        {
            // A copy of the learner's private key leaves the store only for this run.
            File.Delete(userFile);
        }
    }

    Attempt RunSsh(string ssh, string arguments, string dir, string shown)
    {
        using Process? process = TryStart(new ProcessStartInfo(ssh, arguments) { WorkingDirectory = dir, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true });
        if (process is null) return new Attempt(OpenSslTool.CouldNotStart, "ssh.exe could not start", shown);
        Task<string> output = process.StandardOutput.ReadToEndAsync(), errors = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(waitMs))
        {
            process.Kill();
            return new Attempt(OpenSslTool.TimedOut, $"ssh.exe did not finish in {waitMs / 1000.0:0.#} s", shown);
        }
        return new Attempt(process.ExitCode, (output.Result + errors.Result).Trim(), shown);
    }

    /// <summary>A listener whose client never came waits for ever. One connection that closes at once ends it.</summary>
    static void EndListener(int port)
    {
        try { using TcpClient poke = new(); poke.Connect(IPAddress.Loopback, port); }
        catch (SocketException) { }
    }

    bool ToOneReader(string file)
    {
        using Process? icacls = TryStart(new ProcessStartInfo("icacls", $"\"{file}\" /inheritance:r /grant:r \"{Environment.UserName}:(R,W)\"") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true });
        if (icacls is null) return false;
        icacls.StandardOutput.ReadToEnd();
        return icacls.WaitForExit(waitMs) && icacls.ExitCode == 0;
    }

    static Process? TryStart(ProcessStartInfo info)
    {
        try { return Process.Start(info); }
        catch (System.ComponentModel.Win32Exception) { return null; }
    }
}
