#nullable enable
using System;
using System.IO;
using NetSec.Host.Security;
using NetSec.Keys;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>
/// SshExeCheck end to end with a fake ssh.exe, so each branch runs without OpenSSH: a pass, the 2 refusals, a control that is not refused, a control
/// refused for another reason, and a run that hits the time limit. WizardMachineTests runs the same check with the real ssh.exe.
/// </summary>
public class SshExeCheckTests
{
    const string Script = "@echo off\r\n"
        + "echo %* | findstr /c:\"other-pin\" >nul && goto pin\r\n"
        + "echo %* | findstr /c:\"other-user\" >nul && goto user\r\n"
        + "echo hello\r\n"
        + "exit /b 0\r\n"
        + ":pin\r\n"
        + "echo WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! 1>&2\r\n"
        + "exit /b 255\r\n"
        + ":user\r\n"
        + "echo training@127.0.0.1: Permission denied (publickey). 1>&2\r\n"
        + "exit /b 255\r\n";

    const int ShortWaitMs = 1500;

    static (CheckFact Fact, string Dir) Run(string script, string typeId)
    {
        string root = Path.Combine(Path.GetTempPath(), "netsec-fakessh-" + Guid.NewGuid().ToString("N"));
        string dir = Path.Combine(root, "proof");
        Directory.CreateDirectory(dir);
        string fake = Path.Combine(root, "ssh.cmd");
        File.WriteAllText(fake, script);
        SshExeCheck check = new(name => name == "NETSEC_SSH" ? fake : null, ShortWaitMs);
        return (check.Check(typeId, CredentialSet.BuiltIn(new TrainingKeySource()), dir), dir);
    }

    [Theory]
    [InlineData(SecurityTypes.SshHostEd25519, "REMOTE HOST IDENTIFICATION HAS CHANGED")]
    [InlineData(SecurityTypes.SshHostRsa, "REMOTE HOST IDENTIFICATION HAS CHANGED")]
    [InlineData(SecurityTypes.SshKnownHosts, "REMOTE HOST IDENTIFICATION HAS CHANGED")]
    [InlineData(SecurityTypes.SshClient, "Permission denied (publickey)")]
    public void A_run_that_says_hello_and_a_control_refused_for_its_own_reason_pass(string typeId, string refusal)
    {
        (CheckFact fact, string dir) = Run(Script, typeId);
        Assert.True(fact.Passed, fact.Message + " " + fact.Output + " | " + fact.ControlOutput);
        Assert.Contains("hello", fact.Output);
        Assert.Contains(refusal, fact.ControlOutput);
        Assert.Contains("-n ", fact.Command);
        Assert.Empty(Directory.GetFiles(dir, "*.key"));
    }

    [Fact]
    public void A_control_that_is_not_refused_fails_the_check()
    {
        (CheckFact fact, _) = Run("@echo off\r\necho hello\r\nexit /b 0\r\n", SecurityTypes.SshHostEd25519);
        Assert.Equal("CHECK_FAILED", fact.Code);
        Assert.Contains("did not refuse the control", fact.Message);
    }

    [Fact]
    public void A_control_refused_for_another_reason_fails_the_check()
    {
        string other = Script.Replace("Permission denied (publickey).", "Connection refused");
        (CheckFact fact, _) = Run(other, SecurityTypes.SshClient);
        Assert.Equal("CHECK_FAILED", fact.Code);
        Assert.Contains("Connection refused", fact.ControlOutput);
    }

    [Fact]
    public void A_run_that_never_ends_stops_at_the_limit_and_names_it()
    {
        (CheckFact fact, string dir) = Run("@echo off\r\nping -n 30 127.0.0.1 >nul\r\n", SecurityTypes.SshHostEd25519);
        Assert.Equal("CHECK_FAILED", fact.Code);
        Assert.Contains("did not finish in 1.5 s", fact.Output);
        Assert.Empty(Directory.GetFiles(dir, "*.key"));
    }

    /// <summary>The time limit stops the whole tree. A fake ssh.exe that starts a child must leave no child behind.</summary>
    [Fact]
    public void A_run_that_hits_the_limit_leaves_no_child_process()
    {
        // The child is a copy of ping under a name no other process on the machine has, so the count below sees this test's child only.
        string name = "netsec-child-" + Guid.NewGuid().ToString("N")[..12];
        string child = Path.Combine(Path.GetTempPath(), name + ".exe");
        File.Copy(Path.Combine(Environment.SystemDirectory, "PING.EXE"), child);
        Run($"@echo off\r\n\"{child}\" -n 30 127.0.0.1 >nul\r\n", SecurityTypes.SshHostEd25519);
        System.Threading.Thread.Sleep(500);
        Assert.Empty(System.Diagnostics.Process.GetProcessesByName(name));
    }
}
