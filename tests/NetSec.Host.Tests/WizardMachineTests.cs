#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using NetSec.Host.Security;
using NetSec.Keys;
using Xunit;

namespace NetSec.Host.Tests;

public class WizardMachineTests
{
    static readonly string FlowsFile = Path.Combine(AppContext.BaseDirectory, "wizard-flows.json");

    [Fact]
    public void The_five_flows_cover_all_fifteen_types_once_each()
    {
        WizardTable table = WizardTable.Load(FlowsFile);
        Assert.Equal(5, table.Flows.Count);
        string[] listed = table.Flows.SelectMany(f => f.Types).OrderBy(t => t, StringComparer.Ordinal).ToArray();
        Assert.Equal(SecurityTypes.All.OrderBy(t => t, StringComparer.Ordinal).ToArray(), listed);
    }

    [Fact]
    public void Every_state_can_end_and_every_non_final_state_can_cancel()
    {
        WizardTable table = WizardTable.Load(FlowsFile);
        foreach (string state in table.Rows.Select(r => r.From).Distinct())
            Assert.Contains("cancel", table.AllowedFrom(state));
    }

    [Fact]
    public void A_row_with_an_unknown_guard_stops_the_load()
    {
        const string Json = """{"flows":[],"states":[{"state":"A","kind":"explain"}],"spine":[{"from":"A","event":"x","to":"A","guard":"nope"}]}""";
        Assert.Throws<InvalidDataException>(() => WizardTable.Parse(Json));
    }

    [Fact]
    public void A_row_to_an_unknown_state_stops_the_load()
    {
        const string Json = """{"flows":[],"states":[{"state":"A","kind":"explain"}],"spine":[{"from":"A","event":"x","to":"B"}]}""";
        Assert.Throws<InvalidDataException>(() => WizardTable.Parse(Json));
    }

    [Fact]
    public void An_event_with_no_row_is_refused_and_names_the_state_and_the_event()
    {
        WizardDecision d = WizardMachine.Decide(WizardTable.Load(FlowsFile), "Intro", "check", false);
        Assert.Null(d.Row);
        Assert.Equal(WizardMachine.EventNotAllowed, d.RefusedCode);
        Assert.Contains("Intro", d.RefusedMessage);
        Assert.Contains("check", d.RefusedMessage);
    }

    [Theory]
    [InlineData(false, WizardMachine.CheckNotDone)]
    [InlineData(true, null)]
    public void Done_waits_for_a_passed_check(bool passed, string? code)
    {
        Assert.Equal(code, WizardMachine.Decide(WizardTable.Load(FlowsFile), "Check", "next", passed).RefusedCode);
    }

    sealed class Rig : IDisposable
    {
        public readonly string Root = Path.Combine(Path.GetTempPath(), "netsec-flow-" + Guid.NewGuid().ToString("N"));
        public readonly SecurityStore Store;
        public readonly FlowRuns Runs;
        public readonly string Profile;

        public Rig(Func<string, string?>? env = null)
        {
            Profile = Path.Combine(Root, "profile");
            WizardTable table = WizardTable.Load(FlowsFile);
            Store = new SecurityStore(Path.Combine(Root, "security"), table);
            Runs = new FlowRuns(table, Store, new FlowParts(Store, env ?? Environment.GetEnvironmentVariable), Profile);
        }

        public void Dispose()
        {
            if (Directory.Exists(Root)) Directory.Delete(Root, true);
        }
    }

    static JsonElement NoData => JsonDocument.Parse("{}").RootElement;
    static JsonElement PathsData(string typeId, string path) => JsonDocument.Parse(JsonSerializer.Serialize(new { paths = new Dictionary<string, string> { [typeId] = path } })).RootElement;

    static RunReply Move(FlowRuns runs, FlowRun run, string ev, JsonElement data)
    {
        (RunReply? reply, RunRefusal? refusal) = runs.Apply(run.RunId, ev, run.StepSeq, data);
        Assert.Null(refusal);
        return reply!;
    }

    [Fact]
    public void Back_at_review_makes_a_new_version_and_keeps_the_old_file()
    {
        using Rig rig = new();
        FlowRun run = rig.Runs.Start("my-login")!.Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        run = Move(rig.Runs, run, "make", NoData).Run;
        Assert.Equal(1, rig.Store.Entry(SecurityTypes.TokenIssuer).Binding!.Version);
        run = Move(rig.Runs, run, "back", NoData).Run;
        Assert.Equal("Make", run.State);
        run = Move(rig.Runs, run, "make", NoData).Run;
        Assert.Equal(2, rig.Store.Entry(SecurityTypes.TokenIssuer).Binding!.Version);
        Assert.True(File.Exists(Path.Combine(rig.Store.Root, "files", SecurityTypes.TokenIssuer, "v1", "key.pem")));
    }

    [Fact]
    public void A_flow_with_no_maker_stays_on_make_and_names_each_part()
    {
        using Rig rig = new();
        FlowRun run = rig.Runs.Start("my-ssh")!.Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        RunReply made = Move(rig.Runs, run, "make", NoData);
        Assert.Equal("Make", made.Run.State);
        Assert.Equal(4, made.Errors.Count(e => e.Code == FlowRuns.PartNotBuilt));
        Assert.Equal(SecurityStore.StateBuiltIn, rig.Store.StateOf(SecurityTypes.SshClient));
    }

    [Fact]
    public void A_missing_tool_saves_the_key_and_says_it_is_not_checked()
    {
        using Rig rig = new(name => name == "NETSEC_OPENSSL" ? @"Z:\no\such\openssl.exe" : null);
        FlowRun run = rig.Runs.Start("my-login")!.Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        run = Move(rig.Runs, run, "make", NoData).Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        RunReply checkedRun = Move(rig.Runs, run, "check", NoData);
        Assert.Contains(checkedRun.Errors, e => e.Code == "REFEREE_MISSING" && e.TypeId == SecurityTypes.TokenIssuer);
        Assert.Equal("Check", checkedRun.Run.State);
        Assert.False(checkedRun.Run.CheckPassed);
        Assert.Equal(SecurityStore.StateConfigured, rig.Store.StateOf(SecurityTypes.TokenIssuer));
        Assert.Equal(1, rig.Store.Entry(SecurityTypes.TokenIssuer).Binding!.Version);
    }

    [Fact]
    public void A_changed_key_file_turns_a_verified_type_broken()
    {
        using Rig rig = new();
        rig.Store.PlaceKey(SecurityTypes.TokenIssuer, "first");
        rig.Store.MarkChecked(SecurityTypes.TokenIssuer, "openssl", "checked-signature-only");
        Assert.Equal(SecurityStore.StateVerified, rig.Store.StateOf(SecurityTypes.TokenIssuer));
        File.WriteAllText(Path.Combine(rig.Store.Root, "files", SecurityTypes.TokenIssuer, "v1", "key.pem"), "changed");
        Assert.Equal(SecurityStore.StateBroken, rig.Store.StateOf(SecurityTypes.TokenIssuer));
    }

    [Fact]
    public void A_check_records_who_judged_each_type_for_as_long_as_that_version_lasts()
    {
        using Rig rig = new();
        FlowRun run = rig.Runs.Start("my-login")!.Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        run = Move(rig.Runs, run, "make", NoData).Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        Move(rig.Runs, run, "check", NoData);
        Assert.Equal("openssl", rig.Store.Entry(SecurityTypes.TokenIssuer).Judge);
        Assert.Equal("checked-signature-only", rig.Store.Entry(SecurityTypes.TokenIssuer).Says);
        Assert.Equal("none", rig.Store.Entry(SecurityTypes.DeviceEnrolment).Judge);
        Assert.Equal("no-outside-judge", rig.Store.Entry(SecurityTypes.DeviceEnrolment).Says);
    }

    [Theory]
    [InlineData(SecurityTypes.TokenIssuer)]
    [InlineData(SecurityTypes.DeviceEnrolment)]
    public void An_rsa_key_for_an_ed25519_type_is_refused_by_name_and_places_nothing(string typeId)
    {
        using Rig rig = new();
        FlowRun run = rig.Runs.Start("my-login")!.Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        run = Move(rig.Runs, run, "use-files", NoData).Run;
        Directory.CreateDirectory(rig.Root);
        string pem = Path.Combine(rig.Root, "rsa.pem");
        using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create(2048))
            File.WriteAllText(pem, NetSec.Pki.TrainingPki.Pem("PRIVATE KEY", rsa.ExportPkcs8PrivateKey()));
        RunReply reply = Move(rig.Runs, run, "files", PathsData(typeId, pem));
        Assert.Contains(reply.Errors, e => e.Code == "KEY_ALGORITHM_NOT_IN_ENGINE" && e.TypeId == typeId);
        Assert.Equal("PickFiles", reply.Run.State);
        Assert.Null(rig.Store.Entry(typeId).Binding);
    }

    [Fact]
    public void Review_reads_the_algorithm_from_the_key()
    {
        using Rig rig = new();
        FlowParts parts = new(rig.Store, Environment.GetEnvironmentVariable);
        rig.Store.PlaceKey(SecurityTypes.TokenIssuer, NetSec.Pki.TrainingPki.Pem("PRIVATE KEY", NetSec.Pki.TrainingCa.Ed25519Pkcs8(new byte[32])));
        using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create(2048))
            rig.Store.PlaceKey(SecurityTypes.Tls11Server, NetSec.Pki.TrainingPki.Pem("PRIVATE KEY", rsa.ExportPkcs8PrivateKey()));
        Assert.Equal("Ed25519", parts.Review(SecurityTypes.TokenIssuer).Algorithm);
        Assert.Equal("RSA-2048", parts.Review(SecurityTypes.Tls11Server).Algorithm);
    }

    [Fact]
    public void A_check_judges_the_placed_keys_when_the_types_sit_on_built_in()
    {
        using Rig rig = new();
        FlowRun run = rig.Runs.Start("my-certificates")!.Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        run = Move(rig.Runs, run, "make", NoData).Run;
        foreach (string typeId in rig.Runs.Table.Flow("my-certificates")!.Types) rig.Store.SetMode(typeId, SecurityStore.ModeBuiltIn);
        string dir = Path.Combine(rig.Root, "proof");
        FlowParts parts = new(rig.Store, Environment.GetEnvironmentVariable);
        foreach (string typeId in rig.Runs.Table.Flow("my-certificates")!.Types)
        {
            CheckFact fact = parts.Check(typeId, dir);
            Assert.True(fact.Passed, typeId + ": " + fact.Message + " " + fact.Output);
            byte[] root = Convert.FromBase64String(string.Concat(File.ReadAllLines(Path.Combine(dir, "root.pem")).Where(l => !l.StartsWith("-----"))));
            byte[] own = rig.Store.PlacedKey(SecurityTypes.RootCa)!.CopyPublic();
            Assert.True(Convert.ToHexString(root).Contains(Convert.ToHexString(own)), typeId + ": the root OpenSSL saw is not the learner's root");
        }
    }

    /// <summary>A stand-in for OpenSSL that accepts every command. A check with no way to fail must not pass.</summary>
    static string FakeTool(Rig rig, string name, string body)
    {
        Directory.CreateDirectory(rig.Root);
        string path = Path.Combine(rig.Root, name + ".cmd");
        File.WriteAllText(path, "@echo off\r\n" + body + "\r\n");
        return path;
    }

    [Theory]
    [InlineData(SecurityTypes.RootCa)]
    [InlineData(SecurityTypes.TlsTrust)]
    [InlineData(SecurityTypes.Tls13Server)]
    [InlineData(SecurityTypes.Tls13Client)]
    [InlineData(SecurityTypes.Tls11Server)]
    public void A_tool_that_accepts_everything_fails_the_check(string typeId)
    {
        using Rig probe = new();
        string tool = FakeTool(probe, "always-yes", "echo ok\r\nexit /b 0");
        using Rig rig = new(name => name == "NETSEC_OPENSSL" ? tool : null);
        FlowRun run = rig.Runs.Start("my-certificates")!.Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        Move(rig.Runs, run, "make", NoData);
        CheckFact fact = new FlowParts(rig.Store, name => name == "NETSEC_OPENSSL" ? tool : null).Check(typeId, Path.Combine(rig.Root, "proof"));
        Assert.False(fact.Passed);
        Assert.Equal("CHECK_FAILED", fact.Code);
    }

    [Fact]
    public void A_control_that_fails_for_the_wrong_reason_fails_the_check()
    {
        using Rig probe = new();
        // Accepts the real command, and refuses the control with words that are no refusal of a signature.
        string tool = FakeTool(probe, "wrong-reason", "echo %* | findstr /c:\"other-root\" >nul\r\nif %errorlevel%==0 (echo out of memory\r\nexit /b 3)\r\necho ok\r\nexit /b 0");
        using Rig rig = new(name => name == "NETSEC_OPENSSL" ? tool : null);
        FlowRun run = rig.Runs.Start("my-certificates")!.Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        Move(rig.Runs, run, "make", NoData);
        CheckFact fact = new FlowParts(rig.Store, name => name == "NETSEC_OPENSSL" ? tool : null).Check(SecurityTypes.RootCa, Path.Combine(rig.Root, "proof"));
        Assert.False(fact.Passed);
        Assert.Equal("CHECK_FAILED", fact.Code);
    }

    [Fact]
    public void A_passing_check_shows_the_control_and_its_refusal()
    {
        using Rig rig = new();
        rig.Store.PlaceKey(SecurityTypes.TokenIssuer, NetSec.Pki.TrainingPki.Pem("PRIVATE KEY", NetSec.Pki.TrainingCa.Ed25519Pkcs8(new byte[32])));
        CheckFact fact = new FlowParts(rig.Store, Environment.GetEnvironmentVariable).Check(SecurityTypes.TokenIssuer, Path.Combine(rig.Root, "proof"));
        Assert.True(fact.Passed, fact.Message);
        Assert.Contains("changed-input", fact.ControlCommand);
        Assert.Contains("Signature Verification Failure", fact.ControlOutput);
    }

    [Fact]
    public void A_tool_that_cannot_start_reports_the_referee_missing()
    {
        using Rig rig = new();
        Directory.CreateDirectory(rig.Root);
        string notProgram = Path.Combine(rig.Root, "not-a-program.exe");
        File.WriteAllText(notProgram, "this file is no program");
        rig.Store.PlaceKey(SecurityTypes.TokenIssuer, NetSec.Pki.TrainingPki.Pem("PRIVATE KEY", NetSec.Pki.TrainingCa.Ed25519Pkcs8(new byte[32])));
        CheckFact fact = new FlowParts(rig.Store, name => name == "NETSEC_OPENSSL" ? notProgram : null).Check(SecurityTypes.TokenIssuer, Path.Combine(rig.Root, "proof"));
        Assert.Equal("REFEREE_MISSING", fact.Code);
    }

    [Fact]
    public void A_file_for_a_type_outside_the_flow_is_refused_and_no_paths_at_all_is_refused()
    {
        using Rig rig = new();
        FlowRun run = rig.Runs.Start("my-login")!.Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        run = Move(rig.Runs, run, "use-files", NoData).Run;
        RunReply none = Move(rig.Runs, run, "files", JsonDocument.Parse("{\"paths\":{}}").RootElement);
        Assert.Contains(none.Errors, e => e.Code == "KEY_FILE_UNREADABLE");
        Assert.Null(rig.Store.Entry(SecurityTypes.TokenIssuer).Binding);
        Directory.CreateDirectory(rig.Root);
        string pem = Path.Combine(rig.Root, "k.pem");
        File.WriteAllText(pem, NetSec.Pki.TrainingPki.Pem("PRIVATE KEY", NetSec.Pki.TrainingCa.Ed25519Pkcs8(new byte[32])));
        RunReply wrong = Move(rig.Runs, none.Run, "files", PathsData(SecurityTypes.SshClient, pem));
        Assert.Contains(wrong.Errors, e => e.Code == "WIZARD_TYPE_NOT_IN_FLOW" && e.TypeId == SecurityTypes.SshClient);
        Assert.Null(rig.Store.Entry(SecurityTypes.TokenIssuer).Binding);
    }

    [Fact]
    public void A_long_form_path_in_the_ssh_folder_still_warns()
    {
        using Rig rig = new();
        FlowRun run = rig.Runs.Start("my-login")!.Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        run = Move(rig.Runs, run, "use-files", NoData).Run;
        string longForm = @"\\?\" + Path.Combine(rig.Profile, ".ssh", "absent.pem");
        RunReply reply = Move(rig.Runs, run, "files", PathsData(SecurityTypes.TokenIssuer, longForm));
        Assert.Contains(reply.Warnings, w => w.Code == FlowRuns.PathPersonal);
    }

    [Fact]
    public void A_corrupt_modes_file_is_named_at_start()
    {
        using Rig rig = new();
        string root = Path.Combine(rig.Root, "corrupt");
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "modes.json"), "{ not json");
        InvalidDataException e = Assert.Throws<InvalidDataException>(() => new SecurityStore(root, WizardTable.Load(FlowsFile)));
        Assert.Contains("modes.json", e.Message);
    }

    [Fact]
    public void A_key_file_that_is_too_large_is_refused_by_name()
    {
        using Rig rig = new();
        Directory.CreateDirectory(rig.Root);
        string big = Path.Combine(rig.Root, "big.pem");
        using (FileStream f = File.Create(big)) f.SetLength(3L * 1024 * 1024 * 1024);
        NetSec.Errors.NetSecException e = Assert.Throws<NetSec.Errors.NetSecException>(() => NetSec.Pki.KeyFileReader.ReadPrivateKey(big, "k"));
        Assert.Equal("KEY_FILE_FORMAT", e.Error.Code);
    }

    [Fact]
    public void Show_keys_survives_a_new_store_on_the_same_folder()
    {
        using Rig rig = new();
        Assert.True(rig.Store.ShowKeys);
        rig.Store.SetShowKeys(false);
        Assert.False(new SecurityStore(rig.Store.Root, WizardTable.Load(FlowsFile)).ShowKeys);
    }

    [Fact]
    public void A_path_in_the_learners_ssh_folder_warns_and_never_blocks_by_itself()
    {
        using Rig rig = new();
        FlowRun run = rig.Runs.Start("my-login")!.Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        run = Move(rig.Runs, run, "use-files", NoData).Run;
        Directory.CreateDirectory(Path.Combine(rig.Profile, ".ssh"));
        string key = Path.Combine(rig.Profile, ".ssh", "test.pem");
        File.WriteAllText(key, NetSec.Pki.TrainingPki.Pem("PRIVATE KEY", NetSec.Pki.TrainingCa.Ed25519Pkcs8(new byte[32])));
        RunReply reply = Move(rig.Runs, run, "files", PathsData(SecurityTypes.TokenIssuer, key));
        Assert.Contains(reply.Warnings, w => w.Code == FlowRuns.PathPersonal);
        Assert.Empty(reply.Errors);
        Assert.Equal("Review", reply.Run.State);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void A_blank_path_is_named_as_unreadable_and_is_no_server_error(string path)
    {
        using Rig rig = new();
        FlowRun run = rig.Runs.Start("my-login")!.Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        run = Move(rig.Runs, run, "use-files", NoData).Run;
        RunReply reply = Move(rig.Runs, run, "files", PathsData(SecurityTypes.TokenIssuer, path));
        Assert.Contains(reply.Errors, e => e.Code == "KEY_FILE_UNREADABLE");
        Assert.Equal("PickFiles", reply.Run.State);
    }

    [Fact]
    public void A_run_resumes_after_a_restart_with_its_own_step()
    {
        using Rig rig = new();
        FlowRun run = rig.Runs.Start("my-login")!.Run;
        run = Move(rig.Runs, run, "next", NoData).Run;
        WizardTable table = WizardTable.Load(FlowsFile);
        FlowRuns again = new(table, rig.Store, new FlowParts(rig.Store, Environment.GetEnvironmentVariable), rig.Profile);
        Assert.Equal(run.RunId, again.OpenRunOf("my-login"));
        Assert.Equal("Make", again.Find(run.RunId)!.Run.State);
    }
}
