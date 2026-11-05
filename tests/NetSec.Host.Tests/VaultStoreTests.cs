#nullable enable
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NetSec.Host.Security;
using NetSec.Keys;
using NetSec.Vault;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>The Host's use of the vault: the V0 move, readiness that agrees with session start, and the exercise's judge.</summary>
public sealed class VaultStoreTests : IDisposable
{
    static readonly string FlowsFile = Path.Combine(AppContext.BaseDirectory, "wizard-flows.json");
    readonly string _root = Path.Combine(Path.GetTempPath(), "netsec-vstore-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_root, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    SecurityStore Store() => new(_root, WizardTable.Load(FlowsFile));

    static string NewPem() =>
        NetSec.Pki.TrainingPki.Pem("PRIVATE KEY", NetSec.Pki.TrainingCa.Ed25519Pkcs8(RandomNumberGenerator.GetBytes(32)));

    [Fact]
    public void A_v0_key_file_moves_into_the_vault_on_first_start_and_the_file_goes()
    {
        string pem = NewPem(), relative = Path.Combine("files", SecurityTypes.TokenIssuer, "v1", "key.pem"), full = Path.Combine(_root, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllText(full, pem);
        string hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(full)));
        File.WriteAllText(Path.Combine(_root, "modes.json"), JsonSerializer.Serialize(new
        {
            showKeys = true,
            types = new System.Collections.Generic.Dictionary<string, object>
            {
                [SecurityTypes.TokenIssuer] = new { mode = "Mine", binding = new { provider = "file", version = 1, keyFile = relative, keyHash = hash }, checkedVersion = 1, judge = "openssl", says = "checked-signature-only" },
            },
        }));

        SecurityStore store = Store();

        TypeEntry e = store.Entry(SecurityTypes.TokenIssuer);
        Assert.Equal(SecurityStore.ProviderVault, e.Binding!.Provider);
        Assert.False(File.Exists(full));
        Assert.Equal(SecurityStore.StateVerified, store.StateOf(SecurityTypes.TokenIssuer));
        byte[] seed = NetSec.Pki.KeyFileReader.Parse(pem, SecurityTypes.TokenIssuer).CopyMaterial();
        Assert.Equal(seed, store.PlacedKey(SecurityTypes.TokenIssuer)!.CopyMaterial());
        AuditRow moved = store.Vault.Audit(0, 100).Single(r => r.Op == VaultOps.Import);
        Assert.Equal(SecurityStore.CallerMoveV0, moved.Caller);

        // A second start finds nothing left to move.
        Assert.Single(Store().Vault.Audit(0, 100), r => r.Op == VaultOps.Import);
    }

    [Fact]
    public void Readiness_names_a_vault_key_that_no_longer_opens_as_session_start_does()
    {
        SecurityStore store = Store();
        store.PlaceKey(SecurityTypes.TokenIssuer, NewPem());
        store.MarkChecked(SecurityTypes.TokenIssuer, "openssl", "checked-signature-only");
        Assert.True(store.Decide([SecurityTypes.TokenIssuer]).MayRun);

        File.WriteAllBytes(Path.Combine(_root, "vault", "master.key"), RandomNumberGenerator.GetBytes(32));
        LabDecision after = Store().Decide([SecurityTypes.TokenIssuer]);
        Assert.False(after.MayRun);
        Assert.Equal(VaultCodes.UnwrapFailed, after.Problems[0].Code);
        Assert.Contains(SecurityTypes.TokenIssuer, after.Problems[0].Detail);
    }

    [Fact]
    public void A_lab_gets_the_version_the_check_passed()
    {
        SecurityStore store = Store();
        store.PlaceKey(SecurityTypes.TokenIssuer, NewPem());
        byte[] first = store.PlacedKey(SecurityTypes.TokenIssuer)!.CopyMaterial();
        store.Vault.Import(SecurityTypes.TokenIssuer, RandomNumberGenerator.GetBytes(32), "someone-else");
        Assert.Equal(first, store.Credentials([SecurityTypes.TokenIssuer], "host/lab-10").Find(KeyIds.TokenIssuer).CopyMaterial());
    }

    [Fact]
    public void The_exercise_check_has_a_control_that_openssl_refuses_for_the_signature()
    {
        SecurityStore store = Store();
        VaultExercise exercise = new(store.Vault, new OpenSslTool(Environment.GetEnvironmentVariable), Path.Combine(_root, "proof"));
        ExerciseSigned signed = exercise.Sign("pay the pump owner");
        Assert.Equal("OK", signed.Code);
        Assert.Contains("Signature Verified Successfully", signed.Output);
        Assert.Contains("Signature Verification Failure", signed.ControlOutput);
        Assert.NotEqual(signed.Command, signed.ControlCommand);
    }

    [Fact]
    public void The_audit_check_names_the_three_changes_it_cannot_see()
    {
        SecurityStore store = Store();
        string limits = new VaultExercise(store.Vault, new OpenSslTool(Environment.GetEnvironmentVariable), Path.Combine(_root, "proof")).AuditCheck().Limits;
        Assert.Contains("newest row", limits);
        Assert.Contains("cut from the end", limits);
        Assert.Contains("rewrite of every row", limits);
    }
}
