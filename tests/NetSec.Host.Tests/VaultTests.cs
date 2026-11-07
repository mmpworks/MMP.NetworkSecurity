#nullable enable
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using NetSec.Vault;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>The practice vault on its own file, with the edits a person holding the file could make (the same edits acceptance/checks/vaultdb.py makes).</summary>
[Collection(BlockingProductCalls.Name)]
public sealed class VaultTests : IDisposable
{
    readonly string _dir = Path.Combine(Path.GetTempPath(), "netsec-vault-" + Guid.NewGuid().ToString("N"));
    readonly SqliteVault _vault;

    public VaultTests() => _vault = new SqliteVault(_dir);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    static readonly VaultKeyPolicy Signing = new(VaultAlgorithms.Ed25519, false, [VaultOps.Sign]);
    static readonly VaultKeyPolicy Deriving = new(VaultAlgorithms.HkdfSecret, false, [VaultOps.Derive]);
    static readonly VaultKeyPolicy FlowKey = new(VaultAlgorithms.Ed25519, true, [VaultOps.Export]);

    void Sql(string sql)
    {
        using SqliteConnection c = new(new SqliteConnectionStringBuilder { DataSource = Path.Combine(_dir, "vault.db"), Pooling = false }.ToString());
        c.Open();
        using SqliteCommand q = c.CreateCommand();
        q.CommandText = sql;
        q.ExecuteNonQuery();
    }

    [Fact]
    public void A_non_exportable_key_refuses_export_and_the_refusal_is_a_row()
    {
        _vault.CreateKey("exercise/signing", Signing, "test");
        _vault.Generate("exercise/signing", "test");
        VaultException e = Assert.Throws<VaultException>(() => _vault.Export("exercise/signing", "host/test"));
        Assert.Equal(VaultCodes.ExportRefused, e.Code);
        AuditRow last = _vault.Audit(0, 100).Last();
        Assert.Equal(("export", "refused", "host/test"), (last.Op, last.Result, last.Caller));
        Assert.Contains(VaultCodes.ExportRefused, last.Detail);
    }

    [Fact]
    public void An_exportable_key_leaves_and_the_row_names_the_caller()
    {
        byte[] seed = RandomNumberGenerator.GetBytes(32);
        _vault.CreateKey("token.issuer", FlowKey, "host/flow");
        Assert.Equal(1, _vault.Import("token.issuer", seed, "host/flow"));
        Assert.Equal(seed, _vault.Export("token.issuer", "host/lab-10"));
        AuditRow last = _vault.Audit(0, 100).Last();
        Assert.Equal(("export", "ok", "host/lab-10", (int?)1), (last.Op, last.Result, last.Caller, last.Version));
    }

    [Fact]
    public void The_policy_is_set_once()
    {
        _vault.CreateKey("exercise/signing", Signing, "test");
        Assert.Equal(VaultCodes.KeyExists, Assert.Throws<VaultException>(() => _vault.CreateKey("exercise/signing", Signing with { Exportable = true }, "test")).Code);
        Assert.False(_vault.Describe("exercise/signing").Policy.Exportable);
    }

    [Fact]
    public void A_signing_key_refuses_derive_and_a_derive_key_is_steady_per_label()
    {
        _vault.CreateKey("exercise/signing", Signing, "test");
        _vault.Generate("exercise/signing", "test");
        _vault.CreateKey("exercise/derive", Deriving, "test");
        _vault.Generate("exercise/derive", "test");
        Assert.Equal(VaultCodes.OpRefused, Assert.Throws<VaultException>(() => _vault.Derive("exercise/signing", [1], "test")).Code);
        byte[] a = _vault.Derive("exercise/derive", Encoding.UTF8.GetBytes("pump-4"), "test");
        Assert.Equal(a, _vault.Derive("exercise/derive", Encoding.UTF8.GetBytes("pump-4"), "test"));
        Assert.NotEqual(a, _vault.Derive("exercise/derive", Encoding.UTF8.GetBytes("pump-5"), "test"));
    }

    [Fact]
    public void A_signature_verifies_under_the_public_key_the_vault_gives()
    {
        _vault.CreateKey("exercise/signing", Signing, "test");
        _vault.Generate("exercise/signing", "test");
        byte[] message = Encoding.UTF8.GetBytes("pay the pump owner");
        byte[] signature = _vault.Sign("exercise/signing", message, "test");
        Assert.True(NetSec.Crypto.Ed25519.Verify(_vault.PublicKey("exercise/signing", null)!, message, signature));
    }

    [Fact]
    public void A_changed_wrapped_row_is_refused_and_the_refusal_is_a_row()
    {
        _vault.CreateKey("token.issuer", FlowKey, "test");
        _vault.Generate("token.issuer", "test");
        Sql("UPDATE key_versions SET wrapped = zeroblob(length(wrapped))");
        Assert.Equal(VaultCodes.UnwrapFailed, Assert.Throws<VaultException>(() => _vault.Export("token.issuer", "host/lab-10")).Code);
        Assert.Contains(VaultCodes.UnwrapFailed, _vault.Audit(0, 100).Last().Detail);
    }

    [Fact]
    public void A_call_whose_row_cannot_be_written_is_refused()
    {
        _vault.CreateKey("token.issuer", FlowKey, "test");
        _vault.Generate("token.issuer", "test");
        Sql("CREATE TRIGGER block BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'blocked'); END");
        Assert.Equal(VaultCodes.AuditFailed, Assert.Throws<VaultException>(() => _vault.Export("token.issuer", "host/lab-10")).Code);
        Assert.Equal(VaultCodes.AuditFailed, Assert.Throws<VaultException>(() => _vault.Generate("token.issuer", "test")).Code);
        Sql("DROP TRIGGER block");
        Assert.Equal(1, _vault.Describe("token.issuer").Versions);
        Assert.Equal(32, _vault.Export("token.issuer", "host/lab-10").Length);
    }

    [Fact]
    public void The_chain_is_whole_until_a_row_changes_and_then_names_the_row_after_it()
    {
        _vault.CreateKey("exercise/signing", Signing, "test");
        _vault.Generate("exercise/signing", "test");
        _vault.Sign("exercise/signing", [1, 2], "test");
        AuditRow[] rows = _vault.Audit(0, 100);
        Assert.Equal(0, AuditChain.FirstBadSeq(rows));
        Assert.Equal(rows.Length, rows.Select(r => r.PrevHash).Distinct().Count());
        Sql($"UPDATE audit SET detail = 'edited' WHERE seq = {rows[1].Seq}");
        Assert.Equal(rows[2].Seq, AuditChain.FirstBadSeq(_vault.Audit(0, 100)));
    }

    [Fact]
    public void Two_vault_objects_on_one_folder_keep_one_chain()
    {
        _vault.CreateKey("exercise/signing", Signing, "test");
        _vault.Generate("exercise/signing", "test");
        SqliteVault second = new(_dir);
        System.Threading.Tasks.Parallel.For(0, 400, new System.Threading.Tasks.ParallelOptions { MaxDegreeOfParallelism = 8 },
            i => (i % 2 == 0 ? _vault : second).Sign("exercise/signing", [(byte)i], "writer-" + (i % 2)));
        AuditRow[] rows = _vault.Audit(0, 1000);
        Assert.Equal(402, rows.Length);
        Assert.Equal(rows.Length, rows.Select(r => r.PrevHash).Distinct().Count());
        Assert.Equal(0, AuditChain.FirstBadSeq(rows));
    }

    [Theory]
    [InlineData(16)]
    [InlineData(7)]
    public void A_master_key_of_the_wrong_length_is_refused_by_name(int length)
    {
        string dir = Path.Combine(_dir, "short-" + length);
        Directory.CreateDirectory(dir);
        File.WriteAllBytes(Path.Combine(dir, "master.key"), RandomNumberGenerator.GetBytes(length));
        SqliteVault vault = new(dir);
        vault.CreateKey("token.issuer", FlowKey, "test");
        VaultException e = Assert.Throws<VaultException>(() => vault.Import("token.issuer", RandomNumberGenerator.GetBytes(32), "test"));
        Assert.Equal(VaultCodes.MasterKeyBad, e.Code);
        Assert.Contains(length + " bytes", e.Message);
    }

    [Fact]
    public void A_key_with_no_version_is_refused_and_the_refusal_is_a_row()
    {
        _vault.CreateKey("token.issuer", FlowKey, "test");
        Assert.Equal(VaultCodes.KeyUnknown, Assert.Throws<VaultException>(() => _vault.Export("token.issuer", "host/lab-10")).Code);
        AuditRow last = _vault.Audit(0, 100).Last();
        Assert.Equal(("export", "refused", "host/lab-10"), (last.Op, last.Result, last.Caller));
    }

    [Fact]
    public void Export_gives_the_version_asked_for()
    {
        byte[] first = RandomNumberGenerator.GetBytes(32), second = RandomNumberGenerator.GetBytes(32);
        _vault.CreateKey("token.issuer", FlowKey, "test");
        _vault.Import("token.issuer", first, "test");
        _vault.Import("token.issuer", second, "test");
        Assert.Equal(first, _vault.Export("token.issuer", "host/lab-10", 1));
        Assert.Equal(second, _vault.Export("token.issuer", "host/lab-10"));
        Assert.Equal((int?)1, _vault.Audit(0, 100)[^2].Version);
    }

    [Fact]
    public void Probe_names_a_key_that_no_longer_opens_and_writes_no_row()
    {
        _vault.CreateKey("token.issuer", FlowKey, "test");
        _vault.Generate("token.issuer", "test");
        Assert.Null(_vault.Probe("token.issuer", 1));
        int rows = _vault.Audit(0, 100).Length;
        Sql("UPDATE key_versions SET wrapped = zeroblob(length(wrapped))");
        Assert.Equal(VaultCodes.UnwrapFailed, _vault.Probe("token.issuer", 1));
        Assert.Equal(rows, _vault.Audit(0, 100).Length);
    }

    [Fact]
    public void The_wrapped_row_opens_with_the_master_key_and_name_hash_version_as_the_layout_the_suite_assumes()
    {
        byte[] seed = RandomNumberGenerator.GetBytes(32);
        _vault.CreateKey("token.issuer", FlowKey, "test");
        _vault.Import("token.issuer", seed, "test");
        using SqliteConnection c = new(new SqliteConnectionStringBuilder { DataSource = Path.Combine(_dir, "vault.db"), Pooling = false }.ToString());
        c.Open();
        using SqliteCommand q = c.CreateCommand();
        q.CommandText = "SELECT nonce, wrapped FROM key_versions";
        using SqliteDataReader r = q.ExecuteReader();
        Assert.True(r.Read());
        byte[] nonce = (byte[])r[0], wrapped = (byte[])r[1], plain = new byte[wrapped.Length - 16];
        using AesGcm gcm = new(File.ReadAllBytes(Path.Combine(_dir, "master.key")), 16);
        gcm.Decrypt(nonce, wrapped.AsSpan(0, plain.Length), wrapped.AsSpan(plain.Length), plain, Encoding.UTF8.GetBytes("token.issuer#1"));
        Assert.Equal(seed, plain);
    }
}
