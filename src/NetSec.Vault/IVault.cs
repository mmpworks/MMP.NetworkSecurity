namespace NetSec.Vault;

/// <summary>A named key store with versions, fixed usage, export rules and an audit of every call (docs/modes-design.md section 4.1).
/// Each call that takes a caller writes its audit row before it returns. A call whose row cannot be written is refused with VAULT_AUDIT_FAILED.</summary>
public interface IVault
{
    /// <summary>Exportable and the allowed operations are set here, once. VAULT_KEY_EXISTS when the name is taken.</summary>
    VaultKeyInfo CreateKey(string name, VaultKeyPolicy policy, string caller);
    /// <summary>Adds a version made inside the vault. Returns the new version.</summary>
    int Generate(string name, string caller);
    /// <summary>Adds a version from bytes made outside. Returns the new version.</summary>
    int Import(string name, byte[] material, string caller);
    bool Exists(string name);
    VaultKeyInfo Describe(string name);
    VaultKeyInfo[] Keys();
    byte[]? PublicKey(string name, int? version);
    /// <summary>VAULT_OP_REFUSED unless the key allows sign.</summary>
    byte[] Sign(string name, byte[] message, string caller);
    /// <summary>HKDF-SHA256 with the input as the info. VAULT_OP_REFUSED unless the key allows derive.</summary>
    byte[] Derive(string name, byte[] input, string caller);
    /// <summary>The bytes of the newest version. VAULT_EXPORT_REFUSED for a non-exportable key. Audited with the caller.</summary>
    byte[] Export(string name, string caller);
    AuditRow[] Audit(long afterSeq, int limit);
}

public static class VaultCodes
{
    public const string ExportRefused = "VAULT_EXPORT_REFUSED";
    public const string OpRefused = "VAULT_OP_REFUSED";
    public const string UnwrapFailed = "VAULT_UNWRAP_FAILED";
    public const string AuditFailed = "VAULT_AUDIT_FAILED";
    public const string KeyUnknown = "VAULT_KEY_UNKNOWN";
    public const string KeyExists = "VAULT_KEY_EXISTS";
    public const string BadMaterial = "VAULT_BAD_MATERIAL";
}

public static class VaultOps
{
    public const string Create = "create", Generate = "generate", Import = "import", Sign = "sign", Derive = "derive", Export = "export";
}

public static class VaultAlgorithms
{
    /// <summary>An Ed25519 seed of 32 bytes. Its public half is kept beside it.</summary>
    public const string Ed25519 = "ed25519";
    /// <summary>A 32-byte secret that only derives. It has no public half.</summary>
    public const string HkdfSecret = "hkdf-sha256";
}

public sealed class VaultException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public sealed record VaultKeyPolicy(string Algorithm, bool Exportable, string[] AllowedOps)
{
    public bool Allows(string op) => Array.IndexOf(AllowedOps, op) >= 0;
}

/// <summary>What a key list may show. It never holds key bytes.</summary>
public sealed record VaultKeyInfo(string Name, VaultKeyPolicy Policy, string Provenance, int Versions, string Fingerprint, byte[]? PublicKey);

public sealed record AuditRow(long Seq, string At, string Caller, string Op, string Name, int? Version, string Result, string Detail, string PrevHash);
