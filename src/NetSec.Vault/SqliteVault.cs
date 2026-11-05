using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using NetSec.Crypto;

namespace NetSec.Vault;

/// <summary>
/// The practice vault in one SQLite file, vault.db, beside a 32-byte master.key. Key bytes rest wrapped by AES-256-GCM under the master key,
/// with name#version as the additional data, so a row moved to another name or version does not unwrap. wrapped = ciphertext then the 16-byte tag.
/// Anyone with the folder can read every key: the rules here are rules in this code, not in hardware.
/// One lock orders every call, so the audit chain gets one row at a time. Pooling is off, so a change another process makes to the file is seen at once.
/// </summary>
public sealed class SqliteVault : IVault
{
    const int TagBytes = 16, NonceBytes = 12, SecretBytes = 32;
    const string Ok = "ok", Refused = "refused";

    readonly Lock _gate = new();
    readonly string _connection;
    readonly byte[] _master;

    public string Folder { get; }

    public SqliteVault(string folder)
    {
        Folder = folder;
        Directory.CreateDirectory(folder);
        SQLitePCL.Batteries_V2.Init();
        _master = LoadOrMakeMasterKey(Path.Combine(folder, "master.key"));
        _connection = new SqliteConnectionStringBuilder { DataSource = Path.Combine(folder, "vault.db"), Pooling = false, DefaultTimeout = 20 }.ToString();
        using SqliteConnection c = Open();
        Execute(c, null, """
            CREATE TABLE IF NOT EXISTS key_names(name TEXT PRIMARY KEY, algorithm TEXT NOT NULL, exportable INTEGER NOT NULL, allowed_ops TEXT NOT NULL, provenance TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS key_versions(name TEXT NOT NULL, version INTEGER NOT NULL, nonce BLOB NOT NULL, wrapped BLOB NOT NULL, public_key BLOB, fingerprint TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(name, version));
            CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, caller TEXT NOT NULL, op TEXT NOT NULL, name TEXT NOT NULL, version INTEGER, result TEXT NOT NULL, detail TEXT NOT NULL, prev_hash TEXT NOT NULL);
            """);
    }

    static byte[] LoadOrMakeMasterKey(string path)
    {
        if (File.Exists(path)) return File.ReadAllBytes(path);
        byte[] key = RandomNumberGenerator.GetBytes(SecretBytes);
        File.WriteAllBytes(path, key);
        return key;
    }

    // ------------------------------------------------------------ keys in

    public VaultKeyInfo CreateKey(string name, VaultKeyPolicy policy, string caller)
    {
        lock (_gate)
        {
            using SqliteConnection c = Open();
            if (FindPolicy(c, name) is not null) throw new VaultException(VaultCodes.KeyExists, $"A key named {name} exists. Its policy was set when it was made, and stays.");
            using SqliteTransaction t = c.BeginTransaction();
            Execute(c, t, "INSERT INTO key_names VALUES($n, $a, $e, $o, '', $at)",
                ("$n", name), ("$a", policy.Algorithm), ("$e", policy.Exportable ? 1 : 0), ("$o", string.Join(',', policy.AllowedOps)), ("$at", Now()));
            Append(c, t, caller, VaultOps.Create, name, null, Ok, "");
            t.Commit();
        }
        return Describe(name);
    }

    public int Generate(string name, string caller) => AddVersion(name, null, VaultOps.Generate, caller);

    public int Import(string name, byte[] material, string caller) => AddVersion(name, material, VaultOps.Import, caller);

    int AddVersion(string name, byte[]? material, string op, string caller)
    {
        lock (_gate)
        {
            using SqliteConnection c = Open();
            VaultKeyPolicy policy = FindPolicy(c, name) ?? throw Unknown(name);
            byte[] secret = material ?? RandomNumberGenerator.GetBytes(SecretBytes);
            if (secret.Length != SecretBytes) throw new VaultException(VaultCodes.BadMaterial, $"A {policy.Algorithm} key holds {SecretBytes} bytes. These are {secret.Length}.");
            byte[]? publicPart = policy.Algorithm == VaultAlgorithms.Ed25519 ? Ed25519.PublicFrom(secret) : null;
            int version = Scalar(c, null, "SELECT COALESCE(MAX(version), 0) + 1 FROM key_versions WHERE name = $n", ("$n", name));
            (byte[] nonce, byte[] wrapped) = Wrap(name, version, secret);
            using SqliteTransaction t = c.BeginTransaction();
            Execute(c, t, "INSERT INTO key_versions VALUES($n, $v, $nonce, $w, $p, $f, 'active', $at)",
                ("$n", name), ("$v", version), ("$nonce", nonce), ("$w", wrapped), ("$p", (object?)publicPart ?? DBNull.Value),
                ("$f", publicPart is null ? Fingerprints.OfSecret(secret) : Fingerprints.OfPublic(publicPart)), ("$at", Now()));
            Execute(c, t, "UPDATE key_names SET provenance = $p WHERE name = $n", ("$n", name), ("$p", material is null ? "generated" : "imported"));
            Append(c, t, caller, op, name, version, Ok, "");
            t.Commit();
            return version;
        }
    }

    // ------------------------------------------------------------ keys used inside, or let out

    public byte[] Sign(string name, byte[] message, string caller) =>
        Use(name, VaultOps.Sign, caller, p => p.Allows(VaultOps.Sign) ? null : $"{name} may not sign.", seed => Ed25519.Sign(seed, message));

    public byte[] Derive(string name, byte[] input, string caller) =>
        Use(name, VaultOps.Derive, caller, p => p.Allows(VaultOps.Derive) ? null : $"{name} may not derive. A key's usage is fixed when it is made.",
            secret => HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, SecretBytes, [], input));

    public string? Probe(string name, int? version) => null;

    public byte[] Export(string name, string caller, int? version = null) =>
        Use(name, VaultOps.Export, caller, p => p.Exportable ? null : $"{VaultCodes.ExportRefused}: {name} was made non-exportable, as an HSM key is.", secret => secret);

    /// <summary>
    /// The shape of every call that touches key bytes: check the policy, unwrap the newest version, act, then write the row.
    /// A refusal and a failed unwrap write a refused row too, then throw. The row is in the file before the result leaves.
    /// </summary>
    byte[] Use(string name, string op, string caller, Func<VaultKeyPolicy, string?> refusal, Func<byte[], byte[]> act)
    {
        lock (_gate)
        {
            using SqliteConnection c = Open();
            VaultKeyPolicy policy = FindPolicy(c, name) ?? throw RefuseAudited(c, caller, op, name, null, VaultCodes.KeyUnknown, $"No vault key is named {name}.");
            if (refusal(policy) is { } why)
                throw RefuseAudited(c, caller, op, name, null, op == VaultOps.Export ? VaultCodes.ExportRefused : VaultCodes.OpRefused, why);
            (int version, byte[] nonce, byte[] wrapped) = Newest(c, name);
            byte[] secret = Unwrap(name, version, nonce, wrapped)
                ?? throw RefuseAudited(c, caller, op, name, version, VaultCodes.UnwrapFailed, $"{name} version {version} does not unwrap: the stored row or the master key changed.");
            byte[] result = act(secret);
            Append(c, null, caller, op, name, version, Ok, "");
            return result;
        }
    }

    VaultException RefuseAudited(SqliteConnection c, string caller, string op, string name, int? version, string code, string message)
    {
        string detail = message.StartsWith(code, StringComparison.Ordinal) ? message : code + ": " + message;
        Append(c, null, caller, op, name, version, Refused, detail);
        return new VaultException(code, message);
    }

    // ------------------------------------------------------------ reads that hold no secret

    public bool Exists(string name)
    {
        lock (_gate) { using SqliteConnection c = Open(); return FindPolicy(c, name) is not null; }
    }

    public VaultKeyInfo Describe(string name) => Keys().FirstOrDefault(k => k.Name == name) ?? throw Unknown(name);

    public VaultKeyInfo[] Keys()
    {
        lock (_gate)
        {
            using SqliteConnection c = Open();
            using SqliteCommand q = Command(c, null, """
                SELECT n.name, n.algorithm, n.exportable, n.allowed_ops, n.provenance,
                       (SELECT COUNT(*) FROM key_versions v WHERE v.name = n.name),
                       (SELECT v.fingerprint FROM key_versions v WHERE v.name = n.name ORDER BY v.version DESC LIMIT 1),
                       (SELECT v.public_key FROM key_versions v WHERE v.name = n.name ORDER BY v.version DESC LIMIT 1)
                FROM key_names n ORDER BY n.name
                """);
            using SqliteDataReader r = q.ExecuteReader();
            List<VaultKeyInfo> keys = [];
            while (r.Read())
                keys.Add(new VaultKeyInfo(r.GetString(0), PolicyOf(r.GetString(1), r.GetInt64(2), r.GetString(3)), r.GetString(4), r.GetInt32(5),
                    r.IsDBNull(6) ? "" : r.GetString(6), r.IsDBNull(7) ? null : (byte[])r[7]));
            return [.. keys];
        }
    }

    public byte[]? PublicKey(string name, int? version)
    {
        lock (_gate)
        {
            using SqliteConnection c = Open();
            using SqliteCommand q = Command(c, null, "SELECT public_key FROM key_versions WHERE name = $n AND version = COALESCE($v, (SELECT MAX(version) FROM key_versions WHERE name = $n))",
                ("$n", name), ("$v", (object?)version ?? DBNull.Value));
            object? value = q.ExecuteScalar();
            return value is byte[] b ? b : null;
        }
    }

    public AuditRow[] Audit(long afterSeq, int limit)
    {
        lock (_gate)
        {
            using SqliteConnection c = Open();
            using SqliteCommand q = Command(c, null, "SELECT seq, at, caller, op, name, version, result, detail, prev_hash FROM audit WHERE seq > $after ORDER BY seq LIMIT $limit",
                ("$after", afterSeq), ("$limit", limit));
            using SqliteDataReader r = q.ExecuteReader();
            List<AuditRow> rows = [];
            while (r.Read()) rows.Add(RowOf(r));
            return [.. rows];
        }
    }

    // ------------------------------------------------------------ the audit chain

    /// <summary>Writes one row linked to the row before it. Any SQLite failure here refuses the call that asked for the row.</summary>
    void Append(SqliteConnection c, SqliteTransaction? t, string caller, string op, string name, int? version, string result, string detail)
    {
        try
        {
            using SqliteCommand last = Command(c, t, "SELECT seq, at, caller, op, name, version, result, detail, prev_hash FROM audit ORDER BY seq DESC LIMIT 1");
            string prev = AuditChain.Seed;
            using (SqliteDataReader r = last.ExecuteReader())
                if (r.Read()) prev = AuditChain.HashOf(RowOf(r));
            Execute(c, t, "INSERT INTO audit(at, caller, op, name, version, result, detail, prev_hash) VALUES($at, $c, $op, $n, $v, $r, $d, $p)",
                ("$at", Now()), ("$c", caller), ("$op", op), ("$n", name), ("$v", (object?)version ?? DBNull.Value), ("$r", result), ("$d", detail), ("$p", prev));
        }
        catch (SqliteException e)
        {
            throw new VaultException(VaultCodes.AuditFailed, $"The vault could not write its audit row ({e.Message.Trim()}), so it refused the call.");
        }
    }

    static AuditRow RowOf(SqliteDataReader r) => new(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4),
        r.IsDBNull(5) ? null : r.GetInt32(5), r.GetString(6), r.GetString(7), r.GetString(8));

    // ------------------------------------------------------------ wrapping

    (byte[] Nonce, byte[] Wrapped) Wrap(string name, int version, byte[] secret)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceBytes), wrapped = new byte[secret.Length + TagBytes];
        using AesGcm gcm = new(_master, TagBytes);
        gcm.Encrypt(nonce, secret, wrapped.AsSpan(0, secret.Length), wrapped.AsSpan(secret.Length), Aad(name, version));
        return (nonce, wrapped);
    }

    byte[]? Unwrap(string name, int version, byte[] nonce, byte[] wrapped)
    {
        if (nonce.Length != NonceBytes || wrapped.Length <= TagBytes) return null;
        byte[] secret = new byte[wrapped.Length - TagBytes];
        try
        {
            using AesGcm gcm = new(_master, TagBytes);
            gcm.Decrypt(nonce, wrapped.AsSpan(0, secret.Length), wrapped.AsSpan(secret.Length), secret, Aad(name, version));
            return secret;
        }
        catch (CryptographicException) { return null; }
    }

    static byte[] Aad(string name, int version) => Encoding.UTF8.GetBytes(name + "#" + version.ToString(System.Globalization.CultureInfo.InvariantCulture));

    // ------------------------------------------------------------ SQL plumbing

    SqliteConnection Open()
    {
        SqliteConnection c = new(_connection);
        c.Open();
        return c;
    }

    static VaultKeyPolicy? FindPolicy(SqliteConnection c, string name)
    {
        using SqliteCommand q = Command(c, null, "SELECT algorithm, exportable, allowed_ops FROM key_names WHERE name = $n", ("$n", name));
        using SqliteDataReader r = q.ExecuteReader();
        return r.Read() ? PolicyOf(r.GetString(0), r.GetInt64(1), r.GetString(2)) : null;
    }

    static VaultKeyPolicy PolicyOf(string algorithm, long exportable, string ops) =>
        new(algorithm, exportable != 0, ops.Split(',', StringSplitOptions.RemoveEmptyEntries));

    static (int Version, byte[] Nonce, byte[] Wrapped) Newest(SqliteConnection c, string name)
    {
        using SqliteCommand q = Command(c, null, "SELECT version, nonce, wrapped FROM key_versions WHERE name = $n ORDER BY version DESC LIMIT 1", ("$n", name));
        using SqliteDataReader r = q.ExecuteReader();
        if (!r.Read()) throw new VaultException(VaultCodes.KeyUnknown, $"{name} has no version yet.");
        return (r.GetInt32(0), (byte[])r[1], (byte[])r[2]);
    }

    static VaultException Unknown(string name) => new(VaultCodes.KeyUnknown, $"No vault key is named {name}.");

    static string Now() => DateTimeOffset.UtcNow.ToString("o", System.Globalization.CultureInfo.InvariantCulture);

    static SqliteCommand Command(SqliteConnection c, SqliteTransaction? t, string sql, params (string Name, object Value)[] args)
    {
        SqliteCommand q = c.CreateCommand();
        q.CommandText = sql;
        q.Transaction = t;
        foreach ((string n, object v) in args) q.Parameters.AddWithValue(n, v);
        return q;
    }

    static void Execute(SqliteConnection c, SqliteTransaction? t, string sql, params (string Name, object Value)[] args)
    {
        using SqliteCommand q = Command(c, t, sql, args);
        q.ExecuteNonQuery();
    }

    static int Scalar(SqliteConnection c, SqliteTransaction? t, string sql, params (string Name, object Value)[] args)
    {
        using SqliteCommand q = Command(c, t, sql, args);
        return Convert.ToInt32(q.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }
}
