using System.Threading;
using System.Security.Cryptography;
using System.Text.Json;
using NetSec.Keys;
using NetSec.Pki;
using NetSec.Vault;

namespace NetSec.Host.Security;

public sealed record KeyBinding(string Provider, int Version, string? KeyFile, string? KeyHash);
public sealed record TypeEntry(string Mode, KeyBinding? Binding, int CheckedVersion, string? Judge = null, string? Says = null);
public sealed record ModesFile(bool ShowKeys, Dictionary<string, TypeEntry> Types);

/// <summary>modes.json and the key files under .security/. Each write replaces the whole value and the file, so a reader never sees half a change.</summary>
public sealed class SecurityStore
{
    public const string ModeBuiltIn = "BuiltIn", ModeMine = "Mine";
    public const string StateBuiltIn = "BuiltIn", StateUnconfigured = "Unconfigured", StateConfigured = "Configured", StateVerified = "Verified", StateBroken = "Broken";
    const string ProviderFile = "file";
    const string ByteKeyFile = "key.hex";
    public const string ProviderVault = "vault";

    /// <summary>The caller name a flow's own review and check use when they read a key out of the vault.</summary>
    public const string CallerFlow = "host/flow";
    public const string CallerMoveV0 = "host/move-v0-file";

    /// <summary>
    /// The one readiness answer, used by GET /api/security/readiness and by session.start alike. After the state rules pass,
    /// each vault key the lesson reads is probed, so a changed row or master.key is refused here by name rather than later at the export.
    /// </summary>
    public LabDecision Decide(string[] typesTheLabReads)
    {
        LabDecision byState = SecurityReadiness.Decide(typesTheLabReads, States());
        if (!byState.MayRun) return byState;
        TypeProblem[] vault = typesTheLabReads
            .Select(t => (Type: t, Entry: Entry(t)))
            .Where(p => p.Entry.Mode == ModeMine && p.Entry.Binding?.Provider == ProviderVault)
            .Select(p => (p.Type, Code: Vault.Probe(p.Type, p.Entry.Binding!.Version)))
            .Where(p => p.Code is not null)
            .Select(p => new TypeProblem(p.Type, p.Code!, $"{p.Type} version {Entry(p.Type).Binding!.Version} does not open in the vault ({p.Code}). Run the flow {FlowOf(p.Type)} again."))
            .ToArray();
        return vault.Length == 0 ? byState : new LabDecision(vault);
    }

    /// <summary>The types whose keys live in the vault (slice V1: the my-login flow). The others stay key files until their slice moves them.</summary>
    static readonly HashSet<string> VaultTypes = [SecurityTypes.TokenIssuer, SecurityTypes.DeviceEnrolment];

    /// <summary>A flow's key may leave the vault, because a glass engine reads its bytes. Only the vault exercise makes keys that cannot.</summary>
    static readonly VaultKeyPolicy FlowKeyPolicy = new(VaultAlgorithms.Ed25519, true, [VaultOps.Export]);

    static readonly JsonSerializerOptions Json = new(JsonSerializerOptions.Web) { WriteIndented = true };

    readonly Lock _gate = new();
    readonly string _modesPath;
    readonly Dictionary<string, string> _flowOf;
    ModesFile _modes;

    // The restart gap (issue #292): true while memory holds a choice the file does not, after a refused save of Show keys off.
    bool _unsaved;
    Timer? _retry;

    public string Root { get; }
    public IVault Vault { get; }

    public SecurityStore(string root, WizardTable table)
    {
        Root = root;
        Vault = new SqliteVault(Path.Combine(root, "vault"));
        _modesPath = Path.Combine(root, "modes.json");
        _flowOf = table.Flows.SelectMany(f => f.Types.Select(t => (t, f.FlowId))).ToDictionary(p => p.t, p => p.FlowId);
        _modes = File.Exists(_modesPath) ? ReadModes(_modesPath) : Empty();
        MoveV0KeyFiles();
    }

    static ModesFile ReadModes(string path)
    {
        try { return JsonSerializer.Deserialize<ModesFile>(File.ReadAllText(path), Json) ?? Empty(); }
        catch (JsonException e) { throw new InvalidDataException($"{path} cannot be read: {e.Message} Fix the file, or delete it to start again with built-in keys.", e); }
    }

    static ModesFile Empty() => new(true, []);

    /// <summary>NETSEC_SECURITY_DIR wins. Else .security/ in the repository this Host runs from, found by walking up, as Program.cs finds docs/_runs.</summary>
    public static string ResolveRoot(Func<string, string?> env, string baseDirectory)
    {
        string? set = env("NETSEC_SECURITY_DIR");
        if (!string.IsNullOrEmpty(set)) return set;
        for (DirectoryInfo? dir = new(baseDirectory); dir is not null; dir = dir.Parent)
            if (Directory.Exists(Path.Combine(dir.FullName, ".git")) || File.Exists(Path.Combine(dir.FullName, ".git")))
                return Path.Combine(dir.FullName, ".security");
        return Path.Combine(baseDirectory, ".security");
    }

    public bool ShowKeys { get { lock (_gate) return _modes.ShowKeys; } }

    /// <summary>False while memory holds a Show keys choice that modes.json does not, so a restart would lose it. The page shows "not saved yet".</summary>
    public bool Saved { get { lock (_gate) return !_unsaved; } }

    /// <summary>Raised once, outside the lock, when the background retry has saved the choice that a refused save left only in memory.</summary>
    public event Action? SaveHealed;

    const int RetryEveryMs = 500;

    /// <summary>
    /// Saves the Show keys choice. Off fails closed (issue #292): when the save is refused, off still takes effect in memory at once, and
    /// the error says only that the choice was not saved for the next start. On fails open: a refused save keeps keys hidden.
    /// </summary>
    public void SetShowKeys(bool on)
    {
        lock (_gate)
        {
            ModesFile next = _modes with { ShowKeys = on };
            try { Save(next); }
            catch (NetSec.Errors.NetSecException x) when (!on && x.Error.Code == NetSec.Errors.ErrorCodes.SecurityStoreSaveFailed)
            {
                _modes = next;
                _unsaved = true;
                _retry ??= new Timer(_ => RetrySave(), null, RetryEveryMs, RetryEveryMs);
                throw new NetSec.Errors.NetSecException(NetSec.Errors.NetSecError.Of(x.Error.Code,
                    $"Show keys is off now. The choice is not saved yet; the Host keeps trying, and until then a restart may show keys again. {x.Error.Message}"));
            }
        }
    }

    /// <summary>
    /// The background retry for the restart gap. Each tick makes one try, so it never holds _gate for the full retry budget. Any later
    /// save also writes the whole of _modes, so it heals the gap too; the next tick then sees _unsaved false and stops.
    /// </summary>
    void RetrySave()
    {
        lock (_gate)
        {
            if (_retry is null) return;
            if (!Directory.Exists(Root)) { StopRetry(); return; }
            if (_unsaved)
            {
                try { Save(_modes, tries: 1); }
                catch (Exception e) when (e is NetSec.Errors.NetSecException or IOException or UnauthorizedAccessException) { return; }
            }
            StopRetry();
        }
        SaveHealed?.Invoke();
    }

    void StopRetry()
    {
        _retry?.Dispose();
        _retry = null;
    }

    public string FlowOf(string typeId) => _flowOf[typeId];

    TypeEntry EntryOf(ModesFile m, string typeId) => m.Types.GetValueOrDefault(typeId) ?? new TypeEntry(ModeBuiltIn, null, 0);

    public TypeEntry Entry(string typeId)
    {
        lock (_gate) return EntryOf(_modes, typeId);
    }

    public string StateOf(string typeId)
    {
        TypeEntry e = Entry(typeId);
        if (e.Mode != ModeMine) return StateBuiltIn;
        if (e.Binding is null) return StateUnconfigured;
        if (e.Binding.KeyFile is not null && HashOf(FullPath(e.Binding.KeyFile)) != e.Binding.KeyHash) return StateBroken;
        return e.CheckedVersion == e.Binding.Version ? StateVerified : StateConfigured;
    }

    public void SetMode(string typeId, string mode)
    {
        lock (_gate) Put(typeId, EntryOf(_modes, typeId) with { Mode = mode });
    }

    /// <summary>Writes a new version of a type's key and makes it the active one. The old version stays on disk, so a failed check loses nothing.</summary>
    public void PlaceKey(string typeId, string pem)
    {
        if (VaultTypes.Contains(typeId)) { PlaceInVault(typeId, KeyFileReader.Parse(pem, typeId).CopyMaterial()); return; }
        lock (_gate)
        {
            TypeEntry e = EntryOf(_modes, typeId);
            int version = (e.Binding?.Version ?? 0) + 1;
            string relative = Path.Combine("files", typeId, "v" + version, "key.pem");
            string full = FullPath(relative);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, pem);
            Put(typeId, e with { Mode = ModeMine, Binding = new KeyBinding(ProviderFile, version, relative, HashOf(full)) });
        }
    }

    /// <summary>A key that is plain bytes, as hex in its file. As with PlaceKey, the old version stays on disk.</summary>
    public void PlaceBytes(string typeId, byte[] key)
    {
        lock (_gate)
        {
            TypeEntry e = EntryOf(_modes, typeId);
            int version = (e.Binding?.Version ?? 0) + 1;
            string relative = Path.Combine("files", typeId, "v" + version, ByteKeyFile);
            string full = FullPath(relative);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, Convert.ToHexString(key).ToLowerInvariant());
            Put(typeId, e with { Mode = ModeMine, Binding = new KeyBinding(ProviderFile, version, relative, HashOf(full)) });
        }
    }

    /// <summary>The key goes in as a new version of the vault key named for the type. The key's policy was set when the first version went in, and stays.</summary>
    /// <summary>
    /// A folder made before slice V1 holds the my-login keys as key.pem files. On first start each one moves into the vault, under the caller
    /// host/move-v0-file so the audit list names the move, and the file goes once the vault holds it. A checked key stays checked: the bytes are the same.
    /// A file that will not read, or a vault that will not take it, stays where it is, and the type shows its problem by name as before.
    /// </summary>
    void MoveV0KeyFiles()
    {
        foreach (string typeId in VaultTypes)
        {
            TypeEntry e = Entry(typeId);
            if (e.Mode != ModeMine || e.Binding is not { Provider: ProviderFile, KeyFile: { } file } || StateOf(typeId) == StateBroken) continue;
            string full = FullPath(file);
            bool wasChecked = e.CheckedVersion == e.Binding.Version;
            try { PlaceInVault(typeId, KeyFileReader.ReadPrivateKey(full, typeId).CopyMaterial(), CallerMoveV0); }
            catch (NetSec.Errors.NetSecException) { continue; }
            lock (_gate)
            {
                TypeEntry moved = EntryOf(_modes, typeId);
                if (wasChecked) Put(typeId, moved with { CheckedVersion = moved.Binding!.Version });
            }
            File.Delete(full);
        }
    }

    void PlaceInVault(string typeId, byte[] seed, string? caller = null)
    {
        caller ??= "host/flow-" + FlowOf(typeId);
        int version = Vaulted(() =>
        {
            if (!Vault.Exists(typeId)) Vault.CreateKey(typeId, FlowKeyPolicy, caller);
            return Vault.Import(typeId, seed, caller);
        });
        lock (_gate) Put(typeId, EntryOf(_modes, typeId) with { Mode = ModeMine, Binding = new KeyBinding(ProviderVault, version, null, null) });
    }

    /// <summary>A vault refusal keeps its own code (VAULT_UNWRAP_FAILED, VAULT_AUDIT_FAILED, ...) on its way to the screen and the session.</summary>
    static T Vaulted<T>(Func<T> call)
    {
        try { return call(); }
        catch (VaultException e) { throw new NetSec.Errors.NetSecException(NetSec.Errors.NetSecError.Of(e.Code, e.Message)); }
    }

    /// <summary>A type with no private half of its own, such as a trust list that follows its root.</summary>
    public void PlaceDerived(string typeId)
    {
        lock (_gate)
        {
            TypeEntry e = EntryOf(_modes, typeId);
            Put(typeId, e with { Mode = ModeMine, Binding = new KeyBinding("follows", (e.Binding?.Version ?? 0) + 1, null, null) });
        }
    }

    public void MarkChecked(string typeId, string judge, string says)
    {
        lock (_gate)
        {
            TypeEntry e = EntryOf(_modes, typeId);
            if (e.Binding is not null) Put(typeId, e with { CheckedVersion = e.Binding.Version, Judge = judge, Says = says });
        }
    }

    public SecurityTypeState[] States() => SecurityTypes.All.Select(id => new SecurityTypeState
    {
        TypeId = id,
        FlowId = FlowOf(id),
        Mode = Entry(id).Mode == ModeMine ? CredentialMode.Mine : CredentialMode.BuiltIn,
        Readiness = StateOf(id) switch
        {
            StateUnconfigured => Readiness.Unconfigured,
            StateConfigured => Readiness.Configured,
            StateBroken => Readiness.Broken,
            _ => Readiness.Ready,
        },
    }).ToArray();

    /// <summary>The snapshot a session runs on: each own key whose mode is Mine, among the types the lesson reads. A broken key in any other type cannot stop this lesson.</summary>
    /// <summary>The caller (host/lab-&lt;n&gt;) goes on the vault's audit row of each key the set takes out.</summary>
    public CredentialSet Credentials(string[] typesTheLabReads, string caller) =>
        new(new TrainingKeySource(), typesTheLabReads.Select(t => Open(t, caller)).OfType<Credential>().ToArray());

    /// <summary>The learner's key for a type, whatever its mode. Null when none is placed. A vault key comes out by Export, audited under the caller.</summary>
    public ITrainingKey? PlacedKey(string typeId, string caller = CallerFlow)
    {
        KeyBinding? b = Entry(typeId).Binding;
        if (b?.Provider == ProviderVault) return new SeedKey(typeId, Vaulted(() => Vault.Export(typeId, caller, b.Version)));
        if (b?.KeyFile is null) return null;
        return Path.GetFileName(b.KeyFile) == ByteKeyFile ? ReadBytesKey(typeId, FullPath(b.KeyFile)) : KeyFileReader.ReadPrivateKey(FullPath(b.KeyFile), typeId);
    }

    Credential? Open(string typeId, string caller)
    {
        TypeEntry e = Entry(typeId);
        if (e.Mode != ModeMine || e.Binding is null) return null;
        ITrainingKey? key;
        try { key = PlacedKey(typeId, caller); }
        catch (NetSec.Errors.NetSecException x) when (!x.Error.Code.StartsWith("VAULT_", StringComparison.Ordinal))
        {
            throw new NetSec.Errors.NetSecException(NetSec.Errors.NetSecError.Of(NetSec.Errors.ErrorCodes.SecurityTypeNotReady, $"{typeId} cannot be read: {x.Error.Message} Run the flow {FlowOf(typeId)} again."));
        }
        return new Credential(typeId, CredentialMode.Mine, e.Binding.Provider, e.Binding.Version, key is null ? "" : FingerprintOf(key.CopyPublic()), key);
    }

    public static string FingerprintOf(byte[] publicPart) => Fingerprints.OfPublic(publicPart);

    static ITrainingKey ReadBytesKey(string typeId, string path)
    {
        try { return new BytesKey(typeId, Convert.FromHexString(File.ReadAllText(path).Trim())); }
        catch (FormatException) { throw new NetSec.Errors.NetSecException(NetSec.Errors.NetSecError.Of(NetSec.Errors.ErrorCodes.KeyFileFormat, $"{typeId}: the key file does not hold hex.")); }
        catch (IOException e) { throw new NetSec.Errors.NetSecException(NetSec.Errors.NetSecError.Of(NetSec.Errors.ErrorCodes.KeyFileUnreadable, $"{typeId}: {e.Message}")); }
    }

    /// <summary>
    /// A symmetric key has no public half. Its "public" part is a hash that cannot give the key back, so a fingerprint can tell 2 keys apart
    /// with Show keys off. Empty bytes would give every such key one fingerprint.
    /// </summary>
    sealed class BytesKey(string keyId, byte[] key) : ITrainingKey
    {
        static readonly byte[] Label = System.Text.Encoding.ASCII.GetBytes("MMP.NetworkSecurity lesson key fingerprint");
        public string KeyId => keyId;
        public KeyAlgorithm Algorithm => KeyAlgorithm.Raw;
        public byte[] CopyMaterial() => (byte[])key.Clone();
        public byte[] CopyPublic() => SHA256.HashData([.. Label, .. key]);
    }

    /// <summary>An Ed25519 seed taken out of the vault, in the shape the glass engines read.</summary>
    sealed class SeedKey(string keyId, byte[] seed) : ITrainingKey
    {
        readonly byte[] _public = NetSec.Crypto.Ed25519.PublicFrom(seed);
        public string KeyId => keyId;
        public KeyAlgorithm Algorithm => KeyAlgorithm.Ed25519;
        public byte[] CopyMaterial() => (byte[])seed.Clone();
        public byte[] CopyPublic() => (byte[])_public.Clone();
    }

    string FullPath(string relative) => Path.Combine(Root, relative);

    static string? HashOf(string path) => File.Exists(path) ? Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))) : null;

    void Put(string typeId, TypeEntry entry) => Save(_modes with { Types = new Dictionary<string, TypeEntry>(_modes.Types) { [typeId] = entry } });

    /// <summary>Writes next to modes.json and makes it the value in force. next is always a whole file, so a success also ends the restart gap.</summary>
    void Save(ModesFile next, int tries = ReplaceTries)
    {
        Directory.CreateDirectory(Root);
        string readme = Path.Combine(Root, "README.txt");
        if (!File.Exists(readme)) File.WriteAllText(readme, "This folder holds your test keys for MMP.NetworkSecurity. Git ignores it. Use test keys only: this course shows your keys on screen and in saved files.\n");
        string temp = _modesPath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(next, Json));
        ReplaceModes(temp, tries);
        _modes = next;
        _unsaved = false;
    }

    // On Windows a replacing move fails while another handle holds the target open without delete sharing. An antivirus scan or the search
    // indexer often opens a file that was just written, so the move waits out a short hold (issue #292).
    // The wait happens inside _gate, and every reader of ShowKeys and the modes takes _gate. So during a hold those readers wait too, for
    // up to about 1 s. A hold is rare and short, so this is accepted.
    const int ReplaceTries = 20, ReplaceWaitMs = 50;

    /// <summary>Moves the temp file over modes.json, trying up to tries times. After that it fails with SECURITY_STORE_SAVE_FAILED, and the old file stays.</summary>
    void ReplaceModes(string temp, int tries)
    {
        for (int attempt = 1; ; attempt++)
        {
            try { File.Move(temp, _modesPath, overwrite: true); return; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                if (attempt >= tries)
                    throw new NetSec.Errors.NetSecException(NetSec.Errors.NetSecError.Of(NetSec.Errors.ErrorCodes.SecurityStoreSaveFailed,
                        $"{_modesPath} could not be saved, possibly because another program held it open, after {tries} tries over {tries * ReplaceWaitMs} ms ({e.Message}) Close any program that has the file open, then try again."));
                Thread.Sleep(ReplaceWaitMs);
            }
        }
    }
}
