using System.Security.Cryptography;
using System.Text.Json;
using NetSec.Keys;
using NetSec.Pki;

namespace NetSec.Host.Security;

public sealed record KeyBinding(string Provider, int Version, string? KeyFile, string? KeyHash);
public sealed record TypeEntry(string Mode, KeyBinding? Binding, int CheckedVersion);
public sealed record ModesFile(bool ShowKeys, Dictionary<string, TypeEntry> Types);

/// <summary>modes.json and the key files under .security/. Each write replaces the whole value and the file, so a reader never sees half a change.</summary>
public sealed class SecurityStore
{
    public const string ModeBuiltIn = "BuiltIn", ModeMine = "Mine";
    public const string StateBuiltIn = "BuiltIn", StateUnconfigured = "Unconfigured", StateConfigured = "Configured", StateVerified = "Verified", StateBroken = "Broken";
    const string ProviderFile = "file";

    static readonly JsonSerializerOptions Json = new(JsonSerializerOptions.Web) { WriteIndented = true };

    readonly Lock _gate = new();
    readonly string _modesPath;
    readonly Dictionary<string, string> _flowOf;
    ModesFile _modes;

    public string Root { get; }

    public SecurityStore(string root, WizardTable table)
    {
        Root = root;
        _modesPath = Path.Combine(root, "modes.json");
        _flowOf = table.Flows.SelectMany(f => f.Types.Select(t => (t, f.FlowId))).ToDictionary(p => p.t, p => p.FlowId);
        _modes = File.Exists(_modesPath)
            ? JsonSerializer.Deserialize<ModesFile>(File.ReadAllText(_modesPath), Json) ?? Empty()
            : Empty();
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

    public void SetShowKeys(bool on)
    {
        lock (_gate) Save(_modes with { ShowKeys = on });
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

    /// <summary>A type with no private half of its own, such as a trust list that follows its root.</summary>
    public void PlaceDerived(string typeId)
    {
        lock (_gate)
        {
            TypeEntry e = EntryOf(_modes, typeId);
            Put(typeId, e with { Mode = ModeMine, Binding = new KeyBinding("follows", (e.Binding?.Version ?? 0) + 1, null, null) });
        }
    }

    public void MarkChecked(string typeId)
    {
        lock (_gate)
        {
            TypeEntry e = EntryOf(_modes, typeId);
            if (e.Binding is not null) Put(typeId, e with { CheckedVersion = e.Binding.Version });
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

    /// <summary>The snapshot a session runs on: each own key whose mode is Mine. Every other type stays built-in.</summary>
    public CredentialSet Credentials() => new(new TrainingKeySource(), SecurityTypes.All.Select(Open).OfType<Credential>().ToArray());

    /// <summary>The learner's key for a type, whatever its mode. Null when none is placed.</summary>
    public ITrainingKey? PlacedKey(string typeId)
    {
        KeyBinding? b = Entry(typeId).Binding;
        return b?.KeyFile is null ? null : KeyFileReader.ReadPrivateKey(FullPath(b.KeyFile), typeId);
    }

    Credential? Open(string typeId)
    {
        TypeEntry e = Entry(typeId);
        if (e.Mode != ModeMine || e.Binding is null) return null;
        ITrainingKey? key = PlacedKey(typeId);
        return new Credential(typeId, CredentialMode.Mine, e.Binding.Provider, e.Binding.Version, key is null ? "" : FingerprintOf(key.CopyPublic()), key);
    }

    public static string FingerprintOf(byte[] publicPart) => "SHA256:" + Convert.ToBase64String(SHA256.HashData(publicPart)).TrimEnd('=');

    string FullPath(string relative) => Path.Combine(Root, relative);

    static string? HashOf(string path) => File.Exists(path) ? Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))) : null;

    void Put(string typeId, TypeEntry entry) => Save(_modes with { Types = new Dictionary<string, TypeEntry>(_modes.Types) { [typeId] = entry } });

    void Save(ModesFile next)
    {
        Directory.CreateDirectory(Root);
        string readme = Path.Combine(Root, "README.txt");
        if (!File.Exists(readme)) File.WriteAllText(readme, "This folder holds your test keys for MMP.NetworkSecurity. Git ignores it. Use test keys only: this course shows your keys on screen and in saved files.\n");
        string temp = _modesPath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(next, Json));
        File.Move(temp, _modesPath, overwrite: true);
        _modes = next;
    }
}
