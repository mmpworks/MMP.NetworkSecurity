using System.Text.Json;
using NetSec.Errors;

namespace NetSec.Host.Security;

public sealed record StepMessage(string Code, string Message, string? TypeId);

/// <summary>One run of a flow. Saved without a secret, so a learner who quits comes back to the same step.</summary>
public sealed record FlowRun(string RunId, string FlowId, string State, int StepSeq, bool CheckPassed, bool Finished);

public sealed record RunReply(FlowRun Run, IReadOnlyList<StepMessage> Errors, IReadOnlyList<StepMessage> Warnings, IReadOnlyList<object> Facts);
public sealed record RunRefusal(int Status, string Code, string Message);

/// <summary>Applies what WizardMachine decides. The machine owns the moves. This class owns the side effects: keys placed, tools run, runs saved.</summary>
public sealed class FlowRuns
{
    public const string StepStale = "WIZARD_STEP_STALE", RunNotFound = "WIZARD_RUN_NOT_FOUND", FlowUnknown = "WIZARD_FLOW_UNKNOWN", PartNotBuilt = "WIZARD_PART_NOT_BUILT", TypeNotInFlow = "WIZARD_TYPE_NOT_IN_FLOW";
    public const string PathPersonal = "KEY_PATH_PERSONAL";
    const string CheckState = "Check", ReviewState = "Review";

    readonly Lock _gate = new();
    readonly Dictionary<string, FlowRun> _runs = [];
    readonly Dictionary<string, IReadOnlyList<object>> _checkFacts = [];
    readonly WizardTable _table;
    readonly SecurityStore _store;
    readonly FlowParts _parts;
    readonly string _runsDir;
    readonly string _personalSsh;

    public WizardTable Table => _table;

    public FlowRuns(WizardTable table, SecurityStore store, FlowParts parts, string profileDirectory)
    {
        _table = table;
        _store = store;
        _parts = parts;
        _runsDir = Path.Combine(store.Root, "runs");
        _personalSsh = Path.Combine(profileDirectory, ".ssh") + Path.DirectorySeparatorChar;
        if (!Directory.Exists(_runsDir)) return;
        foreach (string file in Directory.GetFiles(_runsDir, "*.json"))
        {
            FlowRun? run = JsonSerializer.Deserialize<FlowRun>(File.ReadAllText(file), JsonSerializerOptions.Web);
            if (run is not null) _runs[run.RunId] = run;
        }
    }

    public string? OpenRunOf(string flowId)
    {
        lock (_gate) return _runs.Values.Where(r => r.FlowId == flowId && !r.Finished).Select(r => r.RunId).LastOrDefault();
    }

    public RunReply? Start(string flowId)
    {
        if (_table.Flow(flowId) is null) return null;
        FlowRun run = new("r" + Guid.NewGuid().ToString("N")[..12], flowId, WizardTable.FirstState, 1, false, false);
        lock (_gate) Save(run);
        return new RunReply(run, [], [], []);
    }

    public RunReply? Find(string runId)
    {
        lock (_gate)
        {
            if (!_runs.TryGetValue(runId, out FlowRun? run)) return null;
            List<StepMessage> errors = [];
            IReadOnlyList<object> facts = FactsOf(run, errors);
            return new RunReply(run, errors, [], facts);
        }
    }

    public (RunReply? Reply, RunRefusal? Refusal) Apply(string runId, string? eventName, int stepSeq, JsonElement data)
    {
        lock (_gate)
        {
            if (!_runs.TryGetValue(runId, out FlowRun? run)) return (null, new RunRefusal(404, RunNotFound, $"No flow run has the id {runId}."));
            if (stepSeq != run.StepSeq) return (null, new RunRefusal(409, StepStale, $"Step {stepSeq} is old. This run is at step {run.StepSeq}."));
            WizardDecision decision = WizardMachine.Decide(_table, run.State, eventName, run.CheckPassed);
            if (decision.Row is null) return (null, new RunRefusal(409, decision.RefusedCode!, decision.RefusedMessage!));

            List<StepMessage> errors = [], warnings = [];
            try { ApplyEffect(run, decision.Row, data, errors, warnings); }
            catch (NetSecException e) { errors.Add(new StepMessage(e.Error.Code, e.Error.Message, null)); }
            string next = errors.Count == 0 ? decision.Row.To : run.State;
            FlowRun moved = run with
            {
                State = next,
                StepSeq = run.StepSeq + 1,
                CheckPassed = (decision.Row.Effect == WizardTable.EffectRunCheck ? errors.Count == 0 : run.CheckPassed) && next == CheckState,
                Finished = _table.KindOf(next) == "done",
            };
            Save(moved);
            IReadOnlyList<object> facts = FactsOf(moved, errors);
            return (new RunReply(moved, errors, warnings, facts), null);
        }
    }

    IReadOnlyList<object> FactsOf(FlowRun run, List<StepMessage> errors)
    {
        if (run.State == ReviewState)
        {
            try { return _table.Flow(run.FlowId)!.Types.Select(t => (object)_parts.Review(t)).ToList(); }
            catch (NetSecException e)
            {
                errors.Add(new StepMessage(e.Error.Code, e.Error.Message, null));
                return [];
            }
        }
        if (run.State == CheckState && _checkFacts.TryGetValue(run.RunId, out IReadOnlyList<object>? facts)) return facts;
        return [];
    }

    void ApplyEffect(FlowRun run, WizardRow row, JsonElement data, List<StepMessage> errors, List<StepMessage> warnings)
    {
        switch (row.Effect)
        {
            case WizardTable.EffectMakeAll: MakeAll(run.FlowId, errors); break;
            case WizardTable.EffectImportFiles: ImportFiles(run.FlowId, data, errors, warnings); break;
            case WizardTable.EffectRunCheck: RunCheck(run, errors); break;
        }
    }

    void MakeAll(string flowId, List<StepMessage> errors)
    {
        string[] types = _table.Flow(flowId)!.Types;
        foreach (string typeId in types.Where(t => !FlowParts.IsBuilt(t)))
            errors.Add(new StepMessage(PartNotBuilt, $"The course cannot make {typeId} yet.", typeId));
        if (errors.Count == 0) foreach (string typeId in types) _parts.Make(typeId);
    }

    void ImportFiles(string flowId, JsonElement data, List<StepMessage> errors, List<StepMessage> warnings)
    {
        string[] types = _table.Flow(flowId)!.Types;
        if (data.ValueKind != JsonValueKind.Object || !data.TryGetProperty("paths", out JsonElement paths) || paths.ValueKind != JsonValueKind.Object)
        {
            errors.Add(new StepMessage(ErrorCodes.KeyFileUnreadable, "Choose a file for at least one key.", null));
            return;
        }
        Dictionary<string, string> chosen = paths.EnumerateObject().Where(p => p.Value.ValueKind == JsonValueKind.String).ToDictionary(p => p.Name, p => p.Value.GetString()!);
        if (chosen.Count == 0)
        {
            errors.Add(new StepMessage(ErrorCodes.KeyFileUnreadable, "Choose a file for at least one key.", null));
            return;
        }
        foreach ((string typeId, string path) in chosen)
        {
            if (IsPersonal(path))
                warnings.Add(new StepMessage(PathPersonal, "This file is in your own .ssh folder, so it may be a key you use every day. This course shows every key. Use a test key.", typeId));
            if (Array.IndexOf(types, typeId) < 0) errors.Add(new StepMessage(TypeNotInFlow, $"{typeId} is not one of the keys this set makes.", typeId));
            else ReadOne(typeId, path, errors);
        }
        if (errors.Count > 0) return;
        foreach (string typeId in types)
        {
            if (chosen.TryGetValue(typeId, out string? path)) _store.PlaceKey(typeId, File.ReadAllText(path));
            else _parts.Make(typeId);
        }
    }

    /// <summary>A blank or malformed path is no personal path. ReadOne then names it as unreadable.</summary>
    bool IsPersonal(string path)
    {
        const string LongForm = @"\\?\";
        string plain = path.StartsWith(LongForm, StringComparison.Ordinal) ? path[LongForm.Length..] : path;
        try { return Path.GetFullPath(plain).StartsWith(_personalSsh, StringComparison.OrdinalIgnoreCase); }
        catch (ArgumentException) { return false; }
        catch (NotSupportedException) { return false; }
    }

    static void ReadOne(string typeId, string path, List<StepMessage> errors)
    {
        if (!FlowParts.CanImport(typeId))
        {
            errors.Add(new StepMessage(PartNotBuilt, $"The course cannot read a file for {typeId} yet.", typeId));
            return;
        }
        try
        {
            NetSec.Keys.KeyAlgorithm algorithm = NetSec.Pki.KeyFileReader.ReadPrivateKey(path, typeId).Algorithm;
            if (algorithm != FlowParts.ImportedAlgorithm(typeId))
                errors.Add(new StepMessage(ErrorCodes.KeyAlgorithmNotInEngine, $"{typeId} takes an {FlowParts.ImportedAlgorithm(typeId)} key, and this key is {algorithm}.", typeId));
        }
        catch (NetSecException e) { errors.Add(new StepMessage(e.Error.Code, e.Error.Message, typeId)); }
    }

    void RunCheck(FlowRun run, List<StepMessage> errors)
    {
        string dir = Path.Combine(_store.Root, "proof", run.RunId);
        List<object> facts = [];
        try
        {
            foreach (string typeId in _table.Flow(run.FlowId)!.Types)
            {
                CheckFact fact = CheckOne(typeId, dir);
                facts.Add(fact);
                if (fact.Passed) _store.MarkChecked(typeId, fact.Judge, fact.Says);
                else errors.Add(new StepMessage(fact.Code!, fact.Message!, typeId));
            }
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
        _checkFacts[run.RunId] = facts;
    }

    /// <summary>A key that will not open is a failed check with its name, and the other types still get theirs.</summary>
    CheckFact CheckOne(string typeId, string dir)
    {
        try { return _parts.Check(typeId, dir); }
        catch (NetSecException e) { return new CheckFact(typeId, FlowParts.JudgeOf(typeId), FlowParts.SaysOf(typeId), "", "", false, e.Error.Code, e.Error.Message); }
    }

    void Save(FlowRun run)
    {
        _runs[run.RunId] = run;
        Directory.CreateDirectory(_runsDir);
        File.WriteAllText(Path.Combine(_runsDir, run.RunId + ".json"), JsonSerializer.Serialize(run, JsonSerializerOptions.Web));
    }
}
