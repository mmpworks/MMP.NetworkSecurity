using System.Text.Json;

namespace NetSec.Host.Security;

public sealed record WizardRow(string From, string Event, string To, string? Guard, string? Effect);
public sealed record WizardFlow(string FlowId, string[] Types);
public sealed record WizardStateRow(string State, string Kind);

/// <summary>The rows of wizard-flows.json. A flow, a state, or a move is a data edit.</summary>
public sealed class WizardTable
{
    public const string FirstState = "Intro";
    public const string GuardCheckPassed = "checkPassed";
    public const string EffectMakeAll = "makeAll", EffectImportFiles = "importFiles", EffectRunCheck = "runCheck";
    static readonly HashSet<string?> KnownGuards = [null, GuardCheckPassed];
    static readonly HashSet<string?> KnownEffects = [null, EffectMakeAll, EffectImportFiles, EffectRunCheck];

    public IReadOnlyList<WizardFlow> Flows { get; }
    public IReadOnlyList<WizardRow> Rows { get; }
    readonly Dictionary<string, string> _kinds;

    public WizardTable(IReadOnlyList<WizardFlow> flows, IReadOnlyList<WizardStateRow> states, IReadOnlyList<WizardRow> rows)
    {
        Flows = flows;
        Rows = rows;
        _kinds = states.ToDictionary(s => s.State, s => s.Kind);
        foreach (WizardRow row in rows)
        {
            if (!_kinds.ContainsKey(row.From) || !_kinds.ContainsKey(row.To)) throw new InvalidDataException($"wizard-flows.json: the row {row.From} {row.Event} {row.To} names an unknown state.");
            if (!KnownGuards.Contains(row.Guard)) throw new InvalidDataException($"wizard-flows.json: the guard '{row.Guard}' has no code.");
            if (!KnownEffects.Contains(row.Effect)) throw new InvalidDataException($"wizard-flows.json: the effect '{row.Effect}' has no code.");
        }
    }

    public static WizardTable Load(string path) => Parse(File.ReadAllText(path));

    public static WizardTable Parse(string json)
    {
        using JsonDocument doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;
        return new WizardTable(
            root.GetProperty("flows").EnumerateArray().Select(f => new WizardFlow(f.GetProperty("flowId").GetString()!, f.GetProperty("types").EnumerateArray().Select(t => t.GetString()!).ToArray())).ToList(),
            root.GetProperty("states").EnumerateArray().Select(s => new WizardStateRow(s.GetProperty("state").GetString()!, s.GetProperty("kind").GetString()!)).ToList(),
            root.GetProperty("spine").EnumerateArray().Select(r => new WizardRow(r.GetProperty("from").GetString()!, r.GetProperty("event").GetString()!, r.GetProperty("to").GetString()!, Optional(r, "guard"), Optional(r, "effect"))).ToList());
    }

    static string? Optional(JsonElement row, string name) => row.TryGetProperty(name, out JsonElement v) ? v.GetString() : null;

    public WizardFlow? Flow(string flowId) => Flows.FirstOrDefault(f => f.FlowId == flowId);
    public string KindOf(string state) => _kinds[state];
    public string[] AllowedFrom(string state) => Rows.Where(r => r.From == state).Select(r => r.Event).ToArray();
}

public sealed record WizardDecision(WizardRow? Row, string? RefusedCode, string? RefusedMessage);

/// <summary>The machine owns the moves. Pure: it decides, and FlowRuns applies the effect. An event with no row is refused by name.</summary>
public static class WizardMachine
{
    public const string EventNotAllowed = "WIZARD_EVENT_NOT_ALLOWED";
    public const string CheckNotDone = "WIZARD_CHECK_NOT_DONE";

    public static WizardDecision Decide(WizardTable table, string state, string? eventName, bool checkPassed)
    {
        WizardRow? row = table.Rows.FirstOrDefault(r => r.From == state && r.Event == eventName);
        if (row is null) return new WizardDecision(null, EventNotAllowed, $"The event '{eventName}' is not allowed in the state '{state}'.");
        if (row.Guard == WizardTable.GuardCheckPassed && !checkPassed) return new WizardDecision(null, CheckNotDone, "The check has not passed yet.");
        return new WizardDecision(row, null, null);
    }
}
