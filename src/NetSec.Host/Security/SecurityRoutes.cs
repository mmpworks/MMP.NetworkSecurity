using System.Text.Json;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Labs;
using NetSec.Trace;

namespace NetSec.Host.Security;

/// <summary>The routes of docs/modes-design.md section 8.3, in the shapes of acceptance/CONTRACT.md section 5.1. Words live in app/src/wizard-copy.json, keyed by id.</summary>
public static class SecurityRoutes
{
    const string TestKeysLine = "wizard.common.test-keys-only";

    /// <summary>The caller name on the vault audit row each read of this route writes.</summary>
    public const string KeyRouteCaller = "host/key-route";

    /// <summary>showKeysChanged tells every socket of a flip, so the UI replaces each open session from /events.</summary>
    public static void Map(WebApplication app, SecurityStore store, FlowRuns runs, Action<bool> showKeysChanged)
    {
        app.MapGet("/api/security", () => Results.Json(new
        {
            schema = 1,
            root = store.Root,
            showKeys = store.ShowKeys,
            flows = runs.Table.Flows.Select(f => new { flowId = f.FlowId, types = f.Types, openRunId = runs.OpenRunOf(f.FlowId) }),
            types = SecurityTypes.All.Select(id => TypeRow(store, id)),
        }));
        app.MapPut("/api/security/types/{typeId}/mode", (string typeId, ModeBody body) =>
        {
            if (Array.IndexOf(SecurityTypes.All, typeId) < 0) return Refuse(404, "SECURITY_TYPE_UNKNOWN", $"No security type has the id {typeId}.");
            if (body.Mode is not (SecurityStore.ModeBuiltIn or SecurityStore.ModeMine)) return Refuse(400, "SECURITY_MODE_UNKNOWN", $"The mode must be {SecurityStore.ModeBuiltIn} or {SecurityStore.ModeMine}.");
            try { store.SetMode(typeId, body.Mode); }
            catch (NetSecException x) when (x.Error.Code == ErrorCodes.SecurityStoreSaveFailed) { return SaveRefused(x); }
            return Results.Json(TypeRow(store, typeId));
        });
        app.MapGet("/api/security/types/{typeId}/key", (string typeId) => KeyReply(store, typeId));
        app.MapGet("/api/security/readiness", (int lesson) =>
        {
            LabDecision d = store.Decide(LabCatalog.Needs(lesson));
            return Results.Json(new { mayRun = d.MayRun, problems = d.Problems.Select(p => new { typeId = p.TypeId, code = p.Code, detail = p.Detail }) });
        });
        app.MapGet("/api/security/show-keys", () => Results.Json(new { on = store.ShowKeys }));
        app.MapPut("/api/security/show-keys", (ShowKeysBody body) =>
        {
            // A failed save keeps the old value, so a learner who turns Show keys off and is refused still has keys on screen. The named
            // refusal tells the page so (issue #292).
            try { store.SetShowKeys(body.On); }
            catch (NetSecException x) when (x.Error.Code == ErrorCodes.SecurityStoreSaveFailed) { return SaveRefused(x); }
            showKeysChanged(store.ShowKeys);
            return Results.Json(new { on = store.ShowKeys });
        });
        app.MapPost("/api/security/flows/{flowId}/runs", (string flowId) =>
            runs.Start(flowId) is { } started
                ? Results.Json(new { runId = started.Run.RunId, step = StepOf(runs, started) })
                : Refuse(404, FlowRuns.FlowUnknown, $"No flow has the id {flowId}."));
        app.MapGet("/api/security/runs/{id}", (string id) =>
            runs.Find(id) is { } found
                ? Results.Json(new { runId = id, step = StepOf(runs, found) })
                : Refuse(404, FlowRuns.RunNotFound, $"No flow run has the id {id}."));
        app.MapPost("/api/security/runs/{id}/events", (string id, RunEventBody body) =>
        {
            (RunReply? reply, RunRefusal? refusal) = runs.Apply(id, body.Event, body.StepSeq, body.Data);
            return reply is not null ? Results.Json(new { runId = id, step = StepOf(runs, reply) }) : Refuse(refusal!.Status, refusal.Code, refusal.Message);
        });
    }

    public sealed record ModeBody(string? Mode);
    public sealed record ShowKeysBody(bool On);
    public sealed record RunEventBody(string? Event, int StepSeq, JsonElement Data);

    static object TypeRow(SecurityStore store, string id)
    {
        TypeEntry e = store.Entry(id);
        bool verified = store.StateOf(id) == SecurityStore.StateVerified;
        return new
        {
            typeId = id,
            flowId = store.FlowOf(id),
            mode = e.Mode,
            state = store.StateOf(id),
            providerKind = e.Binding?.Provider ?? "builtin",
            version = e.Binding?.Version ?? 0,
            judge = verified ? e.Judge : null,
            says = verified ? e.Says : null,
        };
    }

    static IResult KeyReply(SecurityStore store, string typeId)
    {
        if (Array.IndexOf(SecurityTypes.All, typeId) < 0) return Refuse(404, "SECURITY_TYPE_UNKNOWN", $"No security type has the id {typeId}.");
        TypeEntry e = store.Entry(typeId);
        ITrainingKey? key;
        try { key = e.Mode == SecurityStore.ModeMine ? store.PlacedKey(typeId, KeyRouteCaller) : BuiltInKey(typeId); }
        catch (NetSecException x) { return Refuse(409, x.Error.Code, x.Error.Message); }
        byte[]? publicPart = key?.CopyPublic();
        return Results.Json(new
        {
            typeId,
            version = e.Binding?.Version ?? 0,
            provider = e.Mode == SecurityStore.ModeMine ? e.Binding?.Provider : "builtin",
            fingerprint = publicPart is null ? null : SecurityStore.FingerprintOf(publicPart),
            hex = store.ShowKeys && key is not null ? NetSec.Bytes.Hex.Encode(key.CopyMaterial()) : null,
            hidden = store.ShowKeys ? null : "toggle",
            publicHex = typeId == SecurityTypes.TokenIssuer && publicPart is not null ? NetSec.Bytes.Hex.Encode(publicPart) : null,
        }, new JsonSerializerOptions(JsonSerializerOptions.Web) { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
    }

    static ITrainingKey? BuiltInKey(string typeId) =>
        SecurityTypes.BuiltInKeyOf(typeId) is { } keyId ? new TrainingKeySource().Find(keyId) : null;

    static object StepOf(FlowRuns runs, RunReply reply)
    {
        FlowRun run = reply.Run;
        string[] types = runs.Table.Flow(run.FlowId)!.Types;
        return new
        {
            runId = run.RunId,
            flowId = run.FlowId,
            state = run.State,
            kind = runs.Table.KindOf(run.State),
            stepSeq = run.StepSeq,
            copyId = $"wizard.{run.FlowId}.{run.State.ToLowerInvariant()}",
            copy = run.State == WizardTable.FirstState ? new[] { TestKeysLine } : [],
            types,
            allowed = runs.Table.AllowedFrom(run.State),
            facts = reply.Facts,
            errors = reply.Errors.Select(Message),
            warnings = reply.Warnings.Select(Message),
        };
    }

    static object Message(StepMessage m) => new { code = m.Code, message = m.Message, typeId = m.TypeId };

    static IResult Refuse(int status, string code, string message, bool retryable = false) => Results.Json(
        new { code, message, retryable, requestId = Guid.NewGuid().ToString("N") },
        statusCode: status);

    /// <summary>The settings file was held by another program through every try. The hold goes away by itself, so the client may try again.</summary>
    static IResult SaveRefused(NetSecException x) => Refuse(503, x.Error.Code, x.Error.Message, retryable: true);
}
