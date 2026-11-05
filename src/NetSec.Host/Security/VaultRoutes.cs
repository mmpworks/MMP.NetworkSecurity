using System.Text.Json;
using System.Text.Json.Serialization;
using NetSec.Bytes;
using NetSec.Vault;

namespace NetSec.Host.Security;

public sealed record ExerciseTextBody(string? Text);
public sealed record ExerciseLabelBody(string? Label);

/// <summary>The vault's routes, in the shapes of acceptance/CONTRACT.md section 5. No route gives the bytes of a non-exportable key, because none can.</summary>
public static class VaultRoutes
{
    const string Exercise = "/api/security/vault/exercise/";
    const int AuditPage = 500;

    static readonly JsonSerializerOptions Json = new(JsonSerializerOptions.Web) { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public static void Map(WebApplication app, IVault vault, VaultExercise exercise)
    {
        app.MapGet("/api/security/vault/keys", () => Results.Json(new { keys = vault.Keys().Select(KeyOf) }, Json));
        app.MapGet("/api/security/vault/audit", (long? after) => Results.Json(new { rows = vault.Audit(after ?? 0, AuditPage).Select(RowOf) }, Json));
        app.MapPost(Exercise + "sign", (ExerciseTextBody? body) => Answer(() => exercise.Sign(body?.Text ?? "")));
        app.MapPost(Exercise + "derive", (ExerciseLabelBody? body) => Answer(() => exercise.Derive(body?.Label ?? "")));
        app.MapPost(Exercise + "export", () => Answer<object>(() => { exercise.Export(); return new { code = "OK" }; }));
        app.MapPost(Exercise + "audit-check", () => Answer(() =>
        {
            AuditChecked c = exercise.AuditCheck();
            return new { rows = c.Rows.Select(RowOf), firstBadSeq = c.FirstBadSeq, code = c.Code, limits = c.Limits };
        }));
    }

    static object KeyOf(VaultKeyInfo k) => new
    {
        name = k.Name,
        algorithm = k.Policy.Algorithm,
        exportable = k.Policy.Exportable,
        allowedOps = k.Policy.AllowedOps,
        provenance = k.Provenance,
        versions = k.Versions,
        fingerprint = k.Fingerprint,
        hidden = k.Policy.Exportable ? null : "non-exportable",
        publicHex = k.PublicKey is null ? null : Hex.Encode(k.PublicKey),
    };

    /// <summary>The audit table's own column names, so the route and the file read the same.</summary>
    static object RowOf(AuditRow r) => new
    {
        seq = r.Seq, at = r.At, caller = r.Caller, op = r.Op, name = r.Name, version = r.Version, result = r.Result, detail = r.Detail, prev_hash = r.PrevHash,
    };

    /// <summary>A refusal is HTTP 409 with its code. An audit row that cannot be written, or a bad master.key, is HTTP 503: the vault, not the ask, is at fault.</summary>
    static IResult Answer<T>(Func<T> call)
    {
        try { return Results.Json(call(), Json); }
        catch (VaultException e)
        {
            int status = e.Code is VaultCodes.AuditFailed or VaultCodes.MasterKeyBad ? StatusCodes.Status503ServiceUnavailable : StatusCodes.Status409Conflict;
            return Results.Json(new { code = e.Code, message = e.Message, retryable = e.Code == VaultCodes.AuditFailed, requestId = Guid.NewGuid().ToString("N") }, statusCode: status);
        }
    }
}
