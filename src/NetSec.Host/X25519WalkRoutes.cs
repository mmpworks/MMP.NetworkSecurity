using Microsoft.AspNetCore.Http;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Labs;
using static NetSec.Host.WalkReplies;

namespace NetSec.Host;

/// <summary>
/// The X25519 Montgomery ladder walk, slice P8 (docs/sections-plan.md, section 4). It runs on RFC 7748 section 6.1's public test scalars,
/// never a session's key, so it stays open with Show keys off, and it takes no bytes from the client.
/// </summary>
public static class X25519WalkRoutes
{
    public static void Map(WebApplication app) =>
        app.MapGet("/api/walk/x25519", (HttpContext http, string? step) => NoStore(http, Walk(step)));

    static IResult Walk(string? step)
    {
        if (step is null || Array.IndexOf(X25519Walks.Steps, step) < 0) return Refuse(400, ErrorCodes.WalkBadArgument, "step must be alice-public, bob-public or shared.");
        try { return Results.Json(Json(X25519Walks.Rfc7748(step))); }
        catch (NetSecException e) when (e.Error.Code == ErrorCodes.X25519WalkDiverged)
        {
            return Refuse(500, ErrorCodes.X25519WalkDiverged, "The walk differs from the real X25519 path, so it shows nothing.");
        }
    }

    static string? Bytes(byte[]? b) => b is null ? null : Hex.Encode(b);

    static object Json(X25519Walk w) => new
    {
        step = w.Step,
        source = "RFC 7748 section 6.1",
        keySource = "rfc7748",
        byteOrder = "little-endian",
        scalar = Bytes(w.Scalar),
        clamped = Bytes(w.Clamped),
        point = Bytes(w.Point),
        result = Bytes(w.Result),
        rows = w.Rows.Select(r => new
        {
            bit = r.Bit,
            isOne = r.IsOne,
            x2 = Bytes(r.X2),
            z2 = Bytes(r.Z2),
            x3 = Bytes(r.X3),
            z3 = Bytes(r.Z3),
            u2 = Bytes(r.U2),
            u3 = Bytes(r.U3),
            swap = r.Swap,
        }).ToArray(),
    };
}
