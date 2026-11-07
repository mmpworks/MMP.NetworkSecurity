using Microsoft.AspNetCore.Http;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Tls13;
using static NetSec.Host.WalkReplies;

namespace NetSec.Host;

/// <summary>
/// The Handshake section's key schedule walk, slice P4 (docs/sections-plan.md, section 4). It runs on the public inputs of RFC 8448 section 3,
/// never on a session's key, so it stays open with Show keys off. It takes no bytes from the client, so a client cannot feed it canned input.
/// </summary>
public static class Tls13WalkRoutes
{
    public static void Map(WebApplication app) =>
        app.MapGet("/api/walk/tls13/schedule", (HttpContext http) => NoStore(http, Schedule()));

    static IResult Schedule()
    {
        try { return Results.Json(Json(Tls13ScheduleWalks.Rfc8448())); }
        catch (NetSecException e) when (e.Error.Code == ErrorCodes.Tls13WalkDiverged)
        {
            return Refuse(500, ErrorCodes.Tls13WalkDiverged, "The walk differs from the real key schedule, so it shows nothing.");
        }
    }

    static string? Bytes(byte[]? b) => b is null ? null : Hex.Encode(b);

    static object Json(Tls13ScheduleWalk w) => new
    {
        source = w.Source,
        suite = w.Suite,
        keySource = "rfc8448",
        steps = w.Steps.Select(s => new
        {
            name = s.Name,
            kind = s.Kind.ToString(),
            label = s.Label,
            messages = s.Messages,
            salt = Bytes(s.Salt),
            ikm = Bytes(s.Ikm),
            secret = Bytes(s.Secret),
            context = Bytes(s.Context),
            hkdfLabel = Bytes(s.HkdfLabel),
            output = Bytes(s.Output),
        }).ToArray(),
    };
}
