using Microsoft.AspNetCore.Http;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Labs;
using static NetSec.Host.WalkReplies;

namespace NetSec.Host;

/// <summary>
/// The Ed25519 walk (docs/sections-plan.md, section 4). It runs on RFC 8032 section 7.1's published test keys, never a session's key, so it stays
/// open with Show keys off, and it takes no bytes from the client.
/// </summary>
public static class Ed25519WalkRoutes
{
    public static void Map(WebApplication app) =>
        app.MapGet("/api/walk/ed25519", (HttpContext http, string? test) => NoStore(http, Walk(test)));

    static IResult Walk(string? test)
    {
        if (test is null || Array.IndexOf(Ed25519Walks.Tests, test) < 0) return Refuse(400, ErrorCodes.WalkBadArgument, "test must be 1, 2 or 3.");
        try { return Results.Json(Json(Ed25519Walks.Rfc8032(test))); }
        catch (NetSecException e) when (e.Error.Code == ErrorCodes.Ed25519WalkDiverged)
        {
            return Refuse(500, ErrorCodes.Ed25519WalkDiverged, "The walk differs from the real Ed25519 path, so it shows nothing.");
        }
    }

    static object Json(Ed25519Walk w) => new
    {
        test = w.Test,
        source = "RFC 8032 section 7.1",
        keySource = "rfc8032",
        byteOrder = "little-endian",
        seed = Hex.Encode(w.Seed),
        message = Hex.Encode(w.Message),
        expanded = Hex.Encode(w.Expanded),
        scalar = Hex.Encode(w.Scalar),
        prefix = Hex.Encode(w.Prefix),
        publicKey = Hex.Encode(w.PublicKey),
        r = Hex.Encode(w.R),
        rPoint = Hex.Encode(w.RPoint),
        h = Hex.Encode(w.H),
        s = Hex.Encode(w.S),
        signature = Hex.Encode(w.Signature),
        verify = new { sB = Hex.Encode(w.SB), minusHA = Hex.Encode(w.MinusHA), rPrime = Hex.Encode(w.RPrime), valid = w.Valid },
    };
}
