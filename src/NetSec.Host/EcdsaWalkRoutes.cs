using Microsoft.AspNetCore.Http;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Labs;
using static NetSec.Host.WalkReplies;

namespace NetSec.Host;

/// <summary>
/// The ECDSA P-256 walk (docs/sections-plan.md, slice P8b). It runs on RFC 6979 section A.2.5's published test key, never a session's key, so it stays
/// open with Show keys off, and it takes no bytes from the client.
/// </summary>
public static class EcdsaWalkRoutes
{
    public static void Map(WebApplication app) =>
        app.MapGet("/api/walk/ecdsa", (HttpContext http, string? message) => NoStore(http, Walk(message)));

    static IResult Walk(string? message)
    {
        if (message is null || Array.IndexOf(EcdsaWalks.Messages, message) < 0) return Refuse(400, ErrorCodes.WalkBadArgument, "message must be sample or test.");
        try { return Results.Json(Json(EcdsaWalks.Rfc6979(message))); }
        catch (NetSecException e) when (e.Error.Code == ErrorCodes.EcdsaWalkDiverged)
        {
            return Refuse(500, ErrorCodes.EcdsaWalkDiverged, "The walk differs from the real ECDSA path, so it shows nothing.");
        }
    }

    static string? B(byte[]? b) => b is null ? null : Hex.Encode(b);

    static object Json(EcdsaWalk w) => new
    {
        message = w.Message,
        source = "RFC 6979 section A.2.5",
        keySource = "rfc6979",
        curve = "P-256",
        hash = "SHA-256",
        byteOrder = "big-endian",
        privateKey = B(w.PrivateKey),
        publicKey = new { x = B(w.PublicX), y = B(w.PublicY) },
        h1 = B(w.Hash),
        e = B(w.E),
        rfc6979 = w.Rounds.Select(r => new { step = r.Step, k = B(r.K), v = B(r.V), candidate = B(r.Candidate), kept = r.Kept }).ToArray(),
        k = B(w.K),
        kG = w.Bits.Select(r => new
        {
            bit = r.Bit,
            isOne = r.IsOne,
            afterDouble = r.DoubleX is null ? null : new { x = B(r.DoubleX), y = B(r.DoubleY) },
            afterAdd = r.AddX is null ? null : new { x = B(r.AddX), y = B(r.AddY) },
        }).ToArray(),
        bigR = new { x = B(w.Rx), y = B(w.Ry) },
        r = B(w.R),
        kInverse = B(w.KInverse),
        s = B(w.S),
        verify = new { w = B(w.W), u1 = B(w.U1), u2 = B(w.U2), x = new { x = B(w.Xx), y = B(w.Xy) }, valid = w.Valid },
    };
}
