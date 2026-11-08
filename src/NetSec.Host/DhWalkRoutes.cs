using System.Numerics;
using Microsoft.AspNetCore.Http;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Labs;
using static NetSec.Host.WalkReplies;

namespace NetSec.Host;

/// <summary>
/// The Diffie-Hellman walk, slice P7 (docs/sections-plan.md, section 4). It runs on public practice exponents, never a session's key, so it
/// stays open with Show keys off, and it takes no bytes from the client. Each number goes out in hex and in decimal, so the app computes nothing.
/// </summary>
public static class DhWalkRoutes
{
    public static void Map(WebApplication app) =>
        app.MapGet("/api/walk/dh", (HttpContext http, string? group) => NoStore(http, Walk(group)));

    static IResult Walk(string? group)
    {
        if (group is not ("small" or "group14")) return Refuse(400, ErrorCodes.WalkBadArgument, "group must be small or group14.");
        try { return Results.Json(Json(group == "small" ? DhWalks.Small() : DhWalks.Group14())); }
        catch (NetSecException e) when (e.Error.Code == ErrorCodes.DhWalkDiverged)
        {
            return Refuse(500, ErrorCodes.DhWalkDiverged, "The walk differs from the real Diffie-Hellman path, so it shows nothing.");
        }
    }

    /// <summary>One number, in hex and in decimal. Decimal is formatting only, done here with BigInteger.</summary>
    static object? Number(byte[]? bigEndian) => bigEndian is null ? null : new
    {
        hex = Hex.Encode(bigEndian),
        dec = new BigInteger(bigEndian, isUnsigned: true, isBigEndian: true).ToString(),
    };

    static object Pow(DhPowWalk w) => new
    {
        @base = Number(w.Base),
        exponent = Number(w.Exponent),
        result = Number(w.Result),
        rows = w.Rows.Select(r => new { bit = r.Bit, isOne = r.IsOne, afterSquare = Number(r.AfterSquare), afterMultiply = Number(r.AfterMultiply) }).ToArray(),
    };

    static object Side(DhSideWalk s) => new { @private = Number(s.Private), @public = Pow(s.Public), shared = Pow(s.Shared) };

    static object Json(DhWalk w) => new
    {
        group = w.Group,
        keySource = "practice",
        prime = Number(w.Prime),
        generator = Number(w.Generator),
        realExponentBits = w.RealExponentBits,
        client = Side(w.Client),
        server = Side(w.Server),
    };
}
