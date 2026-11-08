using Microsoft.AspNetCore.Http;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Labs;
using static NetSec.Host.WalkReplies;

namespace NetSec.Host;

/// <summary>
/// The DES (Feistel) walk (docs/sections-plan.md, section 4). It runs on NIST CAVP's published known-answer keys, never a session's key, so it stays
/// open with Show keys off, and it takes no bytes from the client. Each value is hex at its own width, so the page computes nothing (R5).
/// </summary>
public static class DesWalkRoutes
{
    public static void Map(WebApplication app) =>
        app.MapGet("/api/walk/des", (HttpContext http, string? name) => NoStore(http, Walk(name)));

    static IResult Walk(string? name)
    {
        if (name is null || Array.IndexOf(DesWalks.Names, name) < 0) return Refuse(400, ErrorCodes.WalkBadArgument, "name must be varkey, vartext or subtab.");
        try { return Results.Json(Json(DesWalks.Known(name))); }
        catch (NetSecException e) when (e.Error.Code == ErrorCodes.DesWalkDiverged)
        {
            return Refuse(500, ErrorCodes.DesWalkDiverged, "The walk differs from the real DES path, so it shows nothing.");
        }
    }

    static string H(ulong v, int bits) => v.ToString("x" + ((bits + 3) / 4));

    static object Json(DesWalk w) => new
    {
        name = w.Name,
        source = "NIST CAVP KAT_TDES (one DES key used three times)",
        keySource = "cavp",
        key = Hex.Encode(w.Key),
        plaintext = Hex.Encode(w.Plaintext),
        ciphertext = Hex.Encode(w.Ciphertext),
        schedule = new
        {
            pc1 = H(w.Chosen, 56),
            rounds = Enumerable.Range(0, 16).Select(r => new { round = r + 1, c = H(w.C[r], 28), d = H(w.D[r], 28), key = H(w.RoundKeys[r], 48) }).ToArray(),
        },
        ip = H(w.Permuted, 64),
        rounds = w.Rounds.Select(r => new
        {
            round = r.Round,
            leftIn = H(r.LeftIn, 32),
            rightIn = H(r.RightIn, 32),
            key = H(r.RoundKey, 48),
            expanded = H(r.Expanded, 48),
            mixed = H(r.Mixed, 48),
            boxes = r.Boxes.Select((b, i) => new
            {
                box = i + 1,
                six = Convert.ToString(b.Six, 2).PadLeft(6, '0'),
                row = b.Row,
                column = b.Column,
                output = Convert.ToString(b.Out, 2).PadLeft(4, '0'),
            }).ToArray(),
            boxesOut = H(r.BoxesOut, 32),
            f = H(r.F, 32),
            leftOut = H(r.LeftOut, 32),
            rightOut = H(r.RightOut, 32),
        }).ToArray(),
        preOutput = H(w.PreOutput, 64),
        output = H(w.Output, 64),
    };
}
