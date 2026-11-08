using Microsoft.AspNetCore.Http;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Labs;
using static NetSec.Host.WalkReplies;

namespace NetSec.Host;

/// <summary>
/// The HMAC and seal-chain walks (docs/sections-plan.md, slice P6). The HMAC walk runs on RFC 4231's published test keys, and the chain walk on a
/// fixture chain from the vault's public seed, never the learner's audit rows. Both stay open with Show keys off and take no bytes from the client.
/// </summary>
public static class HashWalkRoutes
{
    public static void Map(WebApplication app)
    {
        app.MapGet("/api/walk/hmac", (HttpContext http, string? @case) => NoStore(http, Hmac(@case)));
        app.MapGet("/api/walk/seal-chain", (HttpContext http, string? edit) => NoStore(http, Chain(edit ?? "none")));
        app.MapGet("/api/walk/sha256", (HttpContext http, string? name) => NoStore(http, Sha256(name)));
    }

    static string Word(uint v) => v.ToString("x8");

    static IResult Sha256(string? name)
    {
        if (name is null || Array.IndexOf(Sha256Walks.Names, name) < 0) return Refuse(400, ErrorCodes.WalkBadArgument, "name must be abc or two-block.");
        try
        {
            Sha256Walk w = Sha256Walks.Fips180(name);
            return Results.Json(new
            {
                name = w.Name,
                source = "FIPS 180-4 examples",
                keySource = "none",
                message = Hex.Encode(w.Message),
                digest = Hex.Encode(w.Digest),
                blocks = w.Blocks.Select(b => new
                {
                    bytes = Hex.Encode(b.Bytes),
                    hIn = b.HIn.Select(Word).ToArray(),
                    schedule = b.Schedule.Select(Word).ToArray(),
                    rounds = b.Rounds.Select(r => new { t = r.T, k = Word(r.K), w = Word(r.W), t1 = Word(r.T1), t2 = Word(r.T2), state = r.State.Select(Word).ToArray() }).ToArray(),
                    hOut = b.HOut.Select(Word).ToArray(),
                }).ToArray(),
            });
        }
        catch (NetSecException e) when (e.Error.Code == ErrorCodes.Sha256WalkDiverged)
        {
            return Refuse(500, ErrorCodes.Sha256WalkDiverged, "The walk differs from the real SHA-256 path, so it shows nothing.");
        }
    }

    static IResult Hmac(string? testCase)
    {
        if (testCase is null || Array.IndexOf(HmacWalks.Cases, testCase) < 0) return Refuse(400, ErrorCodes.WalkBadArgument, "case must be 1, 2, 3, 4, 6 or 7.");
        try
        {
            HmacWalk w = HmacWalks.Rfc4231(testCase);
            return Results.Json(new
            {
                @case = w.Case,
                source = "RFC 4231 section 4",
                keySource = "rfc4231",
                hash = "SHA-256",
                blockSize = 64,
                key = Hex.Encode(w.Key),
                message = Hex.Encode(w.Message),
                keyHashed = w.KeyHashed,
                keyUsed = Hex.Encode(w.KeyUsed),
                paddedKey = Hex.Encode(w.PaddedKey),
                innerPad = Hex.Encode(w.InnerPad),
                innerDigest = Hex.Encode(w.InnerDigest),
                outerPad = Hex.Encode(w.OuterPad),
                mac = Hex.Encode(w.Mac),
            });
        }
        catch (NetSecException e) when (e.Error.Code == ErrorCodes.HmacWalkDiverged)
        {
            return Refuse(500, ErrorCodes.HmacWalkDiverged, "The walk differs from the real HMAC path, so it shows nothing.");
        }
    }

    static IResult Chain(string edit)
    {
        if (Array.IndexOf(SealChainWalks.Edits, edit) < 0) return Refuse(400, ErrorCodes.WalkBadArgument, "edit must be none, middle or newest.");
        SealChainWalkResult w = SealChainWalks.Build(edit);
        return Results.Json(new
        {
            edit = w.Edit,
            source = "fixture",
            seed = w.Seed,
            firstBadSeq = w.FirstBadSeq,
            links = w.Links.Select(l => new
            {
                seq = l.Row.Seq, at = l.Row.At, caller = l.Row.Caller, op = l.Row.Op, name = l.Row.Name, version = l.Row.Version,
                result = l.Row.Result, detail = l.Row.Detail,
                text = l.Text, storedPrevHash = l.StoredPrevHash, expectedPrevHash = l.ExpectedPrevHash, linkHolds = l.LinkHolds, hash = l.Hash,
            }).ToArray(),
        });
    }
}
