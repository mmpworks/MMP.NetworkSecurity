using Microsoft.AspNetCore.Http;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Labs;
using static NetSec.Host.WalkReplies;

namespace NetSec.Host;

/// <summary>
/// The TLS 1.1 RSA key-transport walk, slice P4b (docs/sections-plan.md, R8). It runs on one fixed teaching run with the built-in training key,
/// which is public in the source, never a learner's key. So it stays open with Show keys off, and it takes no bytes from the client.
/// </summary>
public static class Tls11WalkRoutes
{
    public static void Map(WebApplication app) =>
        app.MapGet("/api/walk/tls11/schedule", (HttpContext http) => NoStore(http, Schedule()));

    static IResult Schedule()
    {
        try { return Results.Json(Json(Tls11KeyScheduleWalks.TeachingRun())); }
        catch (NetSecException e) when (e.Error.Code == ErrorCodes.Tls11WalkDiverged)
        {
            return Refuse(500, ErrorCodes.Tls11WalkDiverged, "The walk differs from the real TLS 1.1 key schedule, so it shows nothing.");
        }
    }

    static object Json(Tls11KeyScheduleWalk w) => new
    {
        source = "teaching run",
        keySource = "training",
        serverKeyId = w.ServerKeyId,
        suite = w.Suite,
        serverPublicKey = Hex.Encode(w.ServerPublicKey),
        clientRandom = Hex.Encode(w.ClientRandom),
        serverRandom = Hex.Encode(w.ServerRandom),
        encryptedPremaster = Hex.Encode(w.EncryptedPremaster),
        premaster = Hex.Encode(w.Premaster),
        premasterVersion = w.PremasterVersion,
        masterSecret = new { label = Tls11KeyScheduleWalks.MasterSecretLabel, seed = "client random + server random", value = Hex.Encode(w.MasterSecret) },
        keyBlock = new
        {
            label = Tls11KeyScheduleWalks.KeyExpansionLabel,
            seed = "server random + client random",
            value = Hex.Encode(w.KeyBlock),
            clientMacKey = Hex.Encode(w.ClientMacKey),
            serverMacKey = Hex.Encode(w.ServerMacKey),
            clientKey = Hex.Encode(w.ClientKey),
            serverKey = Hex.Encode(w.ServerKey),
        },
        keyLogLine = w.KeyLogLine,
    };
}
