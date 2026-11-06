using Microsoft.AspNetCore.Http;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Host.Security;
using NetSec.Labs;
using NetSec.Platform;

namespace NetSec.Host;

/// <summary>
/// The AES walk's routes, slice W1a (docs/walkthrough-design.md sections 3.4 and 3.5). A route takes a session id and no bytes, so a client cannot send a canned key or block.
/// The block route checks the toggle before it reads anything, its error bodies hold no bytes, and each reply carries no-store. A walk adds no trace event.
/// </summary>
public static class AesWalkRoutes
{
    const int BlockSize = 16;
    const string EcbText = "TextEcb";

    public static void Map(WebApplication app, SecurityStore security, SessionManager sessions)
    {
        app.MapGet("/api/walk/aes/tables", (HttpContext http) => NoStore(http, Guarded(() => Results.Json(AesWalkJson.Tables()))));
        app.MapGet("/api/sessions/{id}/walk/aes/block", (HttpContext http, string id, string? source, string? keyBits) =>
            NoStore(http, Block(security.ShowKeys, sessions.Find(id), id, source, keyBits)));
    }

    static IResult NoStore(HttpContext http, IResult result)
    {
        http.Response.Headers.CacheControl = "no-store";
        return result;
    }

    static IResult Block(bool showKeys, LabSession? session, string id, string? source, string? keyBits)
    {
        if (!showKeys) return Refuse(409, ErrorCodes.KeysHidden, "Show keys is off, so these steps stay closed. Turn Show keys on to walk them.");
        if (session is null) return Refuse(404, "SESSION_NOT_FOUND", $"No session {id}.");
        if (session.Lesson != 1 || session.TransportKind != "glass") return Refuse(409, ErrorCodes.WalkNotBuilt, "The AES walk runs on lesson 1, on the course's own engine.");
        if (source is "ecb" or "cbc" or "gcm") return Refuse(409, ErrorCodes.WalkNotBuilt, "A box from the modes chapter opens when that chapter is built.");
        if (source != "text") return Refuse(400, ErrorCodes.WalkBadArgument, "source must be text, ecb, cbc or gcm.");
        if (keyBits is not ("128" or "192" or "256")) return Refuse(400, ErrorCodes.WalkBadArgument, "keyBits must be 128, 192 or 256.");
        return TextBlock(session, int.Parse(keyBits));
    }

    static IResult TextBlock(LabSession session, int keyBits)
    {
        // Read before the events. A run that sends and finishes between the two reads then reads as waiting, which a retry resolves.
        bool finished = session.Finished;
        AesWalkFacts facts = AesWalkFacts.Read(session.After(0));
        if (facts.Key is null || facts.Text is null || facts.Text.Length < BlockSize) return NotReached(finished);
        byte[] block = facts.Text[..BlockSize];
        // Section 2.7: at 128 bits, the key the run used. At 192 or 256 bits, a key that never ran in the lesson.
        bool runKey = keyBits == facts.Key.Length * 8;
        byte[] key = runKey ? facts.Key : PracticeKey(session.Seed, keyBits);
        return Guarded(() =>
        {
            byte[] cipher = new byte[BlockSize];
            new AesKey(key).EncryptBlock(block, 0, cipher, 0);
            AesBlockPair pair = AesWalks.Block(key, block, cipher);
            string wire = runKey ? WireStatus(facts.EcbTextFrame, cipher) : "notSent";
            return Results.Json(AesWalkJson.Block("text", runKey ? "run" : "practice", pair, wire, EcbText));
        });
    }

    static IResult Guarded(Func<IResult> walk)
    {
        try { return walk(); }
        catch (NetSecException e) when (e.Error.Code == ErrorCodes.AesWalkDiverged)
        {
            return Refuse(500, ErrorCodes.AesWalkDiverged, "The walk differs from the real AES path, so it shows nothing.");
        }
    }

    static IResult NotReached(bool finished) => finished
        ? Refuse(409, ErrorCodes.WalkMessageNotSent, "This run ended before it sent its text.")
        : Refuse(409, ErrorCodes.WalkWaitingForWire, "This run has not sent its text yet.", true);

    static byte[] PracticeKey(int seed, int keyBits)
    {
        byte[] key = new byte[keyBits / 8];
        new SeededRandom(seed ^ keyBits).Fill(key, 0, key.Length);
        return key;
    }

    /// <summary>The label chapter 1 shows. The block goes on the wire only on the L1-use-ecb fork, as the first block of the TextEcb frame's body.</summary>
    static string WireStatus(byte[]? frame, byte[] cipher)
    {
        if (frame is null) return "notSent";
        bool same = frame.Length >= Frame.HeaderSize + BlockSize && frame.AsSpan(Frame.HeaderSize, BlockSize).SequenceEqual(cipher);
        return same ? "match" : "differs";
    }

    static IResult Refuse(int status, string code, string message, bool retryable = false) =>
        Results.Json(new { code, message, retryable, requestId = Guid.NewGuid().ToString("N") }, statusCode: status);
}
