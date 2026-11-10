using Microsoft.AspNetCore.Http;
using NetSec.Errors;
using NetSec.Labs.Teaching;
using static NetSec.Host.WalkReplies;

namespace NetSec.Host;

/// <summary>
/// Slice P8a's two teaching routes (docs/sections-plan.md, R7): the toy curve over GF(17) and the real-curve picture. Every value is public and
/// fixed, with no session key, so both stay open with Show keys off, and neither takes bytes from the client.
/// </summary>
public static class TeachingCurveRoutes
{
    public static void Map(WebApplication app)
    {
        app.MapGet("/api/walk/toy-curve", (HttpContext http) => NoStore(http, Toy()));
        app.MapGet("/api/walk/real-curve", (HttpContext http) => NoStore(http, Results.Json(Json(RealCurveSamples.Build()))));
        app.MapGet("/api/walk/toy-curve/add", (HttpContext http, string? p, string? q) => NoStore(http, Pick(p, q)));
    }

    /// <summary>
    /// A learner's pick of two points, by index into the 19-point list (0 to 17 are the walk's `points`, 18 is O). The same index twice is a
    /// double. The engine does the addition, and the page computes nothing (R5).
    /// </summary>
    static IResult Pick(string? p, string? q)
    {
        int count = ToyCurveWalks.PickList().Length;
        if (!Index(p, count, out int pIndex)) return Refuse(400, ErrorCodes.WalkBadArgument, $"p must be a whole number from 0 to {count - 1}.");
        if (!Index(q, count, out int qIndex)) return Refuse(400, ErrorCodes.WalkBadArgument, $"q must be a whole number from 0 to {count - 1}.");
        try
        {
            ToyPick pick = ToyCurveWalks.Pick(pIndex, qIndex);
            return Results.Json(new { pIndex = pick.PIndex, qIndex = pick.QIndex, resultIndex = pick.ResultIndex, step = Step(pick.Step) });
        }
        catch (NetSecException e) when (e.Error.Code == ErrorCodes.ToyCurveWalkDiverged)
        {
            return Refuse(500, ErrorCodes.ToyCurveWalkDiverged, "The toy-curve walk disagrees with itself, so it shows nothing.");
        }
    }

    static bool Index(string? text, int count, out int index) =>
        int.TryParse(text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out index) && index < count;

    static IResult Toy()
    {
        try { return Results.Json(Json(ToyCurveWalks.Build())); }
        catch (NetSecException e) when (e.Error.Code == ErrorCodes.ToyCurveWalkDiverged)
        {
            return Refuse(500, ErrorCodes.ToyCurveWalkDiverged, "The toy-curve walk disagrees with itself, so it shows nothing.");
        }
    }

    static object? Point(ToyPoint? p) => p is null ? null : p.IsInfinity ? new { infinity = true } : new { x = p.X, y = p.Y };

    static object? Inverse(ToyInverse? i) => i is null ? null : new
    {
        of = i.Of,
        modulus = i.Modulus,
        value = i.Value,
        rows = i.Rows.Select(r => new { a = r.A, b = r.B, quotient = r.Quotient, remainder = r.Remainder, t = r.T }).ToArray(),
    };

    static object? Step(ToyStep? s) => s is null ? null : new
    {
        kind = s.Kind,
        p = Point(s.P),
        q = Point(s.Q),
        rPrime = Point(s.RPrime),
        result = Point(s.Result),
        numerator = s.Inverse is null ? (int?)null : s.Numerator,
        denominator = s.Inverse is null ? (int?)null : s.Denominator,
        inverse = Inverse(s.Inverse),
        lambda = s.Inverse is null ? (int?)null : s.Lambda,
    };

    static object Signature(ToySignature s) => new
    {
        z = s.Z, nonce = s.Nonce, bigR = Point(s.R), r = s.SmallR, s = s.S, nonceInverse = Inverse(s.NonceInverse),
    };

    static object Verify(ToyVerify v) => new { sInverse = Inverse(v.SInverse), u1 = v.U1, u2 = v.U2, x = Point(v.X), valid = v.Valid };

    static object Json(ToyCurveWalk w) => new
    {
        source = "video 4Tfmwxr0I34",
        keySource = "toy",
        curve = new { p = ToyCurve.Prime, a = ToyCurve.A, b = ToyCurve.B, order = ToyCurve.Order, g = Point(ToyCurve.G) },
        points = w.Points.Select(Point).ToArray(),
        addExample = Step(w.AddExample),
        doubleExample = Step(w.DoubleExample),
        hops = w.Hops.Select(h => new { k = h.K, point = Point(h.Point), step = Step(h.Step) }).ToArray(),
        k = w.K,
        doubleAndAdd = w.DoubleAndAdd.Select(r => new { bit = r.Bit, isOne = r.IsOne, doubleStep = Step(r.DoubleStep), addStep = Step(r.AddStep), after = Point(r.After) }).ToArray(),
        ladder = w.Ladder.Select(r => new { bit = r.Bit, isOne = r.IsOne, addStep = Step(r.AddStep), doubleStep = Step(r.DoubleStep), r0 = Point(r.R0), r1 = Point(r.R1) }).ToArray(),
        ecdh = new
        {
            alicePrivate = w.Ecdh.AlicePrivate, bobPrivate = w.Ecdh.BobPrivate,
            alicePublic = Point(w.Ecdh.AlicePublic), bobPublic = Point(w.Ecdh.BobPublic),
            aliceShared = Point(w.Ecdh.AliceShared), bobShared = Point(w.Ecdh.BobShared),
        },
        ecdsa = new
        {
            signerPrivate = w.SignerPrivate,
            signerPublic = Point(w.SignerPublic),
            first = Signature(w.First),
            second = Signature(w.Second),
            firstVerify = Verify(w.FirstVerify),
            secondVerify = Verify(w.SecondVerify),
            recovery = new
            {
                sDifferenceInverse = Inverse(w.Recovery.SDifferenceInverse),
                rInverse = Inverse(w.Recovery.RInverse),
                nonce = w.Recovery.RecoveredNonce,
                privateKey = w.Recovery.RecoveredPrivate,
            },
        },
    };

    static object Real(RealPoint p) => new { x = p.X, y = p.Y };

    static object Line(RealLineExample e) => new { kind = e.Kind, p = Real(e.P), q = Real(e.Q), rPrime = Real(e.RPrime), r = Real(e.R), lambda = e.Lambda };

    static object Json(RealCurveSample s) => new
    {
        source = "video 4Tfmwxr0I34",
        a = s.A,
        b = s.B,
        root = s.Root,
        xMax = s.XMax,
        upper = s.Upper.Select(Real).ToArray(),
        lower = s.Lower.Select(Real).ToArray(),
        chord = Line(s.Chord),
        tangent = Line(s.Tangent),
        samples = s.Samples.Select(Line).ToArray(),
    };
}
