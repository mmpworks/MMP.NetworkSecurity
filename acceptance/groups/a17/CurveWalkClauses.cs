using System;
using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>
    /// Slice P8a's teaching curves (docs/sections-plan.md lines 153 and 154, R7, Q5 answer A). The anchor is the plan, not the engine: the toy curve
    /// is y^2 = x^3 + 2x + 2 over GF(17) with 19 points, and the real curve is the same equation over the reals. The suite brute-forces every toy
    /// value with its own small arithmetic, and checks the real-curve lines by their formulas. Q5 chose the video's curve so a learner can follow
    /// the video and the app side by side, so the video's own numbers are pinned too: G = (5, 1), k = 13 with 13G = (16, 4), and the ECDSA
    /// example d = 7, Q = (0, 6), z = 8, k = 3, r = 10, s = 7 (video 4Tfmwxr0I34; Jared checked them in Python). Both routes are open with Show keys OFF.
    /// </summary>
    public static class CurveWalkClauses
    {
        public const string ToyPath = "/api/walk/toy-curve", RealPath = "/api/walk/real-curve";
        internal const int P = 17, A = 2, B = 2, N = 19;

        // ---------------------------------------------------------------- the suite's own toy-curve arithmetic; null is the point at infinity

        internal sealed class Pt { public int X, Y; public Pt(int x, int y) { X = x; Y = y; } public override string ToString() { return "(" + X + ", " + Y + ")"; } }

        internal static int Mod(long v, int m) { long r = v % m; return (int)(r < 0 ? r + m : r); }

        internal static int Inv(int v, int m) { for (int i = 1; i < m; i++) if (Mod((long)v * i, m) == 1) return i; throw new FailException("no inverse of " + v + " mod " + m); }

        static bool Same(Pt a, Pt b) { return a == null ? b == null : b != null && a.X == b.X && a.Y == b.Y; }

        internal static Pt Add(Pt p, Pt q)
        {
            if (p == null) return q;
            if (q == null) return p;
            if (p.X == q.X && Mod(p.Y + q.Y, P) == 0) return null;
            int lambda = Same(p, q) ? Mod((3L * p.X * p.X + A) * Inv(Mod(2 * p.Y, P), P), P) : Mod((long)(q.Y - p.Y) * Inv(Mod(q.X - p.X, P), P), P);
            int x = Mod((long)lambda * lambda - p.X - q.X, P);
            return new Pt(x, Mod((long)lambda * (p.X - x) - p.Y, P));
        }

        internal static Pt Mul(int k, Pt g) { Pt r = null; for (int i = 0; i < Mod(k, N); i++) r = Add(r, g); return r; }

        internal static List<Pt> AllPoints()
        {
            List<Pt> all = new List<Pt>();
            for (int x = 0; x < P; x++) for (int y = 0; y < P; y++) if (Mod((long)y * y - ((long)x * x * x + A * x + B), P) == 0) all.Add(new Pt(x, y));
            return all;
        }

        static Pt ReadPt(object o, string where)
        {
            Dictionary<string, object> d = MiniJson.AsObject(o);
            Check.True(d != null, where + ": no point");
            if (MiniJson.Bool(d, "infinity", false)) return null;
            return new Pt((int)MiniJson.Num(d, "x", -1), (int)MiniJson.Num(d, "y", -1));
        }

        static void SamePt(string where, Pt want, Pt got) { Check.True(Same(want, got), where + ": the walk shows " + (got == null ? "O" : got.ToString()) + ", and the curve gives " + (want == null ? "O" : want.ToString())); }

        static Reply GetOpen(HostProc h, string path, string slice)
        {
            Reply r = HostHttp.Get(h, path);
            if (r.Status == 404 && string.IsNullOrEmpty(r.Code)) throw new NotRunException("PRODUCT_MISSING", "the Host has no route " + path + " yet (" + slice + ")");
            Check.True(r.Ok && r.Json != null, "OFF: GET " + path + " got " + r + ". The walk holds only public teaching values, so it stays open");
            return r;
        }

        static void Step(Dictionary<string, object> s, string where)
        {
            Check.True(s != null, where + ": missing");
            Pt p = ReadPt(s["p"], where + " p"), q = s.ContainsKey("q") && s["q"] != null ? ReadPt(s["q"], where + " q") : p;
            SamePt(where + " result", Add(p, q), ReadPt(s["result"], where + " result"));
            if (s.ContainsKey("lambda") && s["lambda"] != null)
            {
                int num = Mod((long)MiniJson.Num(s, "numerator", 0), P), den = Mod((long)MiniJson.Num(s, "denominator", 0), P);
                Dictionary<string, object> inv = MiniJson.Obj(s, "inverse");
                Check.True(inv != null && Mod((long)MiniJson.Num(inv, "value", 0) * den, P) == 1, where + ": the inverse times the denominator is not 1 mod 17");
                Check.True(Mod((long)MiniJson.Num(s, "lambda", -1), P) == Mod((long)num * Inv(den, P), P), where + ": lambda is not numerator times the inverse mod 17");
            }
        }

        [Clause("A19.host.toy-curve-open-and-brute-force")]
        public static string ToyCurve(Ctx c)
        {
            using (HostProc h = A17.Host(c, "walk-toy-curve"))
            {
                Reply off = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", false));
                Check.True(off.Ok, "PUT show-keys got " + off);
                Reply r = GetOpen(h, ToyPath, "slice P8a");
                Check.Equal("keySource", "toy", MiniJson.Str(r.Json, "keySource"));
                Dictionary<string, object> curve = MiniJson.Obj(r.Json, "curve");
                Check.True(curve != null && (int)MiniJson.Num(curve, "p", 0) == P && (int)MiniJson.Num(curve, "a", 0) == A && (int)MiniJson.Num(curve, "b", 0) == B && (int)MiniJson.Num(curve, "order", 0) == N,
                    "the curve is not y^2 = x^3 + 2x + 2 over GF(17) with order 19 (sections-plan.md Q5)");
                Pt g = ReadPt(curve["g"], "G");
                SamePt("G is the video's generator", new Pt(5, 1), g);

                // Every point, by trying each x and y.
                List<Pt> want = AllPoints();
                List<object> shown = MiniJson.Arr(r.Json, "points") ?? new List<object>();
                Check.True(shown.Count == want.Count, shown.Count + " points shown, and the curve has " + want.Count + " besides O");
                foreach (Pt w in want) Check.True(shown.Exists(o => Same(w, ReadPt(o, "point"))), "the point " + w + " is missing from the scatter");

                Step(MiniJson.Obj(r.Json, "addExample"), "addExample");
                Step(MiniJson.Obj(r.Json, "doubleExample"), "doubleExample");

                // k.G one hop at a time, until the cycle closes at the order.
                List<object> hops = MiniJson.Arr(r.Json, "hops") ?? new List<object>();
                Check.True(hops.Count == N, hops.Count + " hops, and the cycle closes at 19");
                for (int i = 0; i < hops.Count; i++)
                {
                    Dictionary<string, object> hop = MiniJson.AsObject(hops[i]);
                    int k = (int)MiniJson.Num(hop, "k", -1);
                    Check.True(k == i + 1, "hop " + i + " names k " + k);
                    SamePt("hop " + k, Mul(k, g), ReadPt(hop["point"], "hop " + k));
                }

                int kk = (int)MiniJson.Num(r.Json, "k", -1);
                Check.True(kk == 13, "double-and-add runs on k = " + kk + ", and the video uses k = 13");
                SamePt("13G on the video's curve", new Pt(16, 4), Mul(13, g));
                List<object> dad = MiniJson.Arr(r.Json, "doubleAndAdd"), ladder = MiniJson.Arr(r.Json, "ladder");
                Check.True(dad != null && dad.Count > 0 && ladder != null && ladder.Count > 0, "the walk has no double-and-add or ladder rows");
                SamePt("double-and-add ends on k.G", Mul(kk, g), ReadPt(MiniJson.AsObject(dad[dad.Count - 1])["after"], "double-and-add"));
                SamePt("the ladder ends on k.G", Mul(kk, g), ReadPt(MiniJson.AsObject(ladder[ladder.Count - 1])["r0"], "ladder"));

                Dictionary<string, object> ecdh = MiniJson.Obj(r.Json, "ecdh");
                int ap = (int)MiniJson.Num(ecdh, "alicePrivate", 0), bp = (int)MiniJson.Num(ecdh, "bobPrivate", 0);
                SamePt("ECDH Alice public", Mul(ap, g), ReadPt(ecdh["alicePublic"], "ecdh"));
                SamePt("ECDH Bob public", Mul(bp, g), ReadPt(ecdh["bobPublic"], "ecdh"));
                SamePt("ECDH Alice shared", Mul(ap * bp, g), ReadPt(ecdh["aliceShared"], "ecdh"));
                SamePt("ECDH Bob shared", Mul(ap * bp, g), ReadPt(ecdh["bobShared"], "ecdh"));

                // ECDSA by its relations on the reply's own values, so new example values keep this clause valid.
                Dictionary<string, object> ec = MiniJson.Obj(r.Json, "ecdsa");
                int d = (int)MiniJson.Num(ec, "signerPrivate", 0);
                Check.True(d == 7, "the ECDSA example signs with d = " + d + ", and the video uses d = 7");
                Pt qpub = Mul(d, g);
                SamePt("ECDSA public key", qpub, ReadPt(ec["signerPublic"], "ecdsa"));
                SamePt("the video's public key Q", new Pt(0, 6), qpub);
                int[] nonces = new int[2], zs = new int[2], rs = new int[2], ss = new int[2];
                string[] names = { "first", "second" };
                for (int i = 0; i < 2; i++)
                {
                    Dictionary<string, object> sig = MiniJson.Obj(ec, names[i]);
                    zs[i] = (int)MiniJson.Num(sig, "z", 0); nonces[i] = (int)MiniJson.Num(sig, "nonce", 0);
                    Pt bigR = Mul(nonces[i], g);
                    SamePt(names[i] + " R = nonce.G", bigR, ReadPt(sig["bigR"], names[i]));
                    rs[i] = (int)MiniJson.Num(sig, "r", -1); ss[i] = (int)MiniJson.Num(sig, "s", -1);
                    Check.True(bigR != null && rs[i] == Mod(bigR.X, N), names[i] + ": r is not R.x mod 19");
                    Check.True(ss[i] == Mod((long)Inv(Mod(nonces[i], N), N) * (zs[i] + (long)rs[i] * d), N), names[i] + ": s is not nonce^-1 (z + r d) mod 19");
                    Dictionary<string, object> v = MiniJson.Obj(ec, names[i] + "Verify");
                    int w = Inv(ss[i], N), u1 = Mod((long)zs[i] * w, N), u2 = Mod((long)rs[i] * w, N);
                    Check.True((int)MiniJson.Num(v, "u1", -1) == u1 && (int)MiniJson.Num(v, "u2", -1) == u2, names[i] + " verify: u1 or u2 is wrong");
                    Pt x = Add(Mul(u1, g), Mul(u2, qpub));
                    SamePt(names[i] + " verify X = u1.G + u2.Q", x, ReadPt(v["x"], names[i] + " verify"));
                    Check.True(MiniJson.Bool(v, "valid", false) && x != null && Mod(x.X, N) == rs[i], names[i] + " verify: the signature should be valid");
                }
                Check.True(nonces[0] == nonces[1], "the 2 signatures should reuse one nonce, for the recovery");
                Check.True(zs[0] == 8 && nonces[0] == 3 && rs[0] == 10 && ss[0] == 7, "the first signature is z " + zs[0] + ", k " + nonces[0] + ", r " + rs[0] + ", s " + ss[0] + ", and the video's is z 8, k 3, r 10, s 7");
                Dictionary<string, object> rec = MiniJson.Obj(ec, "recovery");
                int nonce = Mod((long)(zs[0] - zs[1]) * Inv(Mod(ss[0] - ss[1], N), N), N);
                Check.True((int)MiniJson.Num(rec, "nonce", -1) == nonce && nonce == Mod(nonces[0], N), "the recovered nonce is not (z1 - z2) / (s1 - s2) mod 19");
                int priv = Mod((long)(Mod((long)ss[0] * nonce, N) - zs[0]) * Inv(rs[0], N), N);
                Check.True((int)MiniJson.Num(rec, "privateKey", -1) == priv && priv == Mod(d, N), "the recovered private key is not (s1 k - z1) / r mod 19, or is not the signer's key");
                Check.True(priv == 7, "the recovery gives d = " + priv + ", and the video's key is 7");
                HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", true));
                return "with Show keys OFF the toy curve is y^2 = x^3 + 2x + 2 over GF(17): its " + want.Count + " points, 19 hops of k.G, double-and-add, the ladder, ECDH and 2 ECDSA signatures all match the suite's own arithmetic, and the reused nonce gives back the private key. The video's numbers hold: 13G = (16, 4), and d 7, Q (0, 6), z 8, k 3, r 10, s 7";
            }
        }

        // ---------------------------------------------------------------- the real curve

        static double On(double x, double y) { return y * y - (x * x * x + A * x + B); }

        static void OnCurve(string where, double x, double y)
        {
            double scale = Math.Max(1.0, Math.Abs(x * x * x) + Math.Abs(y * y));
            Check.True(Math.Abs(On(x, y)) <= 1e-9 * scale, where + " (" + x + ", " + y + ") is not on y^2 = x^3 + 2x + 2");
        }

        static double[] RealPt(Dictionary<string, object> parent, string field, string where)
        {
            Dictionary<string, object> d = MiniJson.Obj(parent, field);
            Check.True(d != null, where + ": no " + field);
            return new double[] { MiniJson.Num(d, "x", double.NaN), MiniJson.Num(d, "y", double.NaN) };
        }

        static void LineExample(Dictionary<string, object> e, bool tangent, string where)
        {
            Check.True(e != null, where + ": missing");
            double[] p = RealPt(e, "p", where), q = RealPt(e, "q", where), rp = RealPt(e, "rPrime", where), r = RealPt(e, "r", where);
            OnCurve(where + " P", p[0], p[1]); OnCurve(where + " Q", q[0], q[1]);
            double lambda = tangent ? (3 * p[0] * p[0] + A) / (2 * p[1]) : (q[1] - p[1]) / (q[0] - p[0]);
            double tol = 1e-9 * Math.Max(1.0, Math.Abs(lambda));
            Check.True(Math.Abs(MiniJson.Num(e, "lambda", double.NaN) - lambda) <= tol, where + ": lambda is not the " + (tangent ? "tangent" : "chord") + " slope");
            OnCurve(where + " R'", rp[0], rp[1]);
            Check.True(Math.Abs((rp[1] - p[1]) - lambda * (rp[0] - p[0])) <= 1e-9 * Math.Max(1.0, Math.Abs(rp[1])), where + ": R' is not on the line through P");
            Check.True(Math.Abs(r[0] - rp[0]) <= 1e-12 * Math.Max(1.0, Math.Abs(r[0])) && Math.Abs(r[1] + rp[1]) <= 1e-12 * Math.Max(1.0, Math.Abs(r[1])), where + ": R is not R' reflected across the x axis");
        }

        [Clause("A19.host.real-curve-open-and-on-curve")]
        public static string RealCurve(Ctx c)
        {
            using (HostProc h = A17.Host(c, "walk-real-curve"))
            {
                Reply off = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", false));
                Check.True(off.Ok, "PUT show-keys got " + off);
                Reply r = GetOpen(h, RealPath, "slice P8a");
                Check.True(MiniJson.Num(r.Json, "a", 0) == A && MiniJson.Num(r.Json, "b", 0) == B, "the real curve is not y^2 = x^3 + 2x + 2");
                int points = 0;
                foreach (string branch in new string[] { "upper", "lower" })
                    foreach (object o in MiniJson.Arr(r.Json, branch) ?? new List<object>())
                    {
                        Dictionary<string, object> pt = MiniJson.AsObject(o);
                        double x = MiniJson.Num(pt, "x", double.NaN), y = MiniJson.Num(pt, "y", double.NaN);
                        OnCurve(branch, x, y);
                        Check.True(branch == "upper" ? y >= 0 : y <= 0, branch + " branch point (" + x + ", " + y + ") is on the wrong side");
                        points++;
                    }
                Check.True(points > 0, "the real curve has no sample points");
                LineExample(MiniJson.Obj(r.Json, "chord"), false, "chord");
                LineExample(MiniJson.Obj(r.Json, "tangent"), true, "tangent");
                HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", true));
                return "with Show keys OFF " + points + " sample points lie on y^2 = x^3 + 2x + 2, and the chord and tangent examples each have the right slope, an R' on the line and the curve, and R as its reflection";
            }
        }
    }
}
