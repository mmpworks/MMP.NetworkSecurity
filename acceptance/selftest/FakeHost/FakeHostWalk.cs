using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace Acceptance
{
    /// <summary>The walk routes of the fake Host, built from CONTRACT.md section 6. RefAes gives the states. Each defect name below is one way a Host could get the walk wrong.</summary>
    public sealed partial class FakeHost
    {
        static readonly byte[] CannedWalkKey = Hex.Decode("000102030405060708090a0b0c0d0e0f");

        static void WalkWrite(HttpListenerContext ctx, int status, object body, bool store)
        {
            if (!store) ctx.Response.Headers["Cache-Control"] = "no-store";
            Write(ctx, status, body);
        }

        void WalkFail(HttpListenerContext ctx, int status, string code, string message)
        {
            Dictionary<string, object> d = D("code", code, "message", message, "retryable", false, "requestId", "fake-request");
            if (M("walk-no-request-id")) d.Remove("requestId");
            WalkWrite(ctx, status, d, false);
        }

        static List<object> StepsJson(WalkRun run)
        {
            List<object> steps = new List<object>();
            foreach (WalkStep s in run.Steps)
            {
                Dictionary<string, object> d = D("kind", s.Kind, "round", (double)s.Round, "state", s.State);
                if (s.RoundKey != null) d["roundKey"] = s.RoundKey;
                if (s.Terms != null)
                {
                    List<object> terms = new List<object>();
                    foreach (ColumnByte b in s.Terms)
                    {
                        List<object> parts = new List<object>();
                        foreach (TermPart p in b.Parts)
                        {
                            List<object> doublings = new List<object>();
                            foreach (Doubling x in p.Doublings) doublings.Add(D("from", x.From, "shifted", x.Shifted.ToString("x3"), "reduced", x.Reduced, "to", x.To));
                            List<object> picks = new List<object>(), sums = new List<object>();
                            foreach (string q in p.Picks) picks.Add(q);
                            foreach (string q in p.Sums) sums.Add(q);
                            parts.Add(D("factor", (double)p.Factor, "input", p.Input, "doublings", doublings, "picks", picks, "sums", sums, "reduced", p.Reduced, "result", p.Result));
                        }
                        List<object> running = new List<object>();
                        foreach (string q in b.Running) running.Add(q);
                        terms.Add(D("result", b.Result, "running", running, "parts", parts));
                    }
                    d["terms"] = terms;
                }
                steps.Add(d);
            }
            return steps;
        }

        static Dictionary<string, object> RunJson(WalkRun run) { return D("input", run.Input, "output", run.Output, "steps", StepsJson(run)); }

        byte[] RunKey(Session s)
        {
            foreach (SessionEv e in s.Events) foreach (RawSecret r in e.Secrets) if (r.Name == "aes.key") return r.Bytes;
            return null;
        }

        /// <summary>Design section 2.2g: /typed-block and /long-text run on the public practice key and stay open with Show keys OFF.</summary>
        bool TypedRoute(HttpListenerContext ctx, string path, Dictionary<string, object> body)
        {
            if (path != "/api/walk/aes/typed-block" && path != "/api/walk/aes/long-text") return false;
            if (M("walk-routes-missing")) return false;
            // Design section 2.2g: both run on the public practice key and stay open with Show keys OFF.
            if (!_showKeys && M("typed-closed-off")) { WalkFail(ctx, 409, "KEYS_HIDDEN", "closed"); return true; }
            int typedBits = body != null && body.ContainsKey("keyBits") ? (int)MiniJson.Num(body, "keyBits", 128) : 128;
            if (typedBits != 128 && typedBits != 192 && typedBits != 256 && !M("typed-bad-size-accepted")) { WalkFail(ctx, 400, "WALK_BAD_ARGUMENT", "keyBits must be 128, 192 or 256."); return true; }
            if (typedBits != 128 && typedBits != 192 && typedBits != 256) typedBits = 128;
            if (M("typed-size-ignored")) typedBits = 128;
            byte[] typedKey = M("typed-run-key") ? CannedWalkKey : AesWalkHostClauses.TypedPracticeKey(typedBits);
            byte[] text = Encoding.UTF8.GetBytes((body == null ? null : MiniJson.Str(body, "text")) ?? "");
            if (path.EndsWith("typed-block", StringComparison.Ordinal))
            {
                byte[] block = new byte[16];
                int used = Math.Min(16, text.Length);
                Array.Copy(text, block, used);
                for (int i = used; i < 16; i++) block[i] = (byte)(16 - used);
                WalkRun fw = new RefAes(typedKey).Encrypt(block);
                WalkWrite(ctx, 200, D("walk", D("source", "typed", "keyBits", (double)typedBits, "rounds", (double)(typedBits / 32 + 6), "keySource", "typed-practice", "inputHex", Hex.Encode(block), "forward", RunJson(fw)),
                    "cut", D("block", Hex.Encode(block), "usedBytes", (double)used, "paddingBytes", (double)(16 - used))), false);
                return true;
            }
            int pad = 16 - text.Length % 16;
            byte[] all = new byte[text.Length + pad];
            Array.Copy(text, all, text.Length);
            for (int i = text.Length; i < all.Length; i++) all[i] = (byte)pad;
            List<object> rows = new List<object>();
            string prev = null;
            using (System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = typedKey;
                for (int b = 0; b < all.Length / 16; b++)
                {
                    byte[] blk = new byte[16];
                    Array.Copy(all, b * 16, blk, 0, 16);
                    string ecb = Hex.Encode(aes.EncryptEcb(blk, System.Security.Cryptography.PaddingMode.None));
                    rows.Add(D("block", (double)b, "data", Hex.Encode(blk), "ecb", ecb, "ecbRepeat", ecb == prev));
                    prev = ecb;
                }
            }
            WalkWrite(ctx, 200, D("keySource", "typed-practice", "keyBits", (double)typedBits, "blocks", (double)rows.Count, "rows", rows), false);
            return true;
        }

        /// <summary>The TLS 1.3 key schedule walk on RFC 8448's public inputs, open with Show keys OFF (sections-plan.md section 4). The fake serves each value from the suite's own vector file.</summary>
        bool ScheduleRoute(HttpListenerContext ctx, string path)
        {
            if (path != Tls13WalkClauses.Path || M("walk-routes-missing")) return false;
            if (!_showKeys && M("schedule-closed-off")) { WalkFail(ctx, 409, "KEYS_HIDDEN", "closed"); return true; }
            string vectors = Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(_vaultScript))), "vectors");
            VectorRecord rfc = Nsv.Load(vectors, "tls13-rfc8448.nsv", "tls13-rfc8448-1rtt")[0];
            List<object> steps = new List<object>();
            foreach (string name in new string[] { "early_secret", "derived_for_handshake", "ecdhe_shared", "handshake_secret", "c_hs_traffic", "s_hs_traffic", "derived_for_master", "master_secret", "s_finished_verify_data", "c_ap_traffic", "s_ap_traffic", "c_finished_verify_data" })
            {
                string output = rfc.Str(name);
                if (name == "master_secret" && M("schedule-step-flip")) output = (output[0] == '0' ? "1" : "0") + output.Substring(1);
                steps.Add(D("name", name, "kind", "Extract", "output", output));
            }
            WalkWrite(ctx, 200, D("source", "RFC 8448 section 3", "suite", "TLS_AES_128_GCM_SHA256", "keySource", M("schedule-other-keysource") ? "run" : "rfc8448", "steps", steps), false);
            return true;
        }

        /// <summary>
        /// The Ed25519 walk on RFC 8032 section 7.1's TESTs 1 to 3, open with Show keys OFF. The fake serves the vector file's seed, public key and
        /// signature, and builds expanded, scalar, prefix, r and h with SHA-512. Defects: ed25519-closed-off, ed25519-unclamped,
        /// ed25519-wrong-h, ed25519-bad-test-ok (test 4 answers 200).
        /// </summary>
        bool Ed25519Route(HttpListenerContext ctx, string path)
        {
            if (path != Ed25519WalkClauses.Path || M("walk-routes-missing")) return false;
            if (!_showKeys && M("ed25519-closed-off")) { WalkFail(ctx, 409, "KEYS_HIDDEN", "closed"); return true; }
            string t = ctx.Request.QueryString["test"];
            int n = t == "1" ? 1 : t == "2" ? 2 : t == "3" ? 3 : t == "4" && M("ed25519-bad-test-ok") ? 1 : 0;
            if (n == 0) { WalkFail(ctx, 400, "WALK_BAD_ARGUMENT", "test must be 1, 2 or 3."); return true; }
            string vectors = Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(_vaultScript))), "vectors");
            VectorRecord v = Nsv.Load(vectors, "ed25519-rfc8032.nsv", "ed25519")[n - 1];
            byte[] seed = Hex.Decode(v.Str("seed")), msg = Hex.Decode(v.Str("message") ?? ""), pub = Hex.Decode(v.Str("public")), sig = Hex.Decode(v.Str("signature"));
            byte[] expanded = Ed25519WalkClauses.Sha512(seed), low = new byte[32], prefix = new byte[32], rPoint = new byte[32], s = new byte[32];
            Array.Copy(expanded, low, 32); Array.Copy(expanded, 32, prefix, 0, 32); Array.Copy(sig, rPoint, 32); Array.Copy(sig, 32, s, 0, 32);
            byte[] scalar = M("ed25519-unclamped") ? low : Ed25519WalkClauses.Clamp(low);
            System.Numerics.BigInteger r = Ed25519WalkClauses.FromLittleEndian(Ed25519WalkClauses.Sha512(prefix, msg)) % Ed25519WalkClauses.L;
            System.Numerics.BigInteger h = Ed25519WalkClauses.FromLittleEndian(Ed25519WalkClauses.Sha512(rPoint, pub, msg)) % Ed25519WalkClauses.L;
            if (M("ed25519-wrong-h")) h = (h + 1) % Ed25519WalkClauses.L;
            Func<byte[], string> hx = b => Hex.Encode(b).ToLowerInvariant();
            // The verify middle points on the suite's edwards25519 arithmetic. The defect ed25519-sb-wrong shows 2*S*B as sB.
            Ed25519WalkClauses.EPt bp = Ed25519WalkClauses.BasePoint(), aPt = Ed25519WalkClauses.Decode(pub);
            Ed25519WalkClauses.EPt sB = Ed25519WalkClauses.EMul(Ed25519WalkClauses.FromLittleEndian(s), bp);
            Ed25519WalkClauses.EPt minusHA = Ed25519WalkClauses.EMul(h, new Ed25519WalkClauses.EPt((Ed25519WalkClauses.Pq - aPt.X) % Ed25519WalkClauses.Pq, aPt.Y));
            byte[] sBShown = Ed25519WalkClauses.Encode(M("ed25519-sb-wrong") ? Ed25519WalkClauses.EAdd(sB, sB) : sB);
            WalkWrite(ctx, 200, D("test", (double)n, "source", "RFC 8032 section 7.1", "keySource", "rfc8032", "byteOrder", "little-endian",
                "seed", hx(seed), "message", hx(msg), "expanded", hx(expanded), "scalar", hx(scalar), "prefix", hx(prefix), "publicKey", hx(pub),
                "r", hx(Ed25519WalkClauses.ToLittleEndian32(r)), "rPoint", hx(rPoint), "h", hx(Ed25519WalkClauses.ToLittleEndian32(h)), "s", hx(s), "signature", hx(sig),
                "verify", D("sB", hx(sBShown), "minusHA", hx(Ed25519WalkClauses.Encode(minusHA)), "rPrime", hx(rPoint), "valid", true)), false);
            return true;
        }

        /// <summary>The X25519 ladder walk on RFC 7748 section 6.1's public scalars, open with Show keys OFF. The fake serves the values from the suite's vector file and builds each row's bit from the clamped scalar.</summary>
        bool X25519Route(HttpListenerContext ctx, string path)
        {
            if (path != X25519WalkClauses.Path || M("walk-routes-missing")) return false;
            if (!_showKeys && M("x25519-closed-off")) { WalkFail(ctx, 409, "KEYS_HIDDEN", "closed"); return true; }
            string step = ctx.Request.QueryString["step"];
            if (step != "alice-public" && step != "bob-public" && step != "shared") { WalkFail(ctx, 400, "WALK_BAD_ARGUMENT", "step must be alice-public, bob-public or shared."); return true; }
            string vectors = Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(_vaultScript))), "vectors");
            VectorRecord v = Nsv.Load(vectors, "x25519-rfc7748.nsv", "x25519-dh")[0];
            string nine = "09" + new string('0', 62);
            string scalar = step == "bob-public" ? v.Str("b") : v.Str("a");
            string point = step == "shared" ? v.Str("b_pub") : nine;
            string result = step == "alice-public" ? v.Str("a_pub") : step == "bob-public" ? v.Str("b_pub") : v.Str("k");
            if (step == "shared" && M("x25519-wrong-shared")) result = (result[0] == '0' ? "1" : "0") + result.Substring(1);
            byte[] raw = Hex.Decode(scalar), clamped = X25519WalkClauses.Clamp(raw);
            byte[] bits = M("x25519-rows-unclamped") ? raw : clamped;
            List<object> rows = new List<object>();
            // swap is the conditional-swap argument, the row's bit (TweetNaCl's order). The defect x25519-swap-wrong flips it on bit 100.
            for (int bit = 254; bit >= 0; bit--) rows.Add(D("bit", (double)bit, "isOne", X25519WalkClauses.Bit(bits, bit), "swap", X25519WalkClauses.Bit(bits, bit) ^ (bit == 100 && M("x25519-swap-wrong"))));
            WalkWrite(ctx, 200, D("step", step, "source", "RFC 7748 section 6.1", "keySource", "rfc7748", "byteOrder", "little-endian", "scalar", scalar, "clamped", Hex.Encode(clamped), "point", point, "result", result, "rows", rows), false);
            return true;
        }

        /// <summary>The Diffie-Hellman walk on public practice exponents, open with Show keys OFF. The fake computes each number with BigInteger.</summary>
        bool DhRoute(HttpListenerContext ctx, string path)
        {
            if (path != DhWalkClauses.Path || M("walk-routes-missing")) return false;
            if (!_showKeys && M("dh-closed-off")) { WalkFail(ctx, 409, "KEYS_HIDDEN", "closed"); return true; }
            string group = ctx.Request.QueryString["group"];
            if (group != "small" && group != "group14") { WalkFail(ctx, 400, "WALK_BAD_ARGUMENT", "group must be small or group14."); return true; }
            System.Numerics.BigInteger p, g, x, y;
            if (group == "small") { p = 467; g = 5; x = 153; y = 197; }
            else
            {
                string vectors = Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(_vaultScript))), "vectors");
                VectorRecord v = Nsv.Load(vectors, "dh-group14-rfc3526.nsv", "dh-group14-params")[0];
                p = DhWalkClauses.FromHex(v.Str("p")); g = DhWalkClauses.FromHex(v.Str("g"));
                x = DhWalkClauses.FromHex("9b" + new string('3', 62)); y = DhWalkClauses.FromHex("a7" + new string('5', 62));
            }
            System.Numerics.BigInteger cp = System.Numerics.BigInteger.ModPow(g, x, p), sp = System.Numerics.BigInteger.ModPow(g, y, p);
            WalkWrite(ctx, 200, D("group", group, "keySource", "practice", "realExponentBits", M("dh-real-bits-short") ? 160.0 : 512.0, "prime", DhNum(p), "generator", DhNum(g),
                "client", D("private", DhNum(x), "public", DhPow(g, x, p), "shared", DhPow(sp, x, p)),
                "server", D("private", DhNum(y), "public", DhPow(g, y, p), "shared", DhPow(cp, y, p, M("dh-shared-mismatch")))), false);
            return true;
        }

        static Dictionary<string, object> DhNum(System.Numerics.BigInteger v)
        {
            string hex = v.ToString("x").TrimStart('0');
            if (hex.Length == 0) hex = "0";
            if (hex.Length % 2 == 1) hex = "0" + hex;
            return D("hex", hex, "dec", v.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        Dictionary<string, object> DhPow(System.Numerics.BigInteger b, System.Numerics.BigInteger e, System.Numerics.BigInteger p, bool wrongResult = false)
        {
            System.Numerics.BigInteger acc = 1, bb = b % p;
            int top = 0; for (System.Numerics.BigInteger t = e; t > 0; t >>= 1) top++;
            List<object> rows = new List<object>();
            for (int bit = top - 1; bit >= 0; bit--)
            {
                bool one = !(e >> bit).IsEven;
                if (!M("dh-row-skip-square")) acc = acc * acc % p;
                Dictionary<string, object> row = D("bit", (double)bit, "isOne", one, "afterSquare", DhNum(acc));
                if (one) { acc = acc * bb % p; row["afterMultiply"] = DhNum(acc); }
                rows.Add(row);
            }
            System.Numerics.BigInteger result = wrongResult ? (acc + 1) % p : acc;
            return D("base", DhNum(bb), "exponent", DhNum(e), "result", DhNum(result), "rows", rows);
        }

        /// <summary>Slice P8a's teaching curves: the toy curve over GF(17) and the real-curve picture, open with Show keys OFF.</summary>
        bool CurveRoute(HttpListenerContext ctx, string path)
        {
            if ((path != CurveWalkClauses.ToyPath && path != CurveWalkClauses.RealPath && path != CurveWalkClauses.ToyAddPath) || M("walk-routes-missing")) return false;
            if (path == CurveWalkClauses.RealPath) { WalkWrite(ctx, 200, RealCurveReply(), false); return true; }
            if (path == CurveWalkClauses.ToyAddPath) { ToyPickRoute(ctx); return true; }
            if (!_showKeys && M("toy-closed-off")) { WalkFail(ctx, 409, "KEYS_HIDDEN", "closed"); return true; }
            WalkWrite(ctx, 200, ToyCurveReply(), false);
            return true;
        }

        static Dictionary<string, object> ToyPt(CurveWalkClauses.Pt p) { return p == null ? D("infinity", true) : D("x", (double)p.X, "y", (double)p.Y); }

        /// <summary>
        /// The learner's pick on the toy curve, by index: 0 to 17 are the points in x, then y order, and 18 is O. Defects: toy-pick-wrong-result
        /// names the next index as the sum, and toy-pick-bad-index-ok answers 200 for index 19.
        /// </summary>
        void ToyPickRoute(HttpListenerContext ctx)
        {
            List<CurveWalkClauses.Pt> list = CurveWalkClauses.AllPoints();
            list.Add(null);
            int i, j;
            Func<string, int> pick = name =>
            {
                string s = ctx.Request.QueryString[name];
                int v;
                if (s == null || !int.TryParse(s, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out v)) return -1;
                if (v == list.Count && M("toy-pick-bad-index-ok")) return 0;
                return v < list.Count ? v : -1;
            };
            i = pick("p"); j = pick("q");
            if (i < 0 || j < 0) { WalkFail(ctx, 400, "WALK_BAD_ARGUMENT", (i < 0 ? "p" : "q") + " must be a whole number from 0 to 18."); return; }
            CurveWalkClauses.Pt p = list[i], q = list[j], sum = CurveWalkClauses.Add(p, q);
            int at = list.FindIndex(x => x == null ? sum == null : sum != null && x.X == sum.X && x.Y == sum.Y);
            if (M("toy-pick-wrong-result")) at = (at + 1) % list.Count;
            Dictionary<string, object> step;
            if (p == null || q == null || (p.X == q.X && CurveWalkClauses.Mod(p.Y + q.Y, CurveWalkClauses.P) == 0))
                step = D("kind", p == null || q == null ? "identity" : "opposite", "p", ToyPt(p), "q", ToyPt(q), "result", ToyPt(sum), "numerator", null, "denominator", null, "inverse", null, "lambda", null);
            else step = ToyStep(p, q);
            // toy-pick-wrong-kind names a double "add". The sum and the slope stay right, so only the kind check can catch it.
            if (M("toy-pick-wrong-kind") && (string)step["kind"] == "double") step["kind"] = "add";
            WalkWrite(ctx, 200, D("pIndex", (double)i, "qIndex", (double)j, "resultIndex", (double)at, "step", step), false);
        }

        Dictionary<string, object> ToyStep(CurveWalkClauses.Pt p, CurveWalkClauses.Pt q)
        {
            const int P = CurveWalkClauses.P;
            bool dbl = p.X == q.X && p.Y == q.Y;
            int num = dbl ? CurveWalkClauses.Mod(3L * p.X * p.X + CurveWalkClauses.A, P) : CurveWalkClauses.Mod(q.Y - p.Y, P);
            int den = dbl ? CurveWalkClauses.Mod(2 * p.Y, P) : CurveWalkClauses.Mod(q.X - p.X, P);
            int inv = CurveWalkClauses.Inv(den, P);
            return D("kind", dbl ? "double" : "add", "p", ToyPt(p), "q", ToyPt(q), "result", ToyPt(CurveWalkClauses.Add(p, q)),
                "numerator", (double)num, "denominator", (double)den, "inverse", D("of", (double)den, "modulus", (double)P, "value", (double)inv), "lambda", (double)CurveWalkClauses.Mod((long)num * inv, P));
        }

        Dictionary<string, object> ToyCurveReply()
        {
            const int N = CurveWalkClauses.N;
            CurveWalkClauses.Pt g = new CurveWalkClauses.Pt(5, 1);
            List<object> points = new List<object>();
            foreach (CurveWalkClauses.Pt pt in CurveWalkClauses.AllPoints()) points.Add(ToyPt(pt));
            if (M("toy-point-missing")) points.RemoveAt(0);
            List<object> hops = new List<object>();
            for (int k = 1; k <= N; k++) hops.Add(D("k", (double)k, "point", ToyPt(CurveWalkClauses.Mul(k, g))));
            int kk = 13, d = 7, nonce = 3, z1 = 8, z2 = 11, a = 3, b = 7;
            CurveWalkClauses.Pt q = CurveWalkClauses.Mul(d, g), bigR = CurveWalkClauses.Mul(nonce, g);
            int r = CurveWalkClauses.Mod(bigR.X, N);
            Func<int, Dictionary<string, object>> sig = z => D("z", (double)z, "nonce", (double)nonce, "bigR", ToyPt(bigR), "r", (double)r,
                "s", (double)CurveWalkClauses.Mod((long)CurveWalkClauses.Inv(nonce, N) * (z + (long)r * d), N));
            Func<int, Dictionary<string, object>> ver = z =>
            {
                int s = CurveWalkClauses.Mod((long)CurveWalkClauses.Inv(nonce, N) * (z + (long)r * d), N), w = CurveWalkClauses.Inv(s, N);
                int u1 = CurveWalkClauses.Mod((long)z * w, N), u2 = CurveWalkClauses.Mod((long)r * w, N);
                return D("u1", (double)u1, "u2", (double)u2, "x", ToyPt(CurveWalkClauses.Add(CurveWalkClauses.Mul(u1, g), CurveWalkClauses.Mul(u2, q))), "valid", true);
            };
            return D("source", "video 4Tfmwxr0I34", "keySource", "toy",
                "curve", D("p", (double)CurveWalkClauses.P, "a", (double)CurveWalkClauses.A, "b", (double)CurveWalkClauses.B, "order", (double)N, "g", ToyPt(g)),
                "points", points, "addExample", ToyStep(g, new CurveWalkClauses.Pt(6, 3)), "doubleExample", ToyStep(g, g), "hops", hops, "k", (double)kk,
                "doubleAndAdd", new List<object> { D("bit", 0.0, "isOne", true, "after", ToyPt(CurveWalkClauses.Mul(kk, g))) },
                "ladder", new List<object> { D("bit", 0.0, "isOne", true, "r0", ToyPt(CurveWalkClauses.Mul(kk, g))) },
                "ecdh", D("alicePrivate", (double)a, "bobPrivate", (double)b, "alicePublic", ToyPt(CurveWalkClauses.Mul(a, g)), "bobPublic", ToyPt(CurveWalkClauses.Mul(b, g)),
                    "aliceShared", ToyPt(CurveWalkClauses.Mul(a * b, g)), "bobShared", ToyPt(CurveWalkClauses.Mul(a * b, g))),
                "ecdsa", D("signerPrivate", (double)d, "signerPublic", ToyPt(q), "first", sig(z1), "second", sig(z2), "firstVerify", ver(z1), "secondVerify", ver(z2),
                    "recovery", D("nonce", (double)nonce, "privateKey", (double)(M("toy-recovery-wrong") ? d + 1 : d))));
        }

        Dictionary<string, object> RealCurveReply()
        {
            Func<double, double> y = x => Math.Sqrt(x * x * x + 2 * x + 2);
            List<object> upper = new List<object>(), lower = new List<object>();
            for (double x = -0.7709; x <= 3.0; x += 0.25) { double v = y(x); if (double.IsNaN(v)) continue; upper.Add(D("x", x, "y", v)); lower.Add(D("x", x, "y", -v)); }
            if (M("real-off-curve")) upper[2] = D("x", -0.27, "y", 9.0);
            Func<double, double, bool, Dictionary<string, object>> line = (x1, x2, tangent) =>
            {
                double y1 = y(x1), y2 = y(x2), l = tangent ? (3 * x1 * x1 + 2) / (2 * y1) : (y2 - y1) / (x2 - x1);
                double x3 = l * l - x1 - x2, yr = y1 + l * (x3 - x1);
                return D("kind", tangent ? "tangent" : "chord", "p", D("x", x1, "y", y1), "q", D("x", x2, "y", y2), "rPrime", D("x", x3, "y", yr), "r", D("x", x3, "y", -yr), "lambda", l);
            };
            // The offered picks: 3 chords and 1 tangent, each R' inside -0.7709 to 3.0. The defect real-sample-off-line moves one R' off its line.
            List<object> samples = new List<object> { line(-0.5, 0.5, false), line(0.0, 2.0, false), line(-0.25, 1.0, false), line(0.5, 0.5, true) };
            // real-sample-out-of-range: the tangent at x = -0.7 has a true R' at x near 13, on its line and the curve, but outside 3.0. Only the range check can catch it.
            if (M("real-sample-out-of-range")) samples[3] = line(-0.7, -0.7, true);
            if (M("real-sample-off-line")) { Dictionary<string, object> s1 = (Dictionary<string, object>)samples[1]; Dictionary<string, object> rp = (Dictionary<string, object>)s1["rPrime"]; s1["rPrime"] = D("x", (double)rp["x"], "y", (double)rp["y"] + 0.5); }
            return D("source", "video 4Tfmwxr0I34", "a", 2.0, "b", 2.0, "root", -0.7709, "xMax", 3.0, "upper", upper, "lower", lower, "chord", line(0.0, 1.0, false), "tangent", line(1.0, 1.0, true), "samples", samples);
        }

        /// <summary>The TLS 1.1 key schedule walk on the built-in training key, open with Show keys OFF (sections-plan.md line 159).</summary>
        bool Tls11ScheduleRoute(HttpListenerContext ctx, string path)
        {
            if (path != Tls11WalkClauses.Path || M("walk-routes-missing")) return false;
            if (!_showKeys && M("tls11-closed-off")) { WalkFail(ctx, 409, "KEYS_HIDDEN", "closed"); return true; }
            byte[] cr = new byte[32], sr = new byte[32], pre = new byte[48];
            for (int i = 0; i < 32; i++) { cr[i] = (byte)(i + 1); sr[i] = (byte)(0xa0 + i); }
            pre[0] = 3; pre[1] = 2; for (int i = 2; i < 48; i++) pre[i] = (byte)(i * 7);
            byte[] enc, spki;
            using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create())
            {
                if (M("tls11-other-key")) rsa.KeySize = 2048; else rsa.ImportPkcs8PrivateKey(_builtInTls11Key, out _);
                enc = rsa.Encrypt(pre, System.Security.Cryptography.RSAEncryptionPadding.Pkcs1);
                spki = rsa.ExportSubjectPublicKeyInfo();
            }
            byte[] crsr = new byte[64], srcr = new byte[64];
            Array.Copy(cr, crsr, 32); Array.Copy(sr, 0, crsr, 32, 32); Array.Copy(sr, srcr, 32); Array.Copy(cr, 0, srcr, 32, 32);
            byte[] master = Tls11WalkClauses.Prf(pre, "master secret", crsr, 48);
            if (M("tls11-master-wrong")) master[0] ^= 1;
            byte[] block = Tls11WalkClauses.Prf(master, "key expansion", srcr, 72);
            Func<int, int, string> part = (o, n) => Hex.Encode(Hex.Slice(block, o, n));
            WalkWrite(ctx, 200, D("keySource", "training", "serverKeyId", "server-tls11-rsa", "suite", "TLS_RSA_WITH_AES_128_CBC_SHA", "serverPublicKey", Hex.Encode(spki),
                "clientRandom", Hex.Encode(cr), "serverRandom", Hex.Encode(sr), "encryptedPremaster", Hex.Encode(enc), "premaster", Hex.Encode(pre), "premasterVersion", 770.0,
                "masterSecret", D("label", "master secret", "seed", Hex.Encode(crsr), "value", Hex.Encode(master)),
                "keyBlock", D("label", "key expansion", "seed", Hex.Encode(srcr), "value", Hex.Encode(block), "clientMacKey", part(0, 20), "serverMacKey", part(20, 20), "clientKey", part(40, 16), "serverKey", part(56, 16)),
                "keyLogLine", "CLIENT_RANDOM " + Hex.Encode(cr) + " " + Hex.Encode(master)), false);
            return true;
        }

        /// <summary>True when the path is a walk route. The route has answered by then.</summary>
        bool WalkRoute(HttpListenerContext ctx, string path)
        {
            if (M("walk-routes-missing") && path.IndexOf("/walk/aes/", StringComparison.Ordinal) >= 0) return false;
            if (path == "/api/walk/aes/tables")
            {
                if (!_showKeys && M("walk-tables-closed-off")) { WalkFail(ctx, 409, "KEYS_HIDDEN", "closed"); return true; }
                byte[] sbox = (byte[])RefAes.Sbox.Clone();
                if (M("walk-table-flip")) sbox[77] ^= 1;
                List<object> forwardMap = new List<object>(), inverseMap = new List<object>();
                foreach (int i in RefField.ShiftMap(false)) forwardMap.Add((double)i);
                foreach (int i in RefField.ShiftMap(true)) inverseMap.Add((double)i);
                if (M("walk-map-wrong")) { forwardMap[1] = 1.0; }
                List<object> sizes = new List<object>();
                sizes.Add(D("keyBits", 128.0, "keyWords", 4.0, "rounds", 10.0, "roundKeys", 11.0, "words", M("walk-sizes-wrong") ? 40.0 : 44.0, "rconUsed", 10.0));
                sizes.Add(D("keyBits", 192.0, "keyWords", 6.0, "rounds", 12.0, "roundKeys", 13.0, "words", 52.0, "rconUsed", 8.0));
                sizes.Add(D("keyBits", 256.0, "keyWords", 8.0, "rounds", 14.0, "roundKeys", 15.0, "words", 60.0, "rconUsed", 7.0));
                Dictionary<string, object> tables = D("sbox", Hex.Encode(sbox), "inverseSbox", Hex.Encode(RefAes.InverseSbox), "shiftRows", forwardMap, "inverseShiftRows", inverseMap,
                    "rcon", M("walk-rcon-wrong") ? "01020408102040800036" : "01020408102040801b36", "sizes", sizes);
                List<object> rconSteps = new List<object>();
                byte[] rconValues = RefField.RoundConstants(10);
                for (int i = 0; i < 9; i++)
                {
                    TermPart twice = RefField.Part(2, rconValues[i]);
                    Doubling step = twice.Doublings[0];
                    rconSteps.Add(D("from", step.From, "shifted", step.Shifted.ToString("x3"), "reduced", M("walk-rcon-steps-all-reduced") || step.Reduced, "to", M("walk-rcon-steps-drop-bit") ? (step.Shifted & 0xff).ToString("x2") : step.To));
                }
                if (M("walk-rcon-steps-short")) rconSteps.RemoveAt(8);
                if (!M("walk-rcon-steps-missing")) tables["rconSteps"] = rconSteps;
                if (M("walk-tables-leak-terms")) tables["terms"] = new List<object> { D("result", "04") };
                if (M("walk-tables-leak-words")) tables["keyWords"] = new List<object> { D("i", 4.0) };
                if (M("walk-tables-leak-key"))
                    foreach (Session open in _sessions.Values) { byte[] k = RunKey(open); if (k != null) tables["note"] = Hex.Encode(k); }
                WalkWrite(ctx, 200, tables, M("walk-no-store-missing"));
                return true;
            }
            if (!path.StartsWith("/api/sessions/") || !path.EndsWith("/walk/aes/block")) return false;
            string id = path.Substring("/api/sessions/".Length).Split('/')[0];
            Session s;
            bool found = _sessions.TryGetValue(id, out s);
            if (M("walk-session-before-toggle") && !found) { WalkFail(ctx, 404, "SESSION_NOT_FOUND", "no session " + id); return true; }
            if (!_showKeys && !M("walk-block-open-off"))
            {
                byte[] leak = found ? RunKey(s) : null;
                if (M("walk-off-error-terms")) { WalkWrite(ctx, 409, D("code", "KEYS_HIDDEN", "message", "off", "retryable", false, "requestId", "fake-request", "terms", new List<object> { D("result", "04") }), false); return true; }
                WalkFail(ctx, 409, "KEYS_HIDDEN", M("walk-off-error-bytes") && leak != null ? "Show keys is off. Key " + Hex.Encode(leak) : "Show keys is off, so these steps stay closed");
                return true;
            }
            if (!found) { WalkFail(ctx, 404, "SESSION_NOT_FOUND", "no session " + id); return true; }
            if (s.Lesson != 1) { WalkFail(ctx, 409, M("walk-lesson-wrong-code") ? "WALK_WAITING_FOR_WIRE" : "WALK_NOT_BUILT", "the walk is built for lesson 1"); return true; }
            string source = ctx.Request.QueryString["source"], bits = ctx.Request.QueryString["keyBits"];
            if (source != "text" || (bits != "128" && bits != "192" && bits != "256"))
            {
                if (M("walk-bad-argument-500")) { WalkFail(ctx, 500, "AES_WALK_DIVERGED", "a bad argument"); return true; }
                WalkFail(ctx, 400, "WALK_BAD_ARGUMENT", "source and keyBits");
                return true;
            }
            int keyBits = int.Parse(bits);
            byte[] key = keyBits != 128 ? AesWalkHostClauses.PracticeKey(M("walk-practice-no-xor") ? s.Seed ^ keyBits : s.Seed, keyBits)
                : M("walk-canned") || (s.EcbFork && M("walk-fork-other-key")) ? CannedWalkKey : RunKey(s);
            byte[] block = Encoding.ASCII.GetBytes("Pump four is ok.");
            if (M("walk-input-other")) block[0] ^= 1;
            RefAes reference = new RefAes(key);
            WalkRun forward = reference.Encrypt(block), inverse = reference.Decrypt(Hex.Decode(forward.Output));
            if (M("walk-state-flip")) forward.Steps[2].State = (forward.Steps[2].State[0] == '0' ? "1" : "0") + forward.Steps[2].State.Substring(1);
            if (M("walk-term-flip")) foreach (WalkStep t in forward.Steps) if (t.Terms != null) { t.Terms[2].Parts[0].Result = "00"; break; }
            if (M("walk-doubling-bytes")) foreach (WalkStep t in forward.Steps) if (t.Terms != null) foreach (ColumnByte b in t.Terms) foreach (TermPart p in b.Parts) foreach (Doubling d in p.Doublings) if (d.Reduced) d.To = (d.Shifted & 0xff).ToString("x2");
            if (M("walk-running-wrong")) foreach (WalkStep t in inverse.Steps) if (t.Terms != null) t.Terms[1].Running[2] = "00";
            if (M("walk-no-terms")) foreach (WalkStep t in inverse.Steps) t.Terms = null;
            if (M("walk-inverse-order")) { WalkStep a = inverse.Steps[1]; inverse.Steps[1] = inverse.Steps[2]; inverse.Steps[2] = a; }
            List<object> words = new List<object>();
            foreach (KeyRow r in reference.KeyRows)
            {
                Dictionary<string, object> d = D("i", (double)r.Index, "divisor", (double)r.Divisor, "quotient", (double)r.Quotient, "remainder", M("walk-word-test-wrong") ? 9.0 : (double)r.Remainder, "word", M("walk-key-row-flip") && r.Index == 20 ? "00000000" : r.Word);
                if (r.Previous != null) d["previous"] = r.Previous;
                if (r.Rotated != null) d["rotated"] = r.Rotated;
                if (r.Substituted != null) d["substituted"] = r.Substituted;
                if (r.Rcon != null) d["rcon"] = r.Rcon;
                if (r.AfterRcon != null) d["afterRcon"] = r.AfterRcon;
                if (r.KeyBack != null) d["keyBack"] = r.KeyBack;
                words.Add(d);
            }
            if (M("walk-adds-event")) Add(s, "client", "aes.walk.read");
            if (M("walk-state-in-events")) Add(s, "client", "aes.walk.state", Raw("walk.state", "client", Hex.Decode(forward.Steps[1].State)));
            Dictionary<string, object> reply = D("source", "text", "keyBits", (double)keyBits, "rounds", (double)(keyBits / 32 + 6), "keySource", keyBits != 128 && !M("walk-practice-says-run") ? "practice" : "run", "inputHex", Hex.Encode(block),
                "keyWords", words, "forward", RunJson(forward), "inverse", RunJson(inverse), "wire", D("status", M("walk-label-match") || (s.EcbFork && !M("walk-fork-not-sent")) ? "match" : "notSent", "message", "TextEcb"));
            WalkWrite(ctx, 200, reply, M("walk-no-store-missing"));
            return true;
        }
    }
}
