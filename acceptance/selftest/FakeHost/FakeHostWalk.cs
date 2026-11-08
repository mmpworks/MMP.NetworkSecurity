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
            for (int bit = 254; bit >= 0; bit--) rows.Add(D("bit", (double)bit, "isOne", X25519WalkClauses.Bit(bits, bit)));
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
