using System;
using System.Collections.Generic;
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
                            foreach (string x in p.Doublings) doublings.Add(x);
                            parts.Add(D("factor", (double)p.Factor, "input", p.Input, "doublings", doublings, "reduced", p.Reduced, "result", p.Result));
                        }
                        terms.Add(D("result", b.Result, "parts", parts));
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
                if (M("walk-tables-leak-terms")) tables["terms"] = new List<object> { D("result", "04") };
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
            if (source != "text" || bits != "128")
            {
                if (M("walk-bad-argument-500")) { WalkFail(ctx, 500, "AES_WALK_DIVERGED", "a bad argument"); return true; }
                WalkFail(ctx, 400, "WALK_BAD_ARGUMENT", "source and keyBits");
                return true;
            }
            byte[] key = M("walk-canned") || (s.EcbFork && M("walk-fork-other-key")) ? CannedWalkKey : RunKey(s);
            byte[] block = Encoding.ASCII.GetBytes("Pump four is ok.");
            if (M("walk-input-other")) block[0] ^= 1;
            RefAes reference = new RefAes(key);
            WalkRun forward = reference.Encrypt(block), inverse = reference.Decrypt(Hex.Decode(forward.Output));
            if (M("walk-state-flip")) forward.Steps[2].State = (forward.Steps[2].State[0] == '0' ? "1" : "0") + forward.Steps[2].State.Substring(1);
            if (M("walk-term-flip")) foreach (WalkStep t in forward.Steps) if (t.Terms != null) { t.Terms[2].Parts[0].Result = "00"; break; }
            if (M("walk-no-terms")) foreach (WalkStep t in inverse.Steps) t.Terms = null;
            if (M("walk-inverse-order")) { WalkStep a = inverse.Steps[1]; inverse.Steps[1] = inverse.Steps[2]; inverse.Steps[2] = a; }
            List<object> words = new List<object>();
            foreach (KeyRow r in reference.KeyRows)
            {
                Dictionary<string, object> d = D("i", (double)r.Index, "word", M("walk-key-row-flip") && r.Index == 20 ? "00000000" : r.Word);
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
            Dictionary<string, object> reply = D("source", "text", "keyBits", 128.0, "rounds", 10.0, "keySource", "run", "inputHex", Hex.Encode(block),
                "keyWords", words, "forward", RunJson(forward), "inverse", RunJson(inverse), "wire", D("status", M("walk-label-match") || (s.EcbFork && !M("walk-fork-not-sent")) ? "match" : "notSent", "message", "TextEcb"));
            WalkWrite(ctx, 200, reply, M("walk-no-store-missing"));
            return true;
        }
    }
}
