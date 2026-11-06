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
                WalkWrite(ctx, 200, D("sbox", Hex.Encode(sbox), "inverseSbox", Hex.Encode(RefAes.InverseSbox)), M("walk-no-store-missing"));
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
            byte[] key = M("walk-canned") ? CannedWalkKey : RunKey(s);
            byte[] block = Encoding.ASCII.GetBytes("Pump four is ok.");
            if (M("walk-input-other")) block[0] ^= 1;
            RefAes reference = new RefAes(key);
            WalkRun forward = reference.Encrypt(block), inverse = reference.Decrypt(Hex.Decode(forward.Output));
            if (M("walk-state-flip")) forward.Steps[2].State = (forward.Steps[2].State[0] == '0' ? "1" : "0") + forward.Steps[2].State.Substring(1);
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
                "keyWords", words, "forward", RunJson(forward), "inverse", RunJson(inverse), "wire", D("status", M("walk-label-match") ? "match" : "notSent", "message", "TextEcb"));
            WalkWrite(ctx, 200, reply, M("walk-no-store-missing"));
            return true;
        }
    }
}
