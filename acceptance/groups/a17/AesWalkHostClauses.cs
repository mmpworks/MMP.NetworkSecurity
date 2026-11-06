using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// A19, the AES walk over the Host's routes (docs/walkthrough-design.md sections 3.4 and 3.5, slice W1a). The field names are in CONTRACT.md section 6.
    /// The anchor: the key and the block come from a live lesson 1 trace on two seeds, RefAes gives every state, and the BCL judges the output. A stored table cannot pass, since each seed draws another key.
    /// </summary>
    public static class AesWalkHostClauses
    {
        const string Tables = "/api/walk/aes/tables";
        const string TextBlock = "Pump four is ok.";

        static string BlockPath(string sessionId) { return "/api/sessions/" + sessionId + "/walk/aes/block?source=text&keyBits=128"; }

        static string KeyOf(SessionRun run)
        {
            foreach (A17.SecretRef s in A17.Secrets(run)) if (s.Name == "aes.key" && !string.IsNullOrEmpty(s.Hex)) return s.Hex.ToLowerInvariant();
            throw new FailException("lesson 1's trace has no secret aes.key with hex, with Show keys ON");
        }

        static WalkRun ReadWalk(Dictionary<string, object> d, string where, int rounds)
        {
            Check.True(d != null, where + ": no walk in the reply");
            WalkRun w = new WalkRun();
            w.Rounds = rounds; w.Input = MiniJson.Str(d, "input"); w.Output = MiniJson.Str(d, "output");
            List<object> steps = MiniJson.Arr(d, "steps");
            Check.True(steps != null, where + ": no steps[]");
            foreach (object o in steps)
            {
                Dictionary<string, object> s = MiniJson.AsObject(o);
                WalkStep x = new WalkStep();
                x.Kind = MiniJson.Str(s, "kind"); x.Round = (int)MiniJson.Num(s, "round", -1); x.State = MiniJson.Str(s, "state"); x.RoundKey = MiniJson.Str(s, "roundKey");
                w.Steps.Add(x);
            }
            return w;
        }

        static List<KeyRow> ReadRows(Dictionary<string, object> d)
        {
            List<object> rows = MiniJson.Arr(d, "keyWords");
            Check.True(rows != null, "the block reply has no keyWords[]");
            List<KeyRow> r = new List<KeyRow>();
            foreach (object o in rows)
            {
                Dictionary<string, object> m = MiniJson.AsObject(o);
                KeyRow k = new KeyRow();
                k.Index = (int)MiniJson.Num(m, "i", -1); k.Previous = MiniJson.Str(m, "previous"); k.Rotated = MiniJson.Str(m, "rotated"); k.Substituted = MiniJson.Str(m, "substituted");
                k.Rcon = MiniJson.Str(m, "rcon"); k.AfterRcon = MiniJson.Str(m, "afterRcon"); k.KeyBack = MiniJson.Str(m, "keyBack"); k.Word = MiniJson.Str(m, "word");
                r.Add(k);
            }
            return r;
        }

        static Reply Block(HostProc h, SessionRun run)
        {
            Reply r = HostHttp.Get(h, BlockPath(run.SessionId));
            Check.True(r.Ok && r.Json != null, "GET block on lesson 1 got " + r);
            return r;
        }

        static void SetShowKeys(HostProc h, bool on)
        {
            Reply r = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", on));
            Check.True(r.Ok, "PUT show-keys got " + r);
        }

        [Clause("A19.host.tables-equal-fips-and-stay-open")]
        public static string TablesEqualFips(Ctx c)
        {
            using (HostProc h = A17.Host(c, "walk-tables"))
            {
                foreach (bool on in new bool[] { true, false })
                {
                    SetShowKeys(h, on);
                    Reply r = HostHttp.Get(h, Tables);
                    string state = on ? "Show keys ON" : "Show keys OFF";
                    Check.True(r.Ok && r.Json != null, state + ": GET tables got " + r);
                    Check.True(string.Equals(MiniJson.Str(r.Json, "sbox"), WalkCheck.Table(c, "sbox"), StringComparison.OrdinalIgnoreCase), state + ": sbox differs from FIPS 197 figure 7");
                    Check.True(string.Equals(MiniJson.Str(r.Json, "inverseSbox"), WalkCheck.Table(c, "inverse"), StringComparison.OrdinalIgnoreCase), state + ": inverseSbox differs from FIPS 197 figure 14");
                }
            }
            return "both tables equal FIPS 197 figures 7 and 14, with Show keys ON and OFF";
        }

        [Clause("A19.host.block-real-run-two-seeds")]
        public static string BlockRealRun(Ctx c)
        {
            int values = 0;
            string firstKey = null, firstState = null;
            using (HostProc h = A17.Host(c, "walk-block"))
            using (Aes aes = Aes.Create())
            {
                foreach (int seed in new int[] { 20261105, 7 })
                {
                    SessionRun run = HostSession.RunSeeded(h, 1, "glass", seed);
                    Check.True(run.SessionId != null, "seed " + seed + ": no session: " + run.ErrorCode);
                    string keyHex = KeyOf(run);
                    Check.True(keyHex != firstKey, "seeds 20261105 and 7 gave one key, so this clause cannot tell a stored table from a real walk");
                    firstKey = firstKey ?? keyHex;
                    byte[] key = Hex.Decode(keyHex), block = Encoding.ASCII.GetBytes(TextBlock);
                    Reply r = Block(h, run);
                    Check.True(MiniJson.Str(r.Json, "source") == "text", "source is " + MiniJson.Str(r.Json, "source"));
                    Check.True((int)MiniJson.Num(r.Json, "keyBits", 0) == 128, "keyBits is " + MiniJson.Num(r.Json, "keyBits", 0));
                    Check.True((int)MiniJson.Num(r.Json, "rounds", 0) == 10, "rounds is " + MiniJson.Num(r.Json, "rounds", 0));
                    Check.True(MiniJson.Str(r.Json, "keySource") == "run", "keySource is " + MiniJson.Str(r.Json, "keySource"));
                    Check.True(string.Equals(MiniJson.Str(r.Json, "inputHex"), Hex.Encode(block), StringComparison.OrdinalIgnoreCase), "inputHex is " + MiniJson.Str(r.Json, "inputHex") + ", expected '" + TextBlock + "'");

                    RefAes reference = new RefAes(key);
                    WalkRun forward = ReadWalk(MiniJson.Obj(r.Json, "forward"), "seed " + seed + " forward", 10);
                    values += WalkCheck.Compare("seed " + seed + " forward against RefAes", reference.Encrypt(block), forward);
                    aes.Key = key;
                    Check.True(string.Equals(forward.Output, Hex.Encode(aes.EncryptEcb(block, PaddingMode.None)), StringComparison.OrdinalIgnoreCase), "seed " + seed + ": the forward output differs from the BCL");
                    WalkRun inverse = ReadWalk(MiniJson.Obj(r.Json, "inverse"), "seed " + seed + " inverse", 10);
                    values += WalkCheck.Compare("seed " + seed + " inverse against RefAes", reference.Decrypt(Hex.Decode(forward.Output)), inverse);
                    Check.True(string.Equals(inverse.Output, Hex.Encode(block), StringComparison.OrdinalIgnoreCase), "seed " + seed + ": the inverse does not give the text back");
                    values += WalkCheck.CompareRows("seed " + seed + " key rows against RefAes", reference.KeyRows, ReadRows(r.Json));
                    Check.True(forward.Steps[0].State != firstState, "seeds 20261105 and 7 gave one first state");
                    firstState = forward.Steps[0].State;
                }
            }
            return values + " values on 2 seeds equal RefAes, and each output equals the BCL";
        }

        [Clause("A19.host.show-keys-off-closes-block-first")]
        public static string OffClosesBlock(Ctx c)
        {
            using (HostProc h = A17.Host(c, "walk-off"))
            {
                SessionRun run = HostSession.Run(h, 1, "glass", null);
                Check.True(run.SessionId != null, "no session: " + run.ErrorCode);
                string key = KeyOf(run);
                Reply on = Block(h, run);
                string state = ReadWalk(MiniJson.Obj(on.Json, "forward"), "ON", 10).Steps[0].State;
                SetShowKeys(h, false);
                Reply off = HostHttp.Get(h, BlockPath(run.SessionId));
                Check.True(off.Status == 409 && off.Code == "KEYS_HIDDEN", "OFF: GET block got " + off + ", expected 409 KEYS_HIDDEN");
                Reply unknown = HostHttp.Get(h, BlockPath("no-such-session"));
                Check.True(unknown.Status == 409 && unknown.Code == "KEYS_HIDDEN", "OFF: an unknown session got " + unknown + ". The toggle is checked before any read");
                foreach (Reply e in new Reply[] { off, unknown })
                {
                    string body = (e.Body ?? "").ToLowerInvariant();
                    Check.True(body.IndexOf(key, StringComparison.Ordinal) < 0, "OFF: the error body holds the key");
                    Check.True(body.IndexOf(state, StringComparison.Ordinal) < 0, "OFF: the error body holds a round state");
                }
                Check.True(HostHttp.Get(h, Tables).Ok, "OFF: the tables route closed");
                SetShowKeys(h, true);
                Check.True(Block(h, run).Ok, "ON again: GET block failed");
            }
            return "OFF gives 409 KEYS_HIDDEN before any session read, with no bytes in the error. The tables stay open, and ON opens the block again";
        }

        [Clause("A19.host.replies-carry-no-store")]
        public static string NoStore(Ctx c)
        {
            using (HostProc h = A17.Host(c, "walk-nostore"))
            {
                SessionRun run = HostSession.Run(h, 1, "glass", null);
                Check.True(run.SessionId != null, "no session: " + run.ErrorCode);
                foreach (string path in new string[] { Tables, BlockPath(run.SessionId) })
                {
                    Reply r = HostHttp.Get(h, path);
                    Check.True(r.Ok, path + " got " + r);
                    Check.True((r.CacheControl ?? "").IndexOf("no-store", StringComparison.OrdinalIgnoreCase) >= 0, path + ": Cache-Control is '" + r.CacheControl + "', expected no-store");
                }
            }
            return "the tables reply and the block reply each carry Cache-Control: no-store";
        }

        static void Error(Reply r, int status, string code, string what)
        {
            Check.True(r.Status == status && r.Code == code, what + " got " + r + ", expected " + status + " " + code);
            Check.True(!string.IsNullOrEmpty(MiniJson.Str(r.Json, "message")), what + ": no message");
            Check.True(r.Json != null && r.Json.ContainsKey("retryable"), what + ": no retryable");
            Check.True(!string.IsNullOrEmpty(MiniJson.Str(r.Json, "requestId")), what + ": no requestId");
        }

        [Clause("A19.host.errors-carry-a-code")]
        public static string Errors(Ctx c)
        {
            using (HostProc h = A17.Host(c, "walk-errors"))
            {
                SessionRun one = HostSession.Run(h, 1, "glass", null), two = HostSession.Run(h, 2, "glass", null);
                Check.True(one.SessionId != null && two.SessionId != null, "no session: " + one.ErrorCode + " " + two.ErrorCode);
                string baseOne = "/api/sessions/" + one.SessionId + "/walk/aes/block";
                Error(HostHttp.Get(h, BlockPath("no-such-session")), 404, "SESSION_NOT_FOUND", "an unknown session");
                Error(HostHttp.Get(h, BlockPath(two.SessionId)), 409, "WALK_NOT_BUILT", "lesson 2");
                Error(HostHttp.Get(h, baseOne + "?source=bad&keyBits=128"), 400, "WALK_BAD_ARGUMENT", "a bad source");
                Error(HostHttp.Get(h, baseOne + "?source=text&keyBits=7"), 400, "WALK_BAD_ARGUMENT", "a bad key size");
            }
            return "4 of 4 refusals carry the named code, message, retryable and requestId";
        }

        [Clause("A19.host.walk-adds-no-trace-event")]
        public static string AddsNoEvent(Ctx c)
        {
            using (HostProc h = A17.Host(c, "walk-noevent"))
            {
                SessionRun run = HostSession.Run(h, 1, "glass", null);
                Check.True(run.SessionId != null, "no session: " + run.ErrorCode);
                string eventsPath = "/api/sessions/" + run.SessionId + "/events";
                string before = HostHttp.Get(h, eventsPath).Body;
                string fileBefore = run.SessionFile != null && File.Exists(run.SessionFile) ? File.ReadAllText(run.SessionFile) : null;
                Reply r = Block(h, run);
                string state = ReadWalk(MiniJson.Obj(r.Json, "forward"), "forward", 10).Steps[1].State;
                string after = HostHttp.Get(h, eventsPath).Body;
                Check.True(before == after, "GET block changed GET events");
                Check.True(after.IndexOf(state, StringComparison.OrdinalIgnoreCase) < 0, "a round state reached GET events");
                Check.True(fileBefore != null, "the session file is missing at " + run.SessionFile);
                string fileAfter = File.ReadAllText(run.SessionFile);
                Check.True(fileBefore == fileAfter, "GET block changed the session file");
                Check.True(fileAfter.IndexOf(state, StringComparison.OrdinalIgnoreCase) < 0, "a round state reached the session file");
            }
            return "a walk changes neither GET events nor the session file, and no round state reaches either";
        }

        [Clause("A19.host.control-run-says-not-sent")]
        public static string ControlNotSent(Ctx c)
        {
            using (HostProc h = A17.Host(c, "walk-label"))
            {
                SessionRun run = HostSession.Run(h, 1, "glass", null);
                Check.True(run.SessionId != null, "no session: " + run.ErrorCode);
                Dictionary<string, object> wire = MiniJson.Obj(Block(h, run).Json, "wire");
                Check.True(wire != null, "the block reply has no wire object");
                Check.True(MiniJson.Str(wire, "status") == "notSent", "wire.status is " + MiniJson.Str(wire, "status") + ". A control run never sends this block in ECB");
                Check.True(MiniJson.Str(wire, "message") == "TextEcb", "wire.message is " + MiniJson.Str(wire, "message"));
            }
            return "a control run's block reply says notSent for TextEcb, so the panel can show its teaching-example label";
        }
    }
}
