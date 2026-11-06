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
                k.Divisor = (int)MiniJson.Num(m, "divisor", -2); k.Quotient = (int)MiniJson.Num(m, "quotient", -2); k.Remainder = (int)MiniJson.Num(m, "remainder", -2);
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

        static List<ColumnByte> ReadTerms(List<object> terms)
        {
            if (terms == null) return null;
            List<ColumnByte> all = new List<ColumnByte>();
            foreach (object o in terms)
            {
                Dictionary<string, object> b = MiniJson.AsObject(o);
                ColumnByte x = new ColumnByte();
                x.Result = MiniJson.Str(b, "result");
                foreach (object q in MiniJson.Arr(b, "parts") ?? new List<object>())
                {
                    Dictionary<string, object> m = MiniJson.AsObject(q);
                    TermPart p = new TermPart();
                    p.Factor = (int)MiniJson.Num(m, "factor", -1); p.Input = MiniJson.Str(m, "input"); p.Reduced = MiniJson.Bool(m, "reduced", false); p.Result = MiniJson.Str(m, "result");
                    foreach (object d in MiniJson.Arr(m, "doublings") ?? new List<object>())
                    {
                        Dictionary<string, object> o2 = MiniJson.AsObject(d);
                        Check.True(o2 != null, "a doubling is not an object with from, shifted, reduced and to");
                        Doubling y = new Doubling();
                        y.From = MiniJson.Str(o2, "from"); y.To = MiniJson.Str(o2, "to"); y.Reduced = MiniJson.Bool(o2, "reduced", false);
                        y.Shifted = Convert.ToInt32(MiniJson.Str(o2, "shifted") ?? "-1", 16);
                        p.Doublings.Add(y);
                    }
                    foreach (object q2 in MiniJson.Arr(m, "picks") ?? new List<object>()) p.Picks.Add((string)q2);
                    foreach (object q2 in MiniJson.Arr(m, "sums") ?? new List<object>()) p.Sums.Add((string)q2);
                    x.Parts.Add(p);
                }
                foreach (object q3 in MiniJson.Arr(b, "running") ?? new List<object>()) x.Running.Add((string)q3);
                all.Add(x);
            }
            return all;
        }

        [Clause("A19.host.tables-carry-maps-rcon-sizes")]
        public static string TablesCarryMaps(Ctx c)
        {
            using (HostProc h = A17.Host(c, "walk-tables2"))
            {
                foreach (bool on in new bool[] { true, false })
                {
                    SetShowKeys(h, on);
                    Reply r = HostHttp.Get(h, Tables);
                    string state = on ? "Show keys ON" : "Show keys OFF";
                    Check.True(r.Ok && r.Json != null, state + ": GET tables got " + r);
                    Map(r.Json, "shiftRows", RefField.ShiftMap(false), state);
                    Map(r.Json, "inverseShiftRows", RefField.ShiftMap(true), state);
                    Check.True(string.Equals(MiniJson.Str(r.Json, "rcon"), "01020408102040801b36", StringComparison.OrdinalIgnoreCase), state + ": rcon is " + MiniJson.Str(r.Json, "rcon"));
                    List<object> sizes = MiniJson.Arr(r.Json, "sizes");
                    Check.True(sizes != null && sizes.Count == 3, state + ": sizes should hold 3 rows");
                    double[,] want = { { 128, 4, 10, 11, 44, 10 }, { 192, 6, 12, 13, 52, 8 }, { 256, 8, 14, 15, 60, 7 } };
                    string[] names = new string[] { "keyBits", "keyWords", "rounds", "roundKeys", "words", "rconUsed" };
                    for (int n = 0; n < 3; n++)
                        for (int f = 0; f < 6; f++)
                            Check.True(MiniJson.Num(MiniJson.AsObject(sizes[n]), names[f], -1) == want[n, f], state + ": sizes[" + n + "]." + names[f] + " is " + MiniJson.Num(MiniJson.AsObject(sizes[n]), names[f], -1) + ", expected " + want[n, f]);
                }
            }
            return "both shift maps, the round constants and the size table are right and open, with Show keys ON and OFF";
        }

        static void Map(Dictionary<string, object> d, string name, int[] want, string state)
        {
            List<object> got = MiniJson.Arr(d, name);
            Check.True(got != null && got.Count == 16, state + ": " + name + " should hold 16 entries");
            for (int i = 0; i < 16; i++) Check.True(Convert.ToInt32(got[i]) == want[i], state + ": " + name + "[" + i + "] is " + got[i] + ", expected " + want[i]);
        }

        /// <summary>Design section 2.2b: the Host sends each doubling of the round constants. The values are the FIPS 197 row, and the rules are the field's, so no step's numbers come from the Host alone.</summary>
        [Clause("A19.host.rcon-steps")]
        public static string RconSteps(Ctx c)
        {
            byte[] rcon = Hex.Decode("01020408102040801b36");
            using (HostProc h = A17.Host(c, "walk-rcon"))
            {
                foreach (bool on in new bool[] { true, false })
                {
                    SetShowKeys(h, on);
                    string state = on ? "Show keys ON" : "Show keys OFF";
                    Reply r = HostHttp.Get(h, Tables);
                    Check.True(r.Ok && r.Json != null, state + ": GET tables got " + r);
                    List<object> steps = MiniJson.Arr(r.Json, "rconSteps");
                    Check.True(steps != null && steps.Count == 9, state + ": rconSteps should hold 9 steps, holds " + (steps == null ? 0 : steps.Count));
                    for (int i = 0; i < 9; i++)
                    {
                        Dictionary<string, object> s = MiniJson.AsObject(steps[i]);
                        string at = state + ", step " + i;
                        Check.True(s != null, at + ": not an object");
                        int from = Convert.ToInt32(MiniJson.Str(s, "from") ?? "-1", 16), to = Convert.ToInt32(MiniJson.Str(s, "to") ?? "-1", 16), shifted = Convert.ToInt32(MiniJson.Str(s, "shifted") ?? "-1", 16);
                        bool reduced = MiniJson.Bool(s, "reduced", false);
                        Check.True(from == rcon[i], at + ": from " + from.ToString("x2") + ", expected " + rcon[i].ToString("x2"));
                        Check.True(to == rcon[i + 1], at + ": to " + to.ToString("x2") + ", expected " + rcon[i + 1].ToString("x2"));
                        Check.True(shifted == from << 1, at + ": shifted " + shifted.ToString("x") + " is not " + from.ToString("x2") + " moved left by one bit");
                        Check.True(reduced == (shifted > 0xff), at + ": reduced " + reduced + " with shifted " + shifted.ToString("x"));
                        Check.True(to == (reduced ? shifted ^ 0x11b : shifted), at + ": to " + to.ToString("x2") + " does not follow from shifted " + shifted.ToString("x"));
                        Check.True(reduced == (from == 0x80), at + ": only 80 to 1b is reduced, and this step from " + from.ToString("x2") + " reads " + reduced);
                    }
                }
            }
            return "9 steps follow the round constants and the field's rules, and only 80 to 1b is reduced, with Show keys ON and OFF";
        }

        [Clause("A19.host.block-terms-real-run")]
        public static string BlockTerms(Ctx c)
        {
            int cells = 0;
            using (HostProc h = A17.Host(c, "walk-terms"))
            {
                foreach (int seed in new int[] { 20261105, 7 })
                {
                    SessionRun run = HostSession.RunSeeded(h, 1, "glass", seed);
                    Check.True(run.SessionId != null, "seed " + seed + ": no session: " + run.ErrorCode);
                    Reply r = Block(h, run);
                    // The terms must come from this run's key. Terms that only agree with their own reply would pass on a stored walk.
                    RefAes reference = new RefAes(Hex.Decode(KeyOf(run)));
                    byte[] block = Encoding.ASCII.GetBytes(TextBlock);
                    WalkRun forwardRun = reference.Encrypt(block);
                    foreach (string side in new string[] { "forward", "inverse" })
                    {
                        WalkRun want = side == "forward" ? forwardRun : reference.Decrypt(Hex.Decode(forwardRun.Output));
                        Dictionary<string, object> walk = MiniJson.Obj(r.Json, side);
                        Check.True(walk != null && MiniJson.Arr(walk, "steps") != null, side + ": no steps");
                        List<object> steps = MiniJson.Arr(walk, "steps");
                        Check.True(steps.Count == want.Steps.Count, "seed " + seed + " " + side + ": " + steps.Count + " steps, expected " + want.Steps.Count);
                        for (int i = 0; i < steps.Count; i++)
                        {
                            Dictionary<string, object> s = MiniJson.AsObject(steps[i]);
                            List<ColumnByte> terms = ReadTerms(MiniJson.Arr(s, "terms"));
                            string where = "seed " + seed + " " + side + " " + want.Steps[i];
                            if (want.Steps[i].Terms != null) cells += RefField.Compare(where, want.Steps[i].Terms, terms, want.Steps[i].State);
                            else Check.True(terms == null, where + ": carries terms");
                        }
                    }
                }
            }
            return cells + " terms on 2 seeds equal RefField and XOR to the state byte";
        }

        /// <summary>True when a field of this name holds data anywhere in the JSON value. A number is no data here: the open size table has a keyWords count, sizes[].keyWords, and the word rows are an array of the same name.</summary>
        static bool HasField(object value, string name)
        {
            Dictionary<string, object> d = value as Dictionary<string, object>;
            if (d != null)
            {
                foreach (KeyValuePair<string, object> kv in d) if ((kv.Key == name && !(kv.Value is double)) || HasField(kv.Value, name)) return true;
                return false;
            }
            List<object> list = value as List<object>;
            if (list != null) foreach (object o in list) if (HasField(o, name)) return true;
            return false;
        }

        [Clause("A19.host.off-holds-no-word-or-term")]
        public static string OffHoldsNoWord(Ctx c)
        {
            using (HostProc h = A17.Host(c, "walk-off2"))
            {
                SessionRun run = HostSession.Run(h, 1, "glass", null);
                Check.True(run.SessionId != null, "no session: " + run.ErrorCode);
                Reply on = Block(h, run);
                List<string> needles = new List<string>();
                needles.Add(KeyOf(run));
                foreach (KeyRow k in ReadRows(on.Json)) needles.Add(k.Word.ToLowerInvariant());
                foreach (object o in MiniJson.Arr(MiniJson.Obj(on.Json, "forward"), "steps"))
                {
                    Dictionary<string, object> s = MiniJson.AsObject(o);
                    needles.Add(MiniJson.Str(s, "state").ToLowerInvariant());
                }
                SetShowKeys(h, false);
                Reply block = HostHttp.Get(h, BlockPath(run.SessionId)), tables = HostHttp.Get(h, Tables);
                Check.True(block.Status == 409 && block.Code == "KEYS_HIDDEN", "OFF: GET block got " + block + ", expected 409 KEYS_HIDDEN");
                Check.True(tables.Ok, "OFF: GET tables got " + tables);
                // A term is one byte, so no byte search can find it. The field names of the word rows and the terms mark them instead, in either reply.
                foreach (string field in new string[] { "keyWords", "terms", "parts", "doublings", "picks", "sums", "running", "afterRcon" })
                {
                    Check.True(!HasField(block.Json, field), "OFF: the block error holds the field " + field);
                    Check.True(!HasField(tables.Json, field), "OFF: the tables reply holds the field " + field);
                }
                foreach (string needle in needles)
                {
                    Check.True((block.Body ?? "").ToLowerInvariant().IndexOf(needle, StringComparison.Ordinal) < 0, "OFF: the block error holds " + needle);
                    Check.True((tables.Body ?? "").ToLowerInvariant().IndexOf(needle, StringComparison.Ordinal) < 0, "OFF: the tables reply holds " + needle);
                }
                return needles.Count + " key, word and state values from the ON reply, and every word-row and term field, are absent from the OFF error and the OFF tables reply";
            }
        }

        /// <summary>Design 2.2: the label reads match on the L1-use-ecb fork. The fork's wire holds the block's forward output, so the claim can be checked against the bytes sent.</summary>
        [Clause("A19.host.ecb-fork-says-match")]
        public static string EcbForkMatches(Ctx c)
        {
            using (HostProc h = A17.Host(c, "walk-fork"))
            {
                SessionRun parent = HostSession.Run(h, 1, "glass", null);
                Check.True(parent.SessionId != null, "no session: " + parent.ErrorCode);
                SessionRun fork = HostSession.Fork(h, parent.SessionId, "L1-use-ecb");
                Check.True(fork.SessionId != null, "no fork: " + fork.ErrorCode);
                Reply r = Block(h, fork);
                Dictionary<string, object> wire = MiniJson.Obj(r.Json, "wire");
                Check.True(wire != null && MiniJson.Str(wire, "status") == "match", "wire.status on the L1-use-ecb fork is " + MiniJson.Str(wire, "status") + ", expected match");
                string output = (MiniJson.Str(MiniJson.Obj(r.Json, "forward"), "output") ?? "").ToLowerInvariant();
                string expected = new RefAes(Hex.Decode(KeyOf(fork))).Encrypt(Encoding.ASCII.GetBytes(TextBlock)).Output;
                Check.True(output == expected, "the fork's forward output is " + output + ", RefAes on the fork's key gives " + expected);
                bool sent = false;
                foreach (Dictionary<string, object> ev in fork.Events)
                    if (MiniJson.Str(ev, "type") == "wire.sent" && (MiniJson.Str(ev, "wire") ?? "").ToLowerInvariant().IndexOf(expected, StringComparison.Ordinal) >= 0) sent = true;
                Check.True(sent, "no wire.sent event of the fork holds the forward output " + expected);
            }
            return "the L1-use-ecb fork says match, and its wire holds the block's forward output";
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
