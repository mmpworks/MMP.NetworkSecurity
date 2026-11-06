using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// A17, slice V3: the Show keys toggle (modes-design.md section 6). The suite runs with it ON. These clauses turn it OFF on purpose, each in its own Host.
    /// The anchor is the bytes: the suite reads secrets while ON, flips the toggle, and looks for those same bytes. It computes fingerprints itself.
    /// Two exclusions, named by the design: the bearer token of lesson 10 (it travels in the clear on purpose) and lesson 11's lab-secret (it is stored in plain).
    /// A public key is no secret either, so a secret whose name holds "public" is left out of the text scan.
    /// </summary>
    public static class V3Clauses
    {
        static readonly int[] AllLabs = new int[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

        static bool Excluded(string name)
        {
            return name == "auth.token" || name == "lab-secret" || (name ?? "").IndexOf("public", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>
        /// The text with every "wire" and "plain" field taken out. Show keys OFF hides secrets[] and leaves wire and plain alone (design 6.2, limit 2): a value the lab
        /// sends in the clear (a challenge, a token, a request) is on the wire whatever the switch says. A rule, not a list of names: the byte scan looks everywhere else,
        /// so a secret in secrets[], in a message, in the file or in a key log still fails it.
        /// </summary>
        static string WithoutWire(string text)
        {
            string whole = (text ?? "").Trim();
            try { if (whole.StartsWith("[") || whole.StartsWith("{")) return MiniJson.Write(Strip(MiniJson.Parse(whole))); } catch (FormatException) { }
            StringBuilder sb = new StringBuilder();
            foreach (string line in (text ?? "").Split('\n'))
            {
                string t = line.Trim();
                if (t.StartsWith("{") || t.StartsWith("["))
                {
                    try { sb.Append(MiniJson.Write(Strip(MiniJson.Parse(t)))).Append('\n'); continue; } catch (FormatException) { }
                }
                sb.Append(line).Append('\n');
            }
            return sb.ToString();
        }

        static object Strip(object o)
        {
            Dictionary<string, object> d = o as Dictionary<string, object>;
            if (d != null)
            {
                Dictionary<string, object> kept = new Dictionary<string, object>();
                foreach (KeyValuePair<string, object> kv in d) if (kv.Key != "wire" && kv.Key != "plain") kept[kv.Key] = Strip(kv.Value);
                return kept;
            }
            List<object> l = o as List<object>;
            if (l == null) return o;
            List<object> items = new List<object>();
            foreach (object v in l) items.Add(Strip(v));
            return items;
        }

        static List<string> HexEntries(string ndjsonOrJson)
        {
            // Every "hex" value in secrets[] entries, found by parsing, never by pattern.
            List<string> found = new List<string>();
            string whole = ndjsonOrJson.Trim();
            if (whole.StartsWith("["))
            {
                // GET /api/sessions/{id}/events answers one JSON array.
                try { CollectHex(MiniJson.Parse(whole), found); return found; } catch (FormatException) { }
            }
            foreach (string line in ndjsonOrJson.Split('\n'))
            {
                string t = line.Trim();
                if (!t.StartsWith("{")) continue;
                try { CollectHex(MiniJson.Parse(t), found); } catch (FormatException) { continue; }
            }
            return found;
        }

        static void CollectHex(object o, List<string> found)
        {
            Dictionary<string, object> d = o as Dictionary<string, object>;
            if (d != null)
            {
                List<object> secrets = MiniJson.Arr(d, "secrets");
                if (secrets != null)
                    foreach (object s in secrets)
                    {
                        string hex = MiniJson.Str(MiniJson.AsObject(s), "hex");
                        if (!string.IsNullOrEmpty(hex)) found.Add(hex);
                    }
                foreach (object v in d.Values) CollectHex(v, found);
                return;
            }
            List<object> l = o as List<object>;
            if (l != null) foreach (object v in l) CollectHex(v, found);
        }

        static void RequireLessonBuilt(SessionRun run, int lesson)
        {
            if (run.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson " + lesson + " as not built yet");
        }

        // ---------------------------------------------------------------- default ON

        [Clause("A17.show-keys.default-on")]
        public static string DefaultOn(Ctx c)
        {
            using (HostProc h = HostProc.Start(c, "a17-sk-default", null))
            {
                A17.Security(h);                                                       // a Host with no security routes reads NOT RUN, before any field is judged
                Reply health = HostHttp.Get(h, "/api/health");
                Check.True(health.Ok && health.Json != null, "GET /api/health got " + health);
                Check.True(health.Json.ContainsKey("showKeys"), "/api/health reports no showKeys. The suite fails a run early on it, so the field must be there");
                Check.True(MiniJson.Bool(health.Json, "showKeys", false), "a fresh Host (no modes.json) reports showKeys false in /api/health. The default is ON");
                Check.True(A17.ShowKeys(h), "GET /api/security/show-keys says OFF on a fresh Host");
                Check.True(MiniJson.Bool(A17.Security(h), "showKeys", false), "GET /api/security says showKeys false on a fresh Host");

                SessionRun run = HostSession.Run(h, 10, "glass", null);
                RequireLessonBuilt(run, 10);
                Check.True(run.Error == null && run.Finished != null, "lesson 10 did not finish: " + (run.Frames.Count == 0 ? "no frames" : run.Frames[run.Frames.Count - 1]));
                Check.True(run.ShowKeysReported && run.ShowKeys, "session.started does not carry showKeys true");
                int entries, withHex;
                HostSession.CountSecrets(run, out entries, out withHex);
                Check.True(withHex > 0, "with Show keys ON, no secrets[] entry of lesson 10 carries hex (" + entries + " entries)");
                Reply ev = HostHttp.Get(h, "/api/sessions/" + run.SessionId + "/events?after=0");
                Check.True(HexEntries(ev.Body ?? "").Count > 0, "/events of an ON session holds no hex");
                Check.True(!string.IsNullOrEmpty(run.SessionFile) && File.Exists(run.SessionFile), "session.started.sessionFile is not a file");
                Check.True(HexEntries(File.ReadAllText(run.SessionFile)).Count > 0, "the session file of an ON session holds no hex");
                Reply keylog = HostHttp.Get(h, "/api/sessions/" + run.SessionId + "/keylog");
                Check.True(keylog.Code != "KEYS_HIDDEN", "the key log was refused with KEYS_HIDDEN while Show keys is ON");

                // Control: the same checks must read differently when the toggle is OFF. Without this a Host that ignores the toggle passes.
                A17.SetShowKeys(h, false);
                Check.True(HexEntries(HostHttp.Get(h, "/api/sessions/" + run.SessionId + "/events?after=0").Body ?? "").Count == 0, "after the toggle went OFF, /events of the open session still holds hex");
                return "fresh Host: showKeys true in /health, /security and show-keys; lesson 10 shows " + withHex + " secrets with hex in frames, /events and the file; the OFF control reads differently";
            }
        }

        // ---------------------------------------------------------------- OFF holds no secret

        [Clause("A17.show-keys.off-holds-no-secret")]
        public static string OffHoldsNoSecret(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-sk-off"))
            {
                List<string> skipped = new List<string>(), textScanned = new List<string>(), structuralOnly = new List<string>();
                int covered = 0, secretsSeen = 0;
                foreach (int lesson in AllLabs)
                {
                    A17.SetShowKeys(h, true);
                    SessionRun on = HostSession.Run(h, lesson, "glass", null);
                    if (on.ErrorCode == "LESSON_NOT_BUILT") { skipped.Add(lesson.ToString()); continue; }
                    Check.True(on.Error == null && on.Finished != null, "lesson " + lesson + " (ON) did not finish: " + (on.Frames.Count == 0 ? "no frames" : on.Frames[on.Frames.Count - 1]));
                    List<A17.SecretRef> onSecrets = A17.Secrets(on);
                    covered++;
                    secretsSeen += onSecrets.Count;

                    // 1. The same session, flipped OFF: the bytes leave /events at once.
                    A17.SetShowKeys(h, false);
                    string flipped = HostHttp.Get(h, "/api/sessions/" + on.SessionId + "/events?after=0").Body ?? "";
                    Check.True(HexEntries(flipped).Count == 0, "lesson " + lesson + ": after the flip to OFF, /events of the open session still holds hex");
                    string flippedScan = WithoutWire(flipped);
                    foreach (A17.SecretRef s in onSecrets)
                        if (!Excluded(s.Name) && s.Hex.Length >= 8)
                            Check.True(flippedScan.IndexOf(s.Hex, StringComparison.OrdinalIgnoreCase) < 0, "lesson " + lesson + ": the secret " + s.Name + " (" + s.Hex.Substring(0, 8) + "..) is still in /events after the flip to OFF");

                    // 2. A new session started OFF: frames, /events and the file.
                    SessionRun off = HostSession.Run(h, lesson, "glass", null);
                    Check.True(off.Error == null && off.Finished != null, "lesson " + lesson + " (OFF) did not finish: " + (off.Frames.Count == 0 ? "no frames" : off.Frames[off.Frames.Count - 1]));
                    Check.True(off.ShowKeysReported && !off.ShowKeys, "lesson " + lesson + ": session.started does not say showKeys false");
                    string offAll = A17.Everything(h, off);
                    Check.True(HexEntries(offAll).Count == 0, "lesson " + lesson + ": an OFF session holds hex in secrets[] (frames, /events or the file)");
                    foreach (A17.SecretRef s in A17.Secrets(off))
                    {
                        Check.True(!string.IsNullOrEmpty(s.Fingerprint), "lesson " + lesson + ": OFF secret " + s.Name + " has no fingerprint");
                        Check.True(!string.IsNullOrEmpty(s.Hidden), "lesson " + lesson + ": OFF secret " + s.Name + " has no hidden marker");
                    }
                    // Same seed gives the same bytes only when every fingerprint matches the ON run. Then the ON bytes are a fair thing to look for.
                    bool sameBytes = onSecrets.Count > 0 && onSecrets.Count == A17.Secrets(off).Count;
                    if (sameBytes)
                    {
                        List<A17.SecretRef> offSecrets = A17.Secrets(off);
                        for (int i = 0; i < onSecrets.Count; i++)
                            if (onSecrets[i].Hex.Length > 0 && onSecrets[i].Hex.Length % 2 == 0 && A17.Fingerprint(onSecrets[i].Hex) != offSecrets[i].Fingerprint) sameBytes = false;
                    }
                    if (sameBytes)
                    {
                        string offScan = WithoutWire(offAll);
                        foreach (A17.SecretRef s in onSecrets)
                            if (!Excluded(s.Name) && s.Hex.Length >= 8)
                                Check.True(offScan.IndexOf(s.Hex, StringComparison.OrdinalIgnoreCase) < 0, "lesson " + lesson + ": the ON secret " + s.Name + " (" + s.Hex.Substring(0, 8) + "..) appears in an OFF session");
                        textScanned.Add(lesson.ToString());
                    }
                    else structuralOnly.Add(lesson.ToString());

                    // 3. The key log is refused while OFF.
                    Reply keylog = HostHttp.Get(h, "/api/sessions/" + off.SessionId + "/keylog");
                    Check.True(!keylog.Ok && keylog.Code == "KEYS_HIDDEN", "lesson " + lesson + ": the key log of an OFF session got " + keylog + "; expected KEYS_HIDDEN");
                }
                if (covered == 0) throw new NotRunException("LESSON_NOT_BUILT", "the Host reports every lab as not built yet");
                if (secretsSeen == 0) throw new FailException("no lab produced a secrets[] entry with Show keys ON, so the OFF scan has nothing to look for");
                return covered + " labs, ON then OFF: no hex in any OFF frame, /events or file; the ON bytes left /events at once after the flip; key log refused with KEYS_HIDDEN. "
                    + "Text scan for ON bytes on labs " + (textScanned.Count == 0 ? "none" : string.Join(",", textScanned.ToArray()))
                    + "; structure only on labs " + (structuralOnly.Count == 0 ? "none" : string.Join(",", structuralOnly.ToArray()))
                    + (skipped.Count > 0 ? "; not built: " + string.Join(",", skipped.ToArray()) : "")
                    + ". Left out of the byte scan: the wire and plain fields of every event (Show keys OFF leaves them alone, design 6.2 limit 2), lab-secret (stored in plain), public keys";
            }
        }

        // ---------------------------------------------------------------- an own key that can show, shows

        [Clause("A17.show-keys.mine-shows-exportable")]
        public static string MineShowsExportable(Ctx c)
        {
            string openssl = Referees.OpenSsl(c);
            using (HostProc h = A17.Host(c, "a17-sk-mine"))
            {
                A17.RunFlow(h, "my-login");
                Reply key = A17.Key(h, "token.issuer");
                Check.True(key.Ok && key.Json != null, "GET key of token.issuer got " + key);
                string hex = MiniJson.Str(key.Json, "hex");
                Check.True(!string.IsNullOrEmpty(hex), "an exportable own key shows no hex with Show keys ON: " + key);
                Check.Equal("length of the token.issuer seed", 64, hex.Length);
                Check.True(!string.IsNullOrEmpty(MiniJson.Str(key.Json, "fingerprint")), "the key reply carries no fingerprint");

                // The hex is the real key: OpenSSL derives its public half, and the lab used that public key.
                string dir = A17.TempDir(c, "mine");
                string pem = Path.Combine(dir, "shown.pem"), pubDer = Path.Combine(dir, "shown.pub.der"), o;
                byte[] p8 = Hex.Concat(Hex.Decode("302e020100300506032b657004220420"), Hex.Decode(hex));
                string label = "PRIV" + "ATE KEY";
                File.WriteAllText(pem, "-----BEGIN " + label + "-----\n" + Convert.ToBase64String(p8) + "\n-----END " + label + "-----\n");
                Check.True(Proc.Run(openssl, "pkey -in \"" + pem + "\" -pubout -outform DER -out \"" + pubDer + "\"", dir, 30000, out o) == 0, "OpenSSL cannot read the shown key as an Ed25519 key: " + o);
                string derivedPub = Hex.Encode(Hex.Slice(File.ReadAllBytes(pubDer), 12, 32));
                Check.Equal("public key reported by the Host", derivedPub, (MiniJson.Str(key.Json, "publicHex") ?? "").ToLowerInvariant());

                SessionRun run = HostSession.Run(h, 10, "glass", null);
                RequireLessonBuilt(run, 10);
                Check.True(run.Error == null && run.Finished != null, "lesson 10 on the learner's key did not finish");
                string tracePub = null;
                foreach (A17.SecretRef s in A17.Secrets(run)) if (s.Name == "auth.issuer-public") tracePub = s.Hex.ToLowerInvariant();
                Check.Equal("issuer public key in the trace", derivedPub, tracePub);

                // The key.in-use event: written by the Host on its own stream, in both modes, for each type the lab reads.
                bool sawEvent = false;
                foreach (Dictionary<string, object> ev in run.Events)
                {
                    if (MiniJson.Str(ev, "type") != "key.in-use" || MiniJson.Str(ev, "typeId") != "token.issuer") continue;
                    sawEvent = true;
                    string stream = MiniJson.Str(ev, "streamId") ?? "";
                    Check.True(stream.EndsWith("/keys") && stream.StartsWith(run.SessionId), "key.in-use is on stream '" + stream + "'; expected '" + run.SessionId + "/keys'");
                    Check.True(!string.IsNullOrEmpty(MiniJson.Str(ev, "provider")), "key.in-use carries no provider");
                    Check.True(MiniJson.Num(ev, "version", 0) >= 1, "key.in-use carries no version");
                    bool holdsKey = false;
                    foreach (object so in MiniJson.Arr(ev, "secrets") ?? new List<object>())
                        if ((MiniJson.Str(MiniJson.AsObject(so), "hex") ?? "").Equals(hex, StringComparison.OrdinalIgnoreCase)) holdsKey = true;
                    Check.True(holdsKey, "key.in-use for token.issuer does not hold the key bytes the key route shows");
                }
                Check.True(sawEvent, "the trace holds no key.in-use event for token.issuer, which lesson 10 reads");
                return "an exportable own key shows its 32 bytes ON; OpenSSL derives the public key the lab used from them; key.in-use on " + run.SessionId + "/keys holds the same bytes";
            }
        }

        // ---------------------------------------------------------------- a non-exportable key shows a fingerprint, and its bytes are nowhere

        [Clause("A17.show-keys.non-exportable-hidden-when-on")]
        public static string NonExportableHiddenWhenOn(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-sk-nx"))
            {
                // Show keys is ON. Flows make exportable keys, and a lab shows them. Only the exercise's keys are non-exportable (design 4.3 and 6.3).
                A17.RunFlow(h, "my-login");
                Reply flowKey = A17.Key(h, "token.issuer");
                string exportableHex = MiniJson.Str(flowKey.Json, "hex");
                Check.True(flowKey.Ok && !string.IsNullOrEmpty(exportableHex), "control: the exportable flow key shows no bytes with Show keys ON: " + flowKey);

                // Everything the Host says about the vault and the exercise, collected as text.
                StringBuilder said = new StringBuilder();
                Reply keys = HostHttp.Get(h, "/api/security/vault/keys");
                Check.True(keys.Ok, "GET vault/keys got " + keys);
                said.Append(keys.Body).Append('\n');
                foreach (string name in new string[] { "exercise/signing", "exercise/derive" })
                {
                    Dictionary<string, object> k = null;
                    foreach (object o in MiniJson.Arr(keys.Json, "keys") ?? new List<object>()) if (MiniJson.Str(MiniJson.AsObject(o), "name") == name) k = MiniJson.AsObject(o);
                    Check.True(k != null, "GET vault/keys lists no key named " + name);
                    Check.Equal("hidden marker of " + name, "non-exportable", MiniJson.Str(k, "hidden"));
                    Check.True(!string.IsNullOrEmpty(MiniJson.Str(k, "fingerprint")), name + " shows no fingerprint");
                    Check.True(string.IsNullOrEmpty(MiniJson.Str(k, "hex")), name + " shows hex with Show keys ON");
                }
                foreach (string route in new string[] { "sign", "derive", "export", "audit-check" })
                {
                    Reply r = HostHttp.Post(h, "/api/security/vault/exercise/" + route, route == "sign" ? A17.Obj("text", "nx") : route == "derive" ? A17.Obj("label", "nx") : "{}");
                    said.Append(r.Body).Append('\n');
                }
                said.Append(HostHttp.Get(h, "/api/security/vault/audit?after=0").Body).Append('\n');
                said.Append(HostHttp.Get(h, "/api/security").Body).Append('\n');
                SessionRun lab = HostSession.Run(h, 10, "glass", null);
                if (lab.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson 10 as not built yet");
                said.Append(A17.Everything(h, lab));
                string all = said.ToString();
                Check.True(all.IndexOf(exportableHex, StringComparison.OrdinalIgnoreCase) >= 0, "control: the exportable key's bytes appear nowhere in what the Host said, so the scan cannot see a leak");

                // The bytes of the non-exportable keys, taken out of the vault file with the master key, by the suite.
                List<string> secrets = A17.UnwrapVaultKeys(c, h, "exercise/");
                foreach (string hex in secrets)
                    Check.True(all.IndexOf(hex, StringComparison.OrdinalIgnoreCase) < 0, "the bytes of a non-exportable key (" + hex.Substring(0, 8) + "..) appear in what the Host said, with Show keys ON");
                return "with Show keys ON the flow key shows its bytes, and both exercise keys show a fingerprint and non-exportable; the " + secrets.Count + " non-exportable key byte strings the suite unwrapped from the vault file with the master key appear in no route, no audit row and no lab frame or file";
            }
        }

        // ---------------------------------------------------------------- fingerprints, computed by the suite

        [Clause("A17.show-keys.fingerprint-compare")]
        public static string FingerprintCompare(Ctx c)
        {
            A17.TestKey device = A17.MakeEd25519(c, "fp-device"), issuer = A17.MakeEd25519(c, "fp-issuer");
            using (HostProc h = A17.Host(c, "a17-sk-fp"))
            {
                A17.Flow f = A17.Flow.Start(h, "my-login");
                f.UseFiles(new Dictionary<string, string> { { "token.issuer", issuer.Pem }, { "device.enrolment", device.Pem } }, null);
                int checkedPairs = 0, equalPairs = 0, covered = 0;
                bool sawDeviceByFile = false;
                foreach (int lesson in AllLabs)
                {
                    A17.SetShowKeys(h, true);
                    SessionRun on = HostSession.Run(h, lesson, "glass", null);
                    if (on.ErrorCode == "LESSON_NOT_BUILT") continue;
                    Check.True(on.Error == null && on.Finished != null, "lesson " + lesson + " did not finish");
                    List<A17.SecretRef> onS = A17.Secrets(on);
                    A17.SetShowKeys(h, false);
                    // The same session, read again with the toggle OFF. The fingerprint must be what the suite computes from the ON bytes.
                    Reply ev = HostHttp.Get(h, "/api/sessions/" + on.SessionId + "/events?after=0");
                    SessionRun view = new SessionRun();
                    Check.True(ev.Array != null, "GET /events answered something that is no JSON array: " + ev);
                    foreach (object o in ev.Array) view.Events.Add(MiniJson.AsObject(o));
                    List<A17.SecretRef> offS = A17.Secrets(view);
                    Check.Equal("secrets of lesson " + lesson + " after the flip", onS.Count, offS.Count);
                    covered++;
                    for (int i = 0; i < onS.Count; i++)
                    {
                        if (onS[i].Hex.Length == 0) continue;
                        string expected = A17.Fingerprint(onS[i].Hex);
                        Check.Equal("fingerprint of " + onS[i].Name + " in lesson " + lesson, expected, offS[i].Fingerprint);
                        checkedPairs++;
                        if (onS[i].Hex.Equals(device.SeedHex, StringComparison.OrdinalIgnoreCase)) { sawDeviceByFile = true; Check.Equal("fingerprint of the imported file's bytes", A17.Fingerprint(device.SeedHex), offS[i].Fingerprint); }
                        for (int j = i + 1; j < onS.Count; j++)
                        {
                            if (onS[j].Hex.Length == 0) continue;
                            bool sameBytes = onS[i].Hex.Equals(onS[j].Hex, StringComparison.OrdinalIgnoreCase), sameFp = offS[i].Fingerprint == offS[j].Fingerprint;
                            Check.True(sameBytes == sameFp, "lesson " + lesson + ": " + onS[i].Name + " and " + onS[j].Name + (sameBytes ? " are one key but show different fingerprints" : " are different keys but show one fingerprint"));
                            if (sameBytes) equalPairs++;
                        }
                    }
                }
                if (covered == 0) throw new NotRunException("LESSON_NOT_BUILT", "the Host reports every lab as not built yet");
                Check.True(checkedPairs > 0, "no secret carried hex while ON, so no fingerprint could be compared");
                Check.True(sawDeviceByFile, "the imported device key (a file the suite made) never appeared in a trace, so the fingerprint was not anchored to a file");
                return checkedPairs + " fingerprints equal the suite's own SHA-256 of the ON bytes; " + equalPairs + " pairs of one key agree and all other pairs differ; the imported file's bytes give the fingerprint the suite computed";
            }
        }
    }
}
