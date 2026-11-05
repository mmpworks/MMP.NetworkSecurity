using System;
using System.Collections.Generic;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// A17, slice V8: each lesson runs on the learner's own test keys. The anchor is the lesson itself on built-in keys: the same Host, the same seed,
    /// the same fixed names. A learner's key must change which bytes are used and nothing else, so the run on own keys must have the same events,
    /// the same checks with the same results, the same byte counts, and the same ending. It must also hold the learner's bytes.
    /// (modes-design.md section 3.3: "its layout matches the built-in one in every byte count".)
    /// </summary>
    public static class MyKeysClauses
    {
        /// <summary>LabCatalog.Needs, the table of modes-design.md section 1.7. Lesson 9 reads one SSH host key; the flow makes both.</summary>
        static string[] Needs(int lesson)
        {
            switch (lesson)
            {
                case 1: return new string[] { "lab.aes-key" };
                case 2: return new string[] { "lab.seal-key" };
                case 4: case 5: return new string[] { "pki.root-ca", "tls13.server", "tls.trust" };
                case 6: return new string[] { "dukpt.bdk", "dukpt.pad" };
                case 7: return new string[] { "pki.root-ca", "tls11.server", "tls13.server", "tls.trust" };
                case 8: return new string[] { "ssh.host-ed25519", "ssh.host-rsa", "ssh.known-hosts", "ssh.client" };
                case 9: return new string[] { "ssh.known-hosts", "ssh.client", "pki.root-ca", "tls13.server", "tls.trust", "dukpt.bdk", "dukpt.pad" };
                case 10: return new string[] { "pki.root-ca", "tls13.server", "tls13.client", "tls.trust", "token.issuer", "device.enrolment" };
            }
            throw new FailException("the suite has no key list for lesson " + lesson);
        }

        static string[] FlowsFor(int lesson)
        {
            switch (lesson)
            {
                case 1: case 2: return new string[] { "my-lesson-keys" };
                case 4: case 5: case 7: return new string[] { "my-certificates" };
                case 6: return new string[] { "my-payment" };
                case 8: return new string[] { "my-ssh" };
                case 9: return new string[] { "my-ssh", "my-certificates", "my-payment" };
                case 10: return new string[] { "my-certificates", "my-login" };
            }
            throw new FailException("the suite has no flows for lesson " + lesson);
        }

        static int Len(Dictionary<string, object> ev, string field) { return (MiniJson.Str(ev, field) ?? "").Length; }

        /// <summary>One line per event, key-dependent bytes left out: what happened, who did it, which check ran and how it ended, and how many bytes moved.</summary>
        static List<string> Shape(SessionRun run)
        {
            List<Dictionary<string, object>> evs = new List<Dictionary<string, object>>();
            foreach (Dictionary<string, object> ev in run.Events) if (MiniJson.Str(ev, "type") != "key.in-use") evs.Add(ev);
            evs.Sort(delegate (Dictionary<string, object> a, Dictionary<string, object> b)
            {
                int s = string.CompareOrdinal(Tail(MiniJson.Str(a, "streamId")), Tail(MiniJson.Str(b, "streamId")));
                return s != 0 ? s : MiniJson.Num(a, "streamSeq", 0).CompareTo(MiniJson.Num(b, "streamSeq", 0));
            });
            // TCP may deliver the same bytes as one read or as two (1232 bytes, or 1214 then 18), so the wire.* events that follow each other in one stream
            // with the same type and parties are one entry whose byte counts add up. What moved is compared, not how the network cut it.
            List<string> heads = new List<string>();
            List<string> streams = new List<string>();
            List<int> wires = new List<int>();
            List<int> plains = new List<int>();
            foreach (Dictionary<string, object> ev in evs)
            {
                Dictionary<string, object> chk = MiniJson.Obj(ev, "check");
                string type = MiniJson.Str(ev, "type") ?? "";
                string head = string.Join("|", new string[] {
                    type, MiniJson.Str(ev, "actor"), MiniJson.Str(ev, "from"), MiniJson.Str(ev, "to"), MiniJson.Str(ev, "step"),
                    MiniJson.Str(chk, "name"), MiniJson.Str(chk, "result"), MiniJson.Str(chk, "code") });
                string stream = Tail(MiniJson.Str(ev, "streamId"));
                int last = heads.Count - 1;
                if (last >= 0 && type.StartsWith("wire.", StringComparison.Ordinal) && heads[last] == head && streams[last] == stream)
                {
                    wires[last] += Len(ev, "wire"); plains[last] += Len(ev, "plain");
                    continue;
                }
                heads.Add(head); streams.Add(stream); wires.Add(Len(ev, "wire")); plains.Add(Len(ev, "plain"));
            }
            List<string> shape = new List<string>();
            for (int i = 0; i < heads.Count; i++) shape.Add(heads[i] + "|wire=" + wires[i] + "|plain=" + plains[i]);
            return shape;
        }

        /// <summary>The event lines that one run has more of than the other (a multiset difference), so a count mismatch names the events and not only the totals.</summary>
        static string Unmatched(List<string> builtIn, List<string> own)
        {
            List<string> onlyOwn = new List<string>(own);
            List<string> onlyBuiltIn = new List<string>();
            foreach (string line in builtIn) if (!onlyOwn.Remove(line)) onlyBuiltIn.Add(line);
            StringBuilder sb = new StringBuilder();
            foreach (string line in onlyBuiltIn) sb.Append("  only on built-in keys: ").Append(line).Append('\n');
            foreach (string line in onlyOwn) sb.Append("  only on own keys: ").Append(line).Append('\n');
            return sb.ToString().TrimEnd();
        }

        /// <summary>A built-in key's bytes as the suite can name them: a lowercase hex needle and a label for the failure text.</summary>
        sealed class Needle { public string TypeId, Kind, Hex; }

        const int MinNeedleHexChars = 32;       // 16 bytes: shorter values could match by chance

        /// <summary>
        /// The bytes of the built-in keys the lesson reads, read from the key route before any flow runs. Each secret is one needle. The public half is a needle too,
        /// because a Certificate message carries the public key and never the secret: an Ed25519 seed (32 bytes) gives its public key, and a longer DER key
        /// gives a 32-byte stretch of its public modulus. A key that openssl will not read adds only its secret.
        /// </summary>
        static List<Needle> BuiltInNeedles(Ctx c, HostProc h, int lesson, SessionRun baseline)
        {
            List<Needle> needles = new List<Needle>();
            List<string> refused = new List<string>();
            foreach (string typeId in Needs(lesson))
            {
                Reply key = A17.Key(h, typeId);
                if (!key.Ok || key.Json == null) { refused.Add(typeId + " " + key); continue; }
                string body = key.Body ?? "";
                refused.Add(typeId + " answered " + (body.Length > 160 ? body.Substring(0, 160) : body));
                string secret = (MiniJson.Str(key.Json, "hex") ?? "").ToLowerInvariant();
                string pub = (MiniJson.Str(key.Json, "publicHex") ?? "").ToLowerInvariant();
                if (secret.Length >= MinNeedleHexChars) needles.Add(new Needle { TypeId = typeId, Kind = "secret", Hex = secret });
                if (pub.Length >= MinNeedleHexChars) needles.Add(new Needle { TypeId = typeId, Kind = "public", Hex = pub });
                string derived = secret.Length >= MinNeedleHexChars ? PublicStretch(c, secret, typeId) : null;
                if (derived != null && derived != pub) needles.Add(new Needle { TypeId = typeId, Kind = "public", Hex = derived });
            }
            // The built-in run names its own secrets in key.in-use (provider builtin), which reaches the types whose key route shows no bytes.
            foreach (Dictionary<string, object> ev in baseline.Events)
            {
                if (MiniJson.Str(ev, "type") != "key.in-use") continue;
                foreach (object so in MiniJson.Arr(ev, "secrets") ?? new List<object>())
                {
                    string hex = (MiniJson.Str(MiniJson.AsObject(so), "hex") ?? "").ToLowerInvariant();
                    if (hex.Length >= MinNeedleHexChars) needles.Add(new Needle { TypeId = MiniJson.Str(ev, "typeId") ?? "?", Kind = "secret", Hex = hex });
                }
            }
            if (needles.Count == 0)
                throw new NotRunException("PRODUCT_MISSING", "no built-in key bytes are in reach for lesson " + lesson + " (the key route shows none, and the built-in run has no key.in-use secret), so the own-key run has nothing to be scanned for: " + string.Join("; ", refused.ToArray()));
            return needles;
        }

        static string PublicStretch(Ctx c, string secretHex, string typeId)
        {
            try
            {
                byte[] secret = Hex.Decode(secretHex);
                byte[] der = secret.Length == 32
                    ? Hex.Concat(Hex.Decode("302e020100300506032b657004220420"), secret)       // PKCS#8 wrapper of an Ed25519 seed
                    : secret;
                string dir = A17.TempDir(c, "builtin-" + typeId.Replace('.', '-'));
                string o, priv = System.IO.Path.Combine(dir, "k.der"), pub = System.IO.Path.Combine(dir, "k.pub.der");
                System.IO.File.WriteAllBytes(priv, der);
                if (Proc.Run(Referees.OpenSsl(c), "pkey -inform DER -in \"" + priv + "\" -pubout -outform DER -out \"" + pub + "\"", dir, 30000, out o) != 0) return null;
                byte[] spki = System.IO.File.ReadAllBytes(pub);
                if (spki.Length == 44) return Hex.Encode(Hex.Slice(spki, 12, 32));                                                  // Ed25519: the 32 public bytes
                return spki.Length >= 64 ? Hex.Encode(Hex.Slice(spki, spki.Length - 5 - 32, 32)) : null;                           // RSA: 32 bytes inside the modulus
            }
            catch (Exception) { return null; }
        }

        static Needle FirstSeen(string haystackLower, List<Needle> needles)
        {
            foreach (Needle n in needles) if (haystackLower.IndexOf(n.Hex, StringComparison.Ordinal) >= 0) return n;
            return null;
        }

        static string Tail(string streamId) { int i = (streamId ?? "").IndexOf('/'); return i < 0 ? streamId : streamId.Substring(i + 1); }

        static string Ending(SessionRun run)
        {
            return MiniJson.Str(run.Finished, "outcome") + "|" + MiniJson.Str(run.Finished, "code") + "|" + MiniJson.Str(run.Finished, "check");
        }

        static string Run(Ctx c, int lesson)
        {
            using (HostProc h = A17.Host(c, "a17-lesson-" + lesson))
            {
                // The lesson on built-in keys: the anchor.
                SessionRun baseline = HostSession.Run(h, lesson, "glass", null);
                if (baseline.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson " + lesson + " as not built yet");
                Check.True(baseline.Error == null && baseline.Finished != null, "lesson " + lesson + " on built-in keys did not finish: " + (baseline.Frames.Count == 0 ? "no frames" : baseline.Frames[baseline.Frames.Count - 1]));
                List<string> shape0 = Shape(baseline);
                Check.True(shape0.Count > 0, "lesson " + lesson + " on built-in keys sent no events, so there is nothing to compare");

                // The scan's control: the built-in run must show at least one built-in key byte string (a secret in key.in-use, or a public key on the wire),
                // or a scan of the own-key run could not see a leak and its silence would prove nothing.
                List<Needle> builtIn = BuiltInNeedles(c, h, lesson, baseline);
                Check.True(FirstSeen(A17.Everything(h, baseline).ToLowerInvariant(), builtIn) != null,
                    "lesson " + lesson + " on built-in keys shows none of the " + builtIn.Count + " built-in key byte strings, so a scan of the own-key run could not see a leak");

                foreach (string flow in FlowsFor(lesson)) A17.RunFlow(h, flow);
                SessionRun mine = HostSession.Run(h, lesson, "glass", null);
                Check.True(mine.Error == null && mine.Finished != null, "lesson " + lesson + " on own keys did not finish: " + (mine.Frames.Count == 0 ? "no frames" : mine.Frames[mine.Frames.Count - 1]));
                // No built-in key may appear anywhere in the run on own keys. A lab that keeps a built-in key for one half of its work (a second context built
                // without the credentials) leaves the same shape of events, so only the bytes give it away.
                Needle leak = FirstSeen(A17.Everything(h, mine).ToLowerInvariant(), builtIn);
                Check.True(leak == null, leak == null ? "" : "lesson " + lesson + " on own keys holds the built-in " + leak.Kind + " bytes of " + leak.TypeId + ", so part of the lab ran on a built-in key");
                Check.Equal("ending of lesson " + lesson, Ending(baseline), Ending(mine));
                List<string> shape1 = Shape(mine);
                if (shape0.Count != shape1.Count)
                    throw new FailException("events of lesson " + lesson + " on own keys against built-in keys: expected " + shape0.Count + " got " + shape1.Count + ".\n" + Unmatched(shape0, shape1));
                for (int i = 0; i < shape0.Count; i++)
                    Check.True(shape0[i] == shape1[i], "lesson " + lesson + ", event " + (i + 1) + " differs on own keys.\n  built-in: " + shape0[i] + "\n  own keys: " + shape1[i]);

                // The run holds the learner's bytes: key.in-use for each type the lab reads names a provider other than built-in,
                // and its bytes are the ones the key route shows for that type.
                int checkedKeys = 0;
                foreach (string typeId in Needs(lesson))
                {
                    Dictionary<string, object> inUse = null;
                    foreach (Dictionary<string, object> ev in mine.Events)
                        if (MiniJson.Str(ev, "type") == "key.in-use" && MiniJson.Str(ev, "typeId") == typeId) inUse = ev;
                    if (inUse == null && typeId == "tls.trust") continue;                 // a trust list holds certificates, not a private key
                    Check.True(inUse != null, "lesson " + lesson + " on own keys has no key.in-use event for " + typeId);
                    Check.True(MiniJson.Str(inUse, "provider") != "builtin" && !string.IsNullOrEmpty(MiniJson.Str(inUse, "provider")), "key.in-use for " + typeId + " names provider '" + MiniJson.Str(inUse, "provider") + "' after the flow made it");
                    Reply key = A17.Key(h, typeId);
                    if (!key.Ok) continue;                                              // a type that shows no private bytes has no hex to compare
                    string shown = MiniJson.Str(key.Json, "hex");
                    if (string.IsNullOrEmpty(shown)) continue;
                    bool held = false;
                    foreach (object so in MiniJson.Arr(inUse, "secrets") ?? new List<object>())
                        if ((MiniJson.Str(MiniJson.AsObject(so), "hex") ?? "").Equals(shown, StringComparison.OrdinalIgnoreCase)) held = true;
                    Check.True(held, "key.in-use for " + typeId + " does not hold the bytes the key route shows for the learner's key");
                    checkedKeys++;
                }
                Check.True(checkedKeys > 0, "no key of lesson " + lesson + " could be compared with the key route");
                return "lesson " + lesson + " on own keys (" + string.Join(" + ", FlowsFor(lesson)) + "): the same " + shape0.Count + " events, checks, results and byte counts as on built-in keys, the same ending, and " + checkedKeys + " keys in use are the learner's bytes";
            }
        }

        [Clause("A17.lesson-1.my-keys")] public static string L1(Ctx c) { return Run(c, 1); }
        [Clause("A17.lesson-2.my-keys")] public static string L2(Ctx c) { return Run(c, 2); }
        [Clause("A17.lesson-4.my-keys")] public static string L4(Ctx c) { return Run(c, 4); }
        [Clause("A17.lesson-5.my-keys")] public static string L5(Ctx c) { return Run(c, 5); }
        [Clause("A17.lesson-6.my-keys")] public static string L6(Ctx c) { return Run(c, 6); }
        [Clause("A17.lesson-7.my-keys")] public static string L7(Ctx c) { return Run(c, 7); }
        [Clause("A17.lesson-8.my-keys")] public static string L8(Ctx c) { return Run(c, 8); }
        [Clause("A17.lesson-9.my-keys")] public static string L9(Ctx c) { return Run(c, 9); }
        [Clause("A17.lesson-10.my-keys")] public static string L10(Ctx c) { return Run(c, 10); }
    }
}
