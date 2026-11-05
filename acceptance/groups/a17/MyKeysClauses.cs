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
            List<string> shape = new List<string>();
            foreach (Dictionary<string, object> ev in evs)
            {
                Dictionary<string, object> chk = MiniJson.Obj(ev, "check");
                shape.Add(string.Join("|", new string[] {
                    MiniJson.Str(ev, "type"), MiniJson.Str(ev, "actor"), MiniJson.Str(ev, "from"), MiniJson.Str(ev, "to"), MiniJson.Str(ev, "step"),
                    MiniJson.Str(chk, "name"), MiniJson.Str(chk, "result"), MiniJson.Str(chk, "code"), "wire=" + Len(ev, "wire"), "plain=" + Len(ev, "plain") }));
            }
            return shape;
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

                foreach (string flow in FlowsFor(lesson)) A17.RunFlow(h, flow);
                SessionRun mine = HostSession.Run(h, lesson, "glass", null);
                Check.True(mine.Error == null && mine.Finished != null, "lesson " + lesson + " on own keys did not finish: " + (mine.Frames.Count == 0 ? "no frames" : mine.Frames[mine.Frames.Count - 1]));
                Check.Equal("ending of lesson " + lesson, Ending(baseline), Ending(mine));
                List<string> shape1 = Shape(mine);
                Check.Equal("events of lesson " + lesson + " on own keys against built-in keys", shape0.Count, shape1.Count);
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
