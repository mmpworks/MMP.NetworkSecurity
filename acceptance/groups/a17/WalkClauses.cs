using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// A17, slices V4 to V7: each wizard flow walked from Intro to Done. A walk checks the spine, that no type of the flow is dropped
    /// (15 of 15 across the five flows), what the Check step says and who judged each type, and that Place writes a new version.
    /// A product's own word "Verified" never proves anything here. Where an outside tool judged, the referee clauses run that tool from acceptance/.
    /// Where none can (payment keys, passkey-shaped login), the clause name says known-answer.
    /// </summary>
    public static class WalkClauses
    {
        static string Judge(string typeId)
        {
            if (typeId.StartsWith("ssh.")) return "ssh.exe";
            if (typeId.StartsWith("dukpt.") || typeId == "device.enrolment") return "none";
            return "openssl";
        }

        /// <summary>The stable id the Check step carries in says (modes-design.md section 8.6); the copy file holds its words.</summary>
        static string Says(string typeId)
        {
            switch (Judge(typeId))
            {
                case "ssh.exe": return "checked-with-ssh-exe";
                case "none": return "no-outside-judge";
                default:
                    if (typeId == "token.issuer") return "checked-signature-only";
                    return typeId.StartsWith("lab.") ? "checked-with-openssl" : "checked-against-root";
            }
        }

        static string NameOf(string typeId)
        {
            switch (typeId)
            {
                case "pki.root-ca": return "MMP.NetworkSecurity training root";
                case "tls13.server": case "tls11.server": return "localhost";
                case "tls13.client": return "pump-reader-4";
                default: return null;                     // the design fixes only the certificate names
            }
        }

        static Dictionary<string, double> Versions(HostProc h)
        {
            Dictionary<string, double> v = new Dictionary<string, double>();
            foreach (object o in MiniJson.Arr(A17.Security(h), "types") ?? new List<object>())
            {
                Dictionary<string, object> d = MiniJson.AsObject(o);
                v[MiniJson.Str(d, "typeId")] = MiniJson.Num(d, "version", -1);
            }
            return v;
        }

        /// <summary>Walks one flow in "Make it for me" by step kind, checks every step, then runs it again to see a new version.</summary>
        public static string Walk(Ctx c, string flowId, string hostName)
        {
            string[] types = A17.TypesOf(flowId);
            using (HostProc h = A17.Host(c, hostName))
            {
                A17.Flow f = A17.Flow.Start(h, flowId);
                Check.Equal("kind of the first step", "explain", f.Kind);
                Check.True(MiniJson.Write(f.Step).Contains("wizard.common.test-keys-only"), "the first step of " + flowId + " does not carry the test-keys line (copy id wizard.common.test-keys-only)");
                f.Next();
                Check.True(f.Kind == "choose" || f.Kind == "generate", "the step after the first is " + f.Kind + "; expected choose or generate");
                f.MakeAll();

                // Review names every type of the flow, none dropped, and the fixed names the design lists.
                Check.Equal("kind of Review", "review", f.Kind);
                List<string> seen = new List<string>();
                foreach (Dictionary<string, object> fact in f.Facts)
                {
                    string id = MiniJson.Str(fact, "typeId");
                    seen.Add(id);
                    Check.True(!string.IsNullOrEmpty(MiniJson.Str(fact, "fingerprint")), "Review shows no fingerprint for " + id);
                    string want = NameOf(id);
                    if (want != null) Check.Equal("name of " + id + " (read-only)", want, MiniJson.Str(fact, "name"));
                }
                foreach (string t in types) Check.True(seen.Contains(t), "Review of " + flowId + " does not show " + t + ". Seen: " + string.Join(",", seen.ToArray()));
                Check.Equal("types shown by Review of " + flowId, types.Length, seen.Count);

                // back goes to the make screen, and making again is a new version. Going forward again reaches Review.
                Check.True(f.Allowed.Contains("back"), "Review allows no back");
                Reply back = f.Send("back", null);
                Check.True(back.Ok, "event back at Review got " + back);
                Check.True(f.Kind == "choose" || f.Kind == "generate", "back from Review left the kind at " + f.Kind + "; expected the make screen");
                f.MakeAll();
                Check.Equal("kind of Review after making again", "review", f.Kind);

                f.Next();
                Check.Equal("kind of the check step", "prove", f.Kind);
                f.RunCheck();

                // Who judged each type, and what the step says (a stable id; the copy file holds the words).
                foreach (string t in types)
                {
                    Dictionary<string, object> fact = null;
                    foreach (Dictionary<string, object> x in f.Facts) if (MiniJson.Str(x, "typeId") == t && x.ContainsKey("judge")) fact = x;
                    Check.True(fact != null, "the check step of " + flowId + " names no judge for " + t);
                    Check.Equal("judge of " + t, Judge(t), MiniJson.Str(fact, "judge"));
                    Check.Equal("says of " + t, Says(t), MiniJson.Str(fact, "says"));
                    Check.True(MiniJson.Bool(fact, "passed", false), "the check of " + t + " does not say passed");
                    if (Judge(t) != "none")
                    {
                        Check.True(!string.IsNullOrEmpty(MiniJson.Str(fact, "command")), "the check of " + t + " shows no command of " + Judge(t));
                        Check.True(!string.IsNullOrEmpty(MiniJson.Str(fact, "output")), "the check of " + t + " shows no output of " + Judge(t));
                    }
                }
                f.Next();
                Check.Equal("last kind", "done", f.Kind);

                Dictionary<string, double> v1 = Versions(h);
                foreach (string t in types)
                {
                    Check.Equal("mode of " + t, "Mine", A17.ModeOf(h, t));
                    Check.Equal("state of " + t, "Verified", A17.StateOf(h, t));
                    Check.True(v1[t] >= 1, "version of " + t + " after the first run is " + v1[t]);
                }
                // Placing writes a new version and keeps the old one.
                A17.Flow second = A17.Flow.Start(h, flowId);
                second.MakeForMe(null);
                Dictionary<string, double> v2 = Versions(h);
                foreach (string t in types) Check.Equal("version of " + t + " after the second run", v1[t] + 1, v2[t]);
                return flowId + ": explain > make > review > prove > done; Review shows all " + types.Length + " types; judges " + string.Join(",", Array.ConvertAll(types, Judge)) + "; a second run writes version +1";
            }
        }

        [Clause("A17.flow.certificates.walk")]
        public static string Certificates(Ctx c) { return Walk(c, "my-certificates", "a17-walk-certs"); }

        [Clause("A17.flow.ssh.walk")]
        public static string Ssh(Ctx c) { return Walk(c, "my-ssh", "a17-walk-ssh"); }

        /// <summary>No outside tool judges the payment keys, so the walk says known-answer in its name and checks that the screen says so.</summary>
        [Clause("A17.flow.payment.known-answer-walk")]
        public static string Payment(Ctx c) { return Walk(c, "my-payment", "a17-walk-payment"); }

        [Clause("A17.flow.lesson-keys.walk")]
        public static string LessonKeys(Ctx c) { return Walk(c, "my-lesson-keys", "a17-walk-lesson"); }

        // ---------------------------------------------------------------- payment keys: the answer is known, not judged by a tool

        [Clause("A17.payment.known-answer-vectors-through-flow-code")]
        public static string PaymentKnownAnswer(Ctx c)
        {
            // Control: the reference derive code reproduces the published X9.24-3 vectors. Without this the comparison below proves nothing.
            Tally control = new Tally();
            foreach (VectorRecord r in c.Vectors("x9-24-3-aes-dukpt.nsv", "dukpt-aes128-from-aes128"))
            {
                byte[] bdk = r.Bytes("bdk"), ikid = r.Bytes("ikid");
                uint counter = (uint)r.Long("counter");
                control.Compare(r.Where + " initial key", r.Bytes("initial_key"), DukptReference.InitialKey(bdk, ikid));
                control.Compare(r.Where + " pin key", r.Bytes("pin"), DukptReference.WorkingKey(bdk, ikid, counter, 0x1000, 16));
            }
            string controlText = control.Done();

            using (HostProc h = A17.Host(c, "a17-payment-ka"))
            {
                A17.RunFlow(h, "my-payment");
                Reply key = A17.Key(h, "dukpt.bdk");
                string bdkHex = MiniJson.Str(key.Json, "hex");
                Check.True(key.Ok && !string.IsNullOrEmpty(bdkHex), "GET key of dukpt.bdk shows no bytes with Show keys ON: " + key);
                Check.Equal("length of a test BDK", 32, bdkHex.Length);               // 16 bytes this round, since lessons use AES-128
                byte[] bdk = Hex.Decode(bdkHex), ikid = Encoding.ASCII.GetBytes("MMPTRAIN");

                SessionRun run = HostSession.Run(h, 6, "glass", null);
                if (run.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson 6 as not built yet");
                Check.True(run.Error == null && run.Finished != null, "lesson 6 on the learner's BDK did not finish: " + (run.Frames.Count == 0 ? "no frames" : run.Frames[run.Frames.Count - 1]));
                string bankBdk = null, initial = null;
                int sales = 0;
                foreach (A17.SecretRef s in A17.Secrets(run))
                {
                    if (s.Holder != "bank") continue;
                    if (s.Name == "dukpt.bdk") bankBdk = s.Hex;
                    else if (s.Name == "dukpt.initial") initial = s.Hex;
                    else if (s.Name.StartsWith("dukpt.pinKey."))
                    {
                        uint counter = uint.Parse(s.Name.Substring("dukpt.pinKey.".Length));
                        Check.Bytes("bank PIN key of sale " + counter, DukptReference.WorkingKey(bdk, ikid, counter, 0x1000, 16), Hex.Decode(s.Hex));
                        sales++;
                    }
                }
                Check.True(bankBdk != null && bankBdk.Equals(bdkHex, StringComparison.OrdinalIgnoreCase), "the bank in lesson 6 holds " + bankBdk + ", not the learner's BDK " + bdkHex);
                Check.True(initial != null, "lesson 6 shows no dukpt.initial secret of the bank");
                Check.Bytes("bank initial key", DukptReference.InitialKey(bdk, ikid), Hex.Decode(initial));
                Check.True(sales >= 3, "lesson 6 shows " + sales + " per-sale PIN keys of the bank; expected at least 3");
                return "known answer, no outside tool: the reference reproduces the published X9.24-3 vectors (" + controlText + "); on the learner's BDK, lesson 6 derives the initial key and " + sales + " per-sale PIN keys that equal the reference's";
            }
        }
    }
}
