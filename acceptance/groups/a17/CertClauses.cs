using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// A17, slice V4: the certificate flow with the learner's own files, and the attack rows against them. The suite makes the chains with OpenSSL,
    /// so it knows which chain is sound before the Host says a word. Import layout (ASSUMED, acceptance/CONTRACT.md section 5): paths["pki.root-ca"] is the root
    /// certificate and paths["pki.root-ca.key"] its key (left out for a trust-only root); each leaf type has its certificate and "&lt;typeId&gt;.key".
    /// </summary>
    public static class CertClauses
    {
        static string Why(A17.ImportResult r) { return r + (r.Messages.Count > 0 ? " (" + r.Messages[0] + ")" : ""); }

        // ---------------------------------------------------------------- the check can fail

        [Clause("A17.proof.root-negative-control")]
        public static string RootNegativeControl(Ctx c)
        {
            TestPki a = TestPki.Make(c, "neg-a", new TestPki.Options()), b = TestPki.Make(c, "neg-b", new TestPki.Options());
            string o;
            // Ground truth, from OpenSSL, before the Host is asked.
            Check.True(TestPki.OpensslVerifies(c, a.RootPem, a.ServerPem, out o), "setup: OpenSSL does not verify A's leaf under A's root: " + o.Trim());
            Check.True(!TestPki.OpensslVerifies(c, a.RootPem, b.ServerPem, out o), "setup: OpenSSL verifies B's leaf under A's root, so there is no negative control");

            using (HostProc h = A17.Host(c, "a17-neg-good"))
            {
                A17.ImportResult good = A17.TryImport(h, "my-certificates", a.Paths(true));
                Check.True(good.Done, "a sound chain made by OpenSSL did not reach Done: " + Why(good));
                Check.Equal("state of tls13.server after a sound chain", "Verified", A17.StateOf(h, "tls13.server"));
            }
            using (HostProc h = A17.Host(c, "a17-neg-bad"))
            {
                Dictionary<string, string> mismatched = a.Paths(true);
                mismatched["tls13.server"] = b.ServerPem;
                mismatched["tls13.server.key"] = b.ServerKey;
                A17.ImportResult bad = A17.TryImport(h, "my-certificates", mismatched);
                Check.True(!bad.Done, "a leaf signed by another root reached Done: the check judged a chain OpenSSL refuses as sound");
                Check.True(bad.Codes.Count > 0 && !bad.Codes.Contains(""), "the refusal carries no code: " + Why(bad));
                Check.True(A17.StateOf(h, "tls13.server") != "Verified", "tls13.server reads Verified although its leaf is not signed by the root");
                Reply ready = A17.Readiness(h, 5);
                Check.True(!MiniJson.Bool(ready.Json, "mayRun", true) || A17.ModeOf(h, "tls13.server") != "Mine", "lesson 5 may run on a leaf the root did not sign");
                return "OpenSSL verifies A's chain and refuses B's leaf under A's root; the Host takes the first and refuses the second with " + string.Join(",", bad.Codes.ToArray()) + ", leaving tls13.server not Verified";
            }
        }

        // ---------------------------------------------------------------- a root the engines cannot verify is named, not blamed on tampering

        [Clause("A17.chain.alg-unsupported-named")]
        public static string AlgUnsupportedNamed(Ctx c)
        {
            TestPki ed = TestPki.Make(c, "alg-ed", new TestPki.Options()), rsa = TestPki.Make(c, "alg-rsa", new TestPki.Options { RootAlg = "rsa" });
            using (HostProc h = A17.Host(c, "a17-alg-control"))
            {
                A17.ImportResult control = A17.TryImport(h, "my-certificates", ed.Paths(true));
                Check.True(control.Done && !control.Has("CERT_SIGNATURE_ALG_UNSUPPORTED") && !control.Has("CERT_SIGNATURE"), "control: an Ed25519 root made by OpenSSL was refused: " + Why(control));
            }
            using (HostProc h = A17.Host(c, "a17-alg-rsa"))
            {
                A17.ImportResult r = A17.TryImport(h, "my-certificates", rsa.Paths(true));
                string where = "at the flow";
                if (!r.Has("CERT_SIGNATURE_ALG_UNSUPPORTED") && r.Done)
                {
                    // The flow let it through. Then the lab must name it.
                    SessionRun run = HostSession.Run(h, 4, "glass", null);
                    if (run.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson 4 as not built yet");
                    string code = run.Error != null ? run.ErrorCode : MiniJson.Str(run.Finished, "code");
                    if (code != null) r.Codes.Add(code);
                    where = "in lesson 4";
                }
                Check.True(r.Has("CERT_SIGNATURE_ALG_UNSUPPORTED"), "an RSA root gives " + (r.Codes.Count == 0 ? "no code" : string.Join(",", r.Codes.ToArray())) + ", not CERT_SIGNATURE_ALG_UNSUPPORTED");
                Check.True(!r.Has("CERT_SIGNATURE"), "an RSA root is reported as CERT_SIGNATURE, which tells a learner the certificate was tampered with");
                bool namesRoute = false;
                foreach (string m in r.Messages) if (m.IndexOf("OS transport", StringComparison.OrdinalIgnoreCase) >= 0) namesRoute = true;
                if (where == "at the flow") Check.True(namesRoute, "CERT_SIGNATURE_ALG_UNSUPPORTED does not name the OS transport as the route: " + string.Join(" | ", r.Messages.ToArray()));
                return "an Ed25519 root passes; an RSA root gives CERT_SIGNATURE_ALG_UNSUPPORTED " + where + (namesRoute ? ", naming the OS transport" : "") + ", never CERT_SIGNATURE";
            }
        }

        // ---------------------------------------------------------------- the lab clock

        [Clause("A17.clock.new-certificate-not-expired")]
        public static string NewCertificateNotExpired(Ctx c)
        {
            DateTime now = DateTime.UtcNow;
            string fmt = "yyyyMMddHHmmss";
            TestPki fresh = TestPki.Make(c, "clock-new", new TestPki.Options { Days = 60, NotBefore = now.AddDays(-1).ToString(fmt) + "Z", NotAfter = now.AddDays(30).ToString(fmt) + "Z" });
            TestPki old = TestPki.Make(c, "clock-old", new TestPki.Options { Days = 60, NotBefore = "20200101000000Z", NotAfter = "20200201000000Z" });
            using (HostProc h = A17.Host(c, "a17-clock-new"))
            {
                A17.ImportResult r = A17.TryImport(h, "my-certificates", fresh.Paths(true));
                Check.True(r.Done, "a certificate valid from yesterday to 30 days ahead did not reach Done: " + Why(r));
                foreach (int lesson in new int[] { 5, 10 })
                {
                    // The lab clocks are fixed at 2030-01-01 (lesson 5) and 2026-11-05 (lesson 10). A 30-day certificate is expired at the first and not yet valid at the second,
                    // unless the lab reads the wall clock for an imported certificate.
                    SessionRun run = HostSession.Run(h, lesson, "glass", null);
                    if (run.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson " + lesson + " as not built yet");
                    Check.True(run.Error == null && run.Finished != null, "lesson " + lesson + " on a fresh certificate did not finish: " + (run.Frames.Count == 0 ? "no frames" : run.Frames[run.Frames.Count - 1]));
                    string code = MiniJson.Str(run.Finished, "code");
                    Check.True(code != "CERT_EXPIRED" && code != "CERT_NOT_YET_VALID", "lesson " + lesson + " on a fresh certificate ends with " + code + ": the lab judged it on its fixed clock");
                }
            }
            using (HostProc h = A17.Host(c, "a17-clock-old"))
            {
                // Control: a certificate that really ran out is named, so the clock is read and not ignored.
                A17.ImportResult r = A17.TryImport(h, "my-certificates", old.Paths(true));
                bool named = r.Has("CERT_EXPIRED");
                if (!named && r.Done)
                {
                    SessionRun run = HostSession.Run(h, 5, "glass", null);
                    named = MiniJson.Str(run.Finished, "code") == "CERT_EXPIRED" || run.ErrorCode == "CERT_EXPIRED";
                }
                Check.True(named, "control: a certificate that expired in 2020 is not named CERT_EXPIRED: " + Why(r));
                return "a certificate valid from yesterday runs lessons 5 and 10 without CERT_EXPIRED or CERT_NOT_YET_VALID; a certificate that expired in 2020 is named CERT_EXPIRED";
            }
        }

        // ---------------------------------------------------------------- attack rows

        static Dictionary<string, object> AttackRow(HostProc h, string attackId)
        {
            Reply r = HostHttp.Get(h, "/api/lessons");
            Check.True(r.Ok && r.Array != null, "GET /api/lessons got " + r);
            foreach (object lo in r.Array)
                foreach (object ao in MiniJson.Arr(MiniJson.AsObject(lo), "attacks") ?? new List<object>())
                {
                    Dictionary<string, object> row = MiniJson.AsObject(ao);
                    if (MiniJson.Str(row, "attackId") == attackId) return row;
                }
            throw new FailException("GET /api/lessons lists no attack row " + attackId);
        }

        static readonly string[] NeedCaKey = new string[] { "L4-expired-cert", "L4-wrong-name", "L10-wrong-client-name" };

        [Clause("A17.attacks.unavailable-names-code")]
        public static string UnavailableNamesCode(Ctx c)
        {
            TestPki pki = TestPki.Make(c, "trustonly", new TestPki.Options());
            using (HostProc h = A17.Host(c, "a17-attacks-trust"))
            {
                A17.ImportResult r = A17.TryImport(h, "my-certificates", pki.Paths(false));       // the root certificate only: a trust-only CA
                Check.True(r.Done, "a trust-only root (certificate without its key) did not reach Done: " + Why(r));
                foreach (string id in NeedCaKey)
                {
                    Dictionary<string, object> row = AttackRow(h, id);
                    Check.True(row.ContainsKey("available") && !MiniJson.Bool(row, "available", true), "attack row " + id + " is still available with a trust-only CA: it cannot sign a bad certificate");
                    Check.Equal("whyNot of " + id, "ATTACK_NEEDS_CA_KEY", MiniJson.Str(row, "whyNot"));
                }
                SessionRun lab = HostSession.Run(h, 4, "glass", null);
                if (lab.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson 4 as not built yet");
                Check.True(lab.Error == null && lab.Finished != null, "the lab itself did not run on a trust-only CA: " + (lab.Frames.Count == 0 ? "no frames" : lab.Frames[lab.Frames.Count - 1]));
            }
            using (HostProc h = A17.Host(c, "a17-attacks-ca"))
            {
                A17.RunFlow(h, "my-certificates");
                foreach (string id in NeedCaKey)
                    Check.True(MiniJson.Bool(AttackRow(h, id), "available", true), "control: attack row " + id + " is unavailable although the CA key is here");
            }
            return "with a trust-only CA the rows " + string.Join(", ", NeedCaKey) + " show available false with ATTACK_NEEDS_CA_KEY and the lab still runs; with the CA key the same rows are available";
        }

        /// <summary>The field of an event that holds byte offset pos, from the event's own fields[] list.</summary>
        static string FieldAt(Dictionary<string, object> ev, int pos, int wireLength)
        {
            foreach (object fo in MiniJson.Arr(ev, "fields") ?? new List<object>())
            {
                Dictionary<string, object> f = MiniJson.AsObject(fo);
                int off = (int)MiniJson.Num(f, "offset", 0), len = (int)MiniJson.Num(f, "length", 0);
                if (len < 0) len = wireLength - off;
                if (pos >= off && pos < off + len) return MiniJson.Str(f, "name");
            }
            return null;
        }

        [Clause("A17.attacks.hit-named-field")]
        public static string HitNamedField(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-attacks-field"))
            {
                Reply lessons = HostHttp.Get(h, "/api/lessons");
                Check.True(lessons.Ok && lessons.Array != null, "GET /api/lessons got " + lessons);
                A17.RunFlow(h, "my-certificates");
                int checkedRows = 0, rowsWithoutField = 0;
                List<string> notBuilt = new List<string>();
                foreach (object lo in lessons.Array)
                {
                    Dictionary<string, object> lesson = MiniJson.AsObject(lo);
                    int n = (int)MiniJson.Num(lesson, "lesson", 0);
                    foreach (object ao in MiniJson.Arr(lesson, "attacks") ?? new List<object>())
                    {
                        Dictionary<string, object> row = MiniJson.AsObject(ao);
                        if (MiniJson.Str(row, "kind") != "flip-byte") continue;
                        string id = MiniJson.Str(row, "attackId"), field = MiniJson.Str(row, "field");
                        if (string.IsNullOrEmpty(field)) { rowsWithoutField++; continue; }
                        if (row.ContainsKey("available") && !MiniJson.Bool(row, "available", true)) continue;
                        SessionRun parent = HostSession.Run(h, n, "glass", null);
                        if (parent.ErrorCode == "LESSON_NOT_BUILT") { notBuilt.Add(id); continue; }
                        Check.True(parent.Error == null && parent.Finished != null, id + ": the parent run of lesson " + n + " did not finish");
                        SessionRun fork = HostSession.Fork(h, parent.SessionId, id);
                        Check.True(fork.Error == null && fork.Finished != null, id + ": the fork did not finish: " + (fork.Frames.Count == 0 ? "no frames" : fork.Frames[fork.Frames.Count - 1]));
                        // The flipped byte, found by comparing the same event in the parent and in the fork.
                        string hit = null; int pos = -1;
                        Dictionary<string, Dictionary<string, object>> byKey = new Dictionary<string, Dictionary<string, object>>();
                        foreach (Dictionary<string, object> ev in parent.Events) byKey[Key(ev)] = ev;
                        foreach (Dictionary<string, object> ev in fork.Events)
                        {
                            Dictionary<string, object> pe;
                            if (!byKey.TryGetValue(Key(ev), out pe)) continue;
                            string pw = MiniJson.Str(pe, "wire") ?? "", fw = MiniJson.Str(ev, "wire") ?? "";
                            if (pw.Length == 0 || pw.Length != fw.Length || pw == fw) continue;
                            byte[] a = Hex.Decode(pw), b = Hex.Decode(fw);
                            int diffs = 0, first = -1;
                            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) { diffs++; if (first < 0) first = i; }
                            if (diffs != 1) continue;                                   // a flip changes one byte; later events change many
                            pos = first; hit = FieldAt(pe, first, a.Length);
                            break;
                        }
                        Check.True(pos >= 0, id + ": no event of the fork differs from the parent by one byte, so the flip cannot be located");
                        Check.Equal(id + ": field hit by byte " + pos, field, hit);
                        string expect = MiniJson.Str(row, "expectCode");
                        if (!string.IsNullOrEmpty(expect)) Check.Equal(id + ": code at the end of the fork", expect, MiniJson.Str(fork.Finished, "code"));
                        checkedRows++;
                    }
                }
                if (checkedRows == 0)
                    throw new NotRunException("PRODUCT_MISSING", rowsWithoutField > 0 ? rowsWithoutField + " flip-byte rows name no field yet (TamperPlan.Field, modes-design.md section 3.4)" : "no flip-byte attack row is listed" + (notBuilt.Count > 0 ? " for a built lesson" : ""));
                return checkedRows + " flip-byte rows: the byte each fork flips lies in the field the row names, and the fork ends with the row's code" + (rowsWithoutField > 0 ? "; " + rowsWithoutField + " rows name no field yet" : "");
            }
        }

        static string Key(Dictionary<string, object> ev)
        {
            string stream = MiniJson.Str(ev, "streamId") ?? "";
            int i = stream.IndexOf('/');
            return (i < 0 ? stream : stream.Substring(i + 1)) + "#" + MiniJson.Num(ev, "streamSeq", 0);
        }
    }
}
