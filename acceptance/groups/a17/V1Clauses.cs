using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// A17, slice V1: the practice vault (modes-design.md section 4). It copies the behaviour of a vault and gives none of the protection.
    /// The anchor is the vault file: these clauses read and edit vault.db with Python's sqlite3 (checks/vaultdb.py), so an audit row counts
    /// only when it is in the file, whatever the Host reports. OpenSSL judges the exercise's signature.
    /// </summary>
    public static class V1Clauses
    {
        static void RequireBuilt(SessionRun run, int lesson)
        {
            if (run.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson " + lesson + " as not built yet");
        }

        static List<Dictionary<string, object>> EventsOfType(SessionRun run, string type)
        {
            List<Dictionary<string, object>> r = new List<Dictionary<string, object>>();
            foreach (Dictionary<string, object> ev in run.Events) if (MiniJson.Str(ev, "type") == type) r.Add(ev);
            return r;
        }

        static Dictionary<string, object> RowWhere(List<Dictionary<string, object>> rows, string op, string nameStart, string result)
        {
            foreach (Dictionary<string, object> r in rows)
                if (MiniJson.Str(r, "op") == op && (MiniJson.Str(r, "name") ?? "").StartsWith(nameStart) && (result == null || MiniJson.Str(r, "result") == result)) return r;
            return null;
        }

        static string ChainProblem(List<Dictionary<string, object>> rows)
        {
            HashSet<string> seen = new HashSet<string>();
            double lastSeq = 0;
            foreach (Dictionary<string, object> r in rows)
            {
                double seq = MiniJson.Num(r, "seq", -1);
                if (seq <= lastSeq) return "audit seq " + seq + " does not rise after " + lastSeq;
                lastSeq = seq;
                string prev = MiniJson.Str(r, "prev_hash") ?? MiniJson.Str(r, "prevHash");
                if (string.IsNullOrEmpty(prev)) return "audit row " + seq + " has no prev_hash";
                if (!seen.Add(prev)) return "audit row " + seq + " repeats a prev_hash, so the rows do not link";
            }
            return null;
        }

        // ---------------------------------------------------------------- the exercise: sign, derive, refuse, audit

        static SessionRun RunExercise(HostProc h)
        {
            SessionRun run = HostSession.Run(h, 20, "glass", null);
            RequireBuilt(run, 20);
            Check.True(run.Error == null && run.Finished != null, "the vault exercise (lab 20) did not finish: " + (run.Frames.Count == 0 ? "no frames" : run.Frames[run.Frames.Count - 1]));
            return run;
        }

        [Clause("A17.vault.export-refused-and-audited")]
        public static string ExportRefusedAndAudited(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-vault-export"))
            {
                SessionRun run = RunExercise(h);
                List<Dictionary<string, object>> refused = EventsOfType(run, "vault.refused");
                Check.True(refused.Count == 1, "the exercise sent " + refused.Count + " vault.refused events; expected 1");
                Check.Equal("code of vault.refused", "VAULT_EXPORT_REFUSED", MiniJson.Str(refused[0], "code"));

                // The rows in the FILE, not the Host's report of them.
                List<Dictionary<string, object>> rows = A17.FileAuditRows(c, h);
                Dictionary<string, object> exportRow = RowWhere(rows, "export", "exercise/", "refused");
                Check.True(exportRow != null, "the vault file holds no audit row for the refused export. Rows: " + rows.Count);
                Check.True((MiniJson.Str(exportRow, "detail") ?? "").Contains("VAULT_EXPORT_REFUSED"), "the audit row of the refusal does not name VAULT_EXPORT_REFUSED: " + MiniJson.Write(exportRow));
                // Control: the two calls that worked left rows that read differently.
                Check.True(RowWhere(rows, "sign", "exercise/", "ok") != null, "the vault file holds no ok row for the exercise's sign call");
                Check.True(RowWhere(rows, "derive", "exercise/", "ok") != null, "the vault file holds no ok row for the exercise's derive call");
                string chain = ChainProblem(rows);
                Check.True(chain == null, chain);

                // The Host's route reports the same refusal.
                Reply route = HostHttp.Get(h, "/api/security/vault/audit?after=0");
                Check.True(route.Ok, "GET vault/audit got " + route);
                Check.True(RowWhere(A17.Audit(h), "export", "exercise/", "refused") != null, "GET vault/audit does not show the refused export that the file holds");
                return "the exercise's export is refused with VAULT_EXPORT_REFUSED; the vault file holds the refused row beside ok rows for sign and derive; " + rows.Count + " rows link by prev_hash";
            }
        }

        [Clause("A17.vault.exercise-sign-judged-by-openssl")]
        public static string ExerciseSignJudgedByOpenssl(Ctx c)
        {
            string openssl = Referees.OpenSsl(c);
            using (HostProc h = A17.Host(c, "a17-vault-sign"))
            {
                SessionRun run = RunExercise(h);
                List<Dictionary<string, object>> signs = EventsOfType(run, "vault.sign");
                Check.True(signs.Count == 1, "the exercise sent " + signs.Count + " vault.sign events; expected 1");
                string name = MiniJson.Str(signs[0], "name"), inputHex = MiniJson.Str(signs[0], "inputHex"), sigHex = MiniJson.Str(signs[0], "signatureHex");
                Check.True(!string.IsNullOrEmpty(inputHex) && !string.IsNullOrEmpty(sigHex), "vault.sign does not carry inputHex and signatureHex, so no outside tool can judge it");
                Check.True(!string.IsNullOrEmpty(MiniJson.Str(signs[0], "inputHash")), "vault.sign carries no inputHash");

                // The public key comes from the vault's key list, and the verdict comes from OpenSSL.
                Reply keys = HostHttp.Get(h, "/api/security/vault/keys");
                Check.True(keys.Ok && keys.Json != null, "GET vault/keys got " + keys);
                string pubHex = null;
                foreach (object o in MiniJson.Arr(keys.Json, "keys") ?? new List<object>())
                {
                    Dictionary<string, object> k = MiniJson.AsObject(o);
                    if (MiniJson.Str(k, "name") == name) pubHex = MiniJson.Str(k, "publicHex");
                }
                Check.True(!string.IsNullOrEmpty(pubHex), "GET vault/keys lists no publicHex for " + name);

                string dir = A17.TempDir(c, "vault-sign");
                string pub = Path.Combine(dir, "pub.pem"), msg = Path.Combine(dir, "msg.bin"), sig = Path.Combine(dir, "sig.bin"), o2;
                File.WriteAllText(pub, V0Clauses.Ed25519Pem(Hex.Decode(pubHex)));
                File.WriteAllBytes(msg, Hex.Decode(inputHex));
                File.WriteAllBytes(sig, Hex.Decode(sigHex));
                int ok = Proc.Run(openssl, "pkeyutl -verify -pubin -inkey \"" + pub + "\" -rawin -in \"" + msg + "\" -sigfile \"" + sig + "\"", dir, 30000, out o2);
                Check.True(ok == 0 && o2.Contains("Signature Verified Successfully"), "OpenSSL does not verify the exercise's signature: " + o2.Trim());
                // Control: one changed byte in the message, same program.
                byte[] bad = Hex.Decode(inputHex);
                bad[0] ^= 0x01;
                File.WriteAllBytes(msg, bad);
                int refused = Proc.Run(openssl, "pkeyutl -verify -pubin -inkey \"" + pub + "\" -rawin -in \"" + msg + "\" -sigfile \"" + sig + "\"", dir, 30000, out o2);
                Check.True(refused != 0, "control: OpenSSL accepted a signature over a changed message, so it is no judge here");
                return "OpenSSL verifies the signature of " + name + " from the vault's public key and refuses it over a message with one byte changed";
            }
        }

        [Clause("A17.vault.exercise-walk")]
        public static string ExerciseWalk(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-vault-walk"))
            {
                // Lab 20 stays outside GET /api/lessons, as lab 0 does.
                Reply lessons = HostHttp.Get(h, "/api/lessons");
                Check.True(lessons.Ok, "GET /api/lessons got " + lessons);
                Check.True(!(lessons.Body ?? "").Contains("\"id\":20") && !(lessons.Body ?? "").Contains("\"lesson\":20"), "GET /api/lessons lists lab 20, which belongs to the vault page only");
                SessionRun run = RunExercise(h);
                List<string> order = new List<string>();
                foreach (Dictionary<string, object> ev in run.Events)
                {
                    string t = MiniJson.Str(ev, "type");
                    if (t != null && t.StartsWith("vault.")) order.Add(t);
                }
                Check.Equal("order of the exercise events", "vault.sign,vault.derive,vault.refused,vault.audit", string.Join(",", order.ToArray()));
                List<Dictionary<string, object>> audit = EventsOfType(run, "vault.audit");
                List<object> auditRows = MiniJson.Arr(audit[0], "rows");
                Check.True(auditRows != null && auditRows.Count >= 3, "vault.audit lists " + (auditRows == null ? 0 : auditRows.Count) + " rows; expected the three calls at least");

                // The tour binds each of the four steps to one of these events.
                string toursDir = c.Prop("tours.dir", Path.Combine(c.RepoRoot, "app", "src", "tours"));
                string tour = Path.Combine(toursDir, "lesson-20.json");
                if (!File.Exists(tour)) throw new NotRunException("PRODUCT_MISSING", tour + " does not exist yet (the tour of the vault exercise)");
                object parsed = MiniJson.Parse(File.ReadAllText(tour));
                List<object> steps = parsed as List<object> ?? MiniJson.Arr(MiniJson.AsObject(parsed), "steps");
                Check.True(steps != null && steps.Count == 4, "the tour of lab 20 has " + (steps == null ? 0 : steps.Count) + " steps; expected 4 (sign, derive, refuse, audit)");
                Tally t2 = new Tally();
                foreach (object so in steps)
                {
                    Dictionary<string, object> s = MiniJson.AsObject(so);
                    Dictionary<string, object> bind = MiniJson.Obj(s, "bind");
                    string want = MiniJson.Str(bind, "eventType");
                    bool found = false;
                    foreach (Dictionary<string, object> ev in run.Events) if (MiniJson.Str(ev, "type") == want) found = true;
                    t2.Expect(MiniJson.Str(s, "id") ?? want, found, "no live event of type '" + want + "' fits the step's bind");
                }
                return "lab 20 sends sign, derive, refused, audit in order and stays out of GET /api/lessons; " + t2.Done();
            }
        }

        // ---------------------------------------------------------------- labs read through CourseRead, and it is audited as such

        [Clause("A17.vault.course-read-audited")]
        public static string CourseReadAudited(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-vault-course"))
            {
                A17.RunFlow(h, "my-login", null);
                int before = A17.FileAuditRows(c, h).Count;
                SessionRun run = HostSession.Run(h, 10, "glass", null);
                RequireBuilt(run, 10);
                Check.True(run.Error == null && run.Finished != null, "lesson 10 on a vault key did not finish");
                List<Dictionary<string, object>> rows = A17.FileAuditRows(c, h);
                Check.True(rows.Count > before, "lesson 10 added no audit row to the vault file");
                Dictionary<string, object> read = RowWhere(rows, "course-read", "token.issuer", "ok");
                Check.True(read != null, "the vault file holds no course-read row for token.issuer after lesson 10");
                Check.True((MiniJson.Str(read, "caller") ?? "").StartsWith("lesson-10"), "the course-read row names the caller '" + MiniJson.Str(read, "caller") + "'; expected one that starts with lesson-10");
                Check.True(RowWhere(rows, "export", "token.issuer", null) == null, "a lab's read of token.issuer was audited as an export. A course read is not an export");
                Check.True(RowWhere(rows, "course-read", "exercise/", null) == null, "a course read touched an exercise/ key, which has no route to the bytes");
                string chain = ChainProblem(rows);
                Check.True(chain == null, chain);
                return "lesson 10 on a vault key left a course-read row by lesson-10 in the vault file, and no export row for that key";
            }
        }

        // ---------------------------------------------------------------- a changed row is refused

        [Clause("A17.vault.tampered-row-refused")]
        public static string TamperedRowRefused(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-vault-tamper"))
            {
                A17.RunFlow(h, "my-login", null);
                SessionRun ok = HostSession.Run(h, 10, "glass", null);
                RequireBuilt(ok, 10);
                Check.True(ok.Error == null && ok.Finished != null, "control: lesson 10 on the untouched vault key did not finish");

                Dictionary<string, object> changed = MiniJson.AsObject(A17.VaultDb(c, h, "tamper-wrapped"));
                Check.True(MiniJson.Num(changed, "changed", 0) > 0, "the suite changed no wrapped key row, so the tamper did nothing");
                SessionRun bad = HostSession.Run(h, 10, "glass", null);
                Check.Equal("error code of a lab on a changed row", "VAULT_UNWRAP_FAILED", bad.ErrorCode);
                Check.True(bad.Events.Count == 0, "a lab on a changed row still sent " + bad.Events.Count + " trace events");
                Reply key = A17.Key(h, "token.issuer");
                Check.True(!key.Ok && key.Code == "VAULT_UNWRAP_FAILED", "the key route on a changed row got " + key + "; expected VAULT_UNWRAP_FAILED");
                return "control runs; after the wrapped bytes of " + (int)MiniJson.Num(changed, "changed", 0) + " rows change, the lab and the key route refuse with VAULT_UNWRAP_FAILED and send no event";
            }
        }

        // ---------------------------------------------------------------- an audit that cannot be written stops the call

        [Clause("A17.vault.audit-failure-refuses")]
        public static string AuditFailureRefuses(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-vault-auditfail"))
            {
                A17.RunFlow(h, "my-login", null);
                SessionRun ok = HostSession.Run(h, 10, "glass", null);
                RequireBuilt(ok, 10);
                Check.True(ok.Error == null && ok.Finished != null, "control: lesson 10 with a working audit did not finish");

                A17.VaultDb(c, h, "block-audit");
                try
                {
                    SessionRun bad = HostSession.Run(h, 10, "glass", null);
                    Check.True(bad.Error != null, "lesson 10 ran although no audit row could be written. A call whose audit cannot be written must be refused");
                    Check.Equal("error code when the audit cannot be written", "VAULT_AUDIT_FAILED", bad.ErrorCode);       // ASSUMED name, see CONTRACT.md
                    Check.True(bad.Events.Count == 0, "the refused lab still sent " + bad.Events.Count + " trace events");
                    Reply key = A17.Key(h, "token.issuer");
                    Check.True(!key.Ok, "the key route served a key although no audit row could be written: " + key);
                }
                finally { A17.VaultDb(c, h, "unblock-audit"); }
                SessionRun again = HostSession.Run(h, 10, "glass", null);
                Check.True(again.Error == null && again.Finished != null, "after the audit works again, lesson 10 still fails: " + (again.Frames.Count == 0 ? "no frames" : again.Frames[again.Frames.Count - 1]));
                return "with an audit insert that fails, the lab and the key route refuse and send no event; with it restored the lab runs again";
            }
        }

        // ---------------------------------------------------------------- exportable is set once

        [Clause("A17.vault.exportable-is-one-way")]
        public static string ExportableIsOneWay(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-vault-oneway"))
            {
                A17.Flow first = A17.Flow.Start(h, "my-login");
                first.MakeForMe(new Dictionary<string, bool> { { "token.issuer", true } }, null);
                Reply hidden = A17.Key(h, "token.issuer");
                Check.True(hidden.Ok && string.IsNullOrEmpty(MiniJson.Str(hidden.Json, "hex")), "control: a key kept from showing shows its bytes: " + hidden);

                // The learner runs the flow again and asks for an exportable key. The vault key was made non-exportable, and that is one-way.
                A17.Flow second = A17.Flow.Start(h, "my-login");
                second.MakeForMe(new Dictionary<string, bool> { { "token.issuer", false } }, null);
                Reply after = A17.Key(h, "token.issuer");
                Check.True(after.Ok, "GET key after the second run got " + after);
                Check.True(string.IsNullOrEmpty(MiniJson.Str(after.Json, "hex")), "a key made non-exportable shows its bytes after a second flow asked for an exportable one. Exportable is one-way");
                Reply keys = HostHttp.Get(h, "/api/security/vault/keys");
                Check.True(keys.Ok, "GET vault/keys got " + keys);
                bool found = false;
                foreach (object o in MiniJson.Arr(keys.Json, "keys") ?? new List<object>())
                {
                    Dictionary<string, object> k = MiniJson.AsObject(o);
                    if (MiniJson.Str(k, "name") != "token.issuer") continue;
                    found = true;
                    Check.True(!MiniJson.Bool(k, "exportable", true), "GET vault/keys lists token.issuer as exportable after it was made non-exportable");
                    Check.True(MiniJson.Num(k, "versions", 0) >= 2 || (MiniJson.Arr(k, "versions") ?? new List<object>()).Count >= 2, "the second flow run did not add a version beside the first: " + MiniJson.Write(k));
                }
                Check.True(found, "GET vault/keys lists no key named token.issuer");
                return "a vault key made non-exportable stays non-exportable after a second flow run with the option off, and the second run adds a version";
            }
        }
    }
}
