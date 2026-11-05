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
    /// Labs read a key through Export, and the audit list shows the caller. The exercise is three screens on narrow Host routes (design 4.3), not a lab.
    /// </summary>
    public static class V1Clauses
    {
        const string Exercise = "/api/security/vault/exercise/";

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

        static Reply Post(HostProc h, string route, string json) { return HostHttp.Post(h, Exercise + route, json); }

        static bool CodeOk(Reply r) { string code = r.Json == null ? null : MiniJson.Str(r.Json, "code"); return string.IsNullOrEmpty(code) || code == "OK"; }

        static Dictionary<string, object> VaultKey(HostProc h, string name)
        {
            Reply keys = HostHttp.Get(h, "/api/security/vault/keys");
            Check.True(keys.Ok, "GET vault/keys got " + keys);
            foreach (object o in MiniJson.Arr(keys.Json, "keys") ?? new List<object>())
            {
                Dictionary<string, object> k = MiniJson.AsObject(o);
                if (MiniJson.Str(k, "name") == name) return k;
            }
            throw new FailException("GET vault/keys lists no key named " + name);
        }

        // ---------------------------------------------------------------- the exercise: sign, derive, refuse, audit

        [Clause("A17.vault.export-refused-and-audited")]
        public static string ExportRefusedAndAudited(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-vault-export"))
            {
                Reply sign = Post(h, "sign", A17.Obj("text", "pay the pump owner"));
                Check.True(sign.Ok && CodeOk(sign), "exercise sign got " + sign);
                Reply derive = Post(h, "derive", A17.Obj("label", "pump-4"));
                Check.True(derive.Ok && CodeOk(derive), "exercise derive got " + derive);
                // The key leaves the box only if the box says yes. It says no, by name, with HTTP 409.
                Reply export = Post(h, "export", "{}");
                Check.True(export.Status == 409 && export.Code == "VAULT_EXPORT_REFUSED", "exercise export got " + export + "; expected HTTP 409 VAULT_EXPORT_REFUSED");

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
                Check.True(RowWhere(A17.Audit(h), "export", "exercise/", "refused") != null, "GET vault/audit does not show the refused export that the file holds");
                return "the exercise's export is refused with HTTP 409 VAULT_EXPORT_REFUSED; the vault file holds the refused row beside ok rows for sign and derive; " + rows.Count + " rows link by prev_hash";
            }
        }

        [Clause("A17.vault.exercise-sign-judged-by-openssl")]
        public static string ExerciseSignJudgedByOpenssl(Ctx c)
        {
            string openssl = Referees.OpenSsl(c);
            using (HostProc h = A17.Host(c, "a17-vault-sign"))
            {
                Reply sign = Post(h, "sign", A17.Obj("text", "pay the pump owner 20 dollars"));
                Check.True(sign.Ok && CodeOk(sign), "exercise sign got " + sign);
                string inputHex = MiniJson.Str(sign.Json, "inputHex"), sigHex = MiniJson.Str(sign.Json, "signatureHex"), pubHex = MiniJson.Str(sign.Json, "publicKeyHex");
                Check.True(!string.IsNullOrEmpty(inputHex) && !string.IsNullOrEmpty(sigHex) && !string.IsNullOrEmpty(pubHex), "sign returns no inputHex, signatureHex and publicKeyHex, so no outside tool can judge it: " + sign);
                Check.Equal("the signed message is the typed text", "pay the pump owner 20 dollars", Encoding.UTF8.GetString(Hex.Decode(inputHex)));
                Check.True(!string.IsNullOrEmpty(MiniJson.Str(sign.Json, "command")) && !string.IsNullOrEmpty(MiniJson.Str(sign.Json, "output")), "sign shows no command and no output of the check the Host ran");

                // The verdict comes from OpenSSL, run here, on the public key the Host gave.
                string dir = A17.TempDir(c, "vault-sign");
                string pub = Path.Combine(dir, "pub.pem"), msg = Path.Combine(dir, "msg.bin"), sig = Path.Combine(dir, "sig.bin"), o2;
                File.WriteAllText(pub, V0Clauses.Ed25519Pem(Hex.Decode(pubHex)));
                File.WriteAllBytes(msg, Hex.Decode(inputHex));
                File.WriteAllBytes(sig, Hex.Decode(sigHex));
                int ok = Proc.Run(openssl, "pkeyutl -verify -pubin -inkey \"" + pub + "\" -rawin -in \"" + msg + "\" -sigfile \"" + sig + "\"", dir, 30000, out o2);
                Check.True(ok == 0 && o2.Contains("Signature Verified Successfully"), "OpenSSL does not verify the exercise's signature: " + o2.Trim());
                // The public key is the vault's: the key list names it too.
                Dictionary<string, object> key = VaultKey(h, MiniJson.Str(sign.Json, "keyName"));
                Check.True(string.IsNullOrEmpty(MiniJson.Str(key, "publicHex")) || MiniJson.Str(key, "publicHex").Equals(pubHex, StringComparison.OrdinalIgnoreCase), "the key list shows another public key than sign returned");
                // Control: one changed byte in the message, same program.
                byte[] bad = Hex.Decode(inputHex);
                bad[0] ^= 0x01;
                File.WriteAllBytes(msg, bad);
                int refused = Proc.Run(openssl, "pkeyutl -verify -pubin -inkey \"" + pub + "\" -rawin -in \"" + msg + "\" -sigfile \"" + sig + "\"", dir, 30000, out o2);
                Check.True(refused != 0, "control: OpenSSL accepted a signature over a changed message, so it is no judge here");
                return "OpenSSL verifies the signature of " + MiniJson.Str(sign.Json, "keyName") + " over the typed text from the public key the Host returned, and refuses it over a message with one byte changed";
            }
        }

        [Clause("A17.vault.exercise-walk")]
        public static string ExerciseWalk(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-vault-walk"))
            {
                // The exercise is not a lab: it is absent from GET /api/lessons, and session.start for lesson 20 says no such lab is built.
                Reply lessons = HostHttp.Get(h, "/api/lessons");
                Check.True(lessons.Ok, "GET /api/lessons got " + lessons);
                Check.True(!(lessons.Body ?? "").Contains("\"lesson\":20") && !(lessons.Body ?? "").Contains("\"id\":20"), "GET /api/lessons lists lab 20; the exercise is routes and not a lab");
                SessionRun lab20 = HostSession.Run(h, 20, "glass", null);
                Check.Equal("session.start for lesson 20", "LESSON_NOT_BUILT", lab20.ErrorCode);

                // The two keys exist at once, need no flow, and say what they are.
                foreach (string name in new string[] { "exercise/signing", "exercise/derive" })
                {
                    Dictionary<string, object> k = VaultKey(h, name);
                    Check.True(!string.IsNullOrEmpty(MiniJson.Str(k, "fingerprint")), name + " shows no fingerprint");
                    Check.Equal("hidden marker of " + name, "non-exportable", MiniJson.Str(k, "hidden"));
                }

                // Step 1, sign. Step 2, derive: the same label gives the same key, another label gives another, and the key stays in the box.
                Reply sign = Post(h, "sign", A17.Obj("text", "walk"));
                Check.True(sign.Ok && CodeOk(sign), "sign got " + sign);
                Reply d1 = Post(h, "derive", A17.Obj("label", "pump-4")), d2 = Post(h, "derive", A17.Obj("label", "pump-4")), d3 = Post(h, "derive", A17.Obj("label", "pump-5"));
                Check.True(d1.Ok && d2.Ok && d3.Ok, "derive got " + d1 + " | " + d2 + " | " + d3);
                string o1 = MiniJson.Str(d1.Json, "outputHex"), o3 = MiniJson.Str(d3.Json, "outputHex");
                Check.True(!string.IsNullOrEmpty(o1) && o1 == MiniJson.Str(d2.Json, "outputHex"), "the same label gives two different derived keys: " + o1 + " and " + MiniJson.Str(d2.Json, "outputHex"));
                Check.True(!string.IsNullOrEmpty(o3) && o3 != o1, "two labels give one derived key");
                Check.Equal("label echoed by derive", "pump-4", MiniJson.Str(d1.Json, "label"));
                // Step 3, refuse. Step 4, audit: the chain is whole, and a changed row is found.
                Check.Equal("export code", "VAULT_EXPORT_REFUSED", Post(h, "export", "{}").Code);
                Reply intact = Post(h, "audit-check", "{}");
                Check.True(intact.Ok && CodeOk(intact), "audit-check got " + intact);
                Check.True(MiniJson.Num(intact.Json, "firstBadSeq", 0) <= 0, "audit-check reports a bad row (" + MiniJson.Num(intact.Json, "firstBadSeq", 0) + ") before any row changed");
                Check.True((MiniJson.Arr(intact.Json, "rows") ?? new List<object>()).Count >= 4, "audit-check lists " + (MiniJson.Arr(intact.Json, "rows") ?? new List<object>()).Count + " rows; expected the sign, derive and export calls");

                List<Dictionary<string, object>> before = A17.FileAuditRows(c, h);
                Dictionary<string, object> edited = MiniJson.AsObject(A17.VaultDb(c, h, "edit-audit"));
                double editedSeq = MiniJson.Num(edited, "seq", 0);
                Check.True(editedSeq > 0 && editedSeq < before.Count, "the suite changed no audit row");
                Reply found = Post(h, "audit-check", "{}");
                double bad = MiniJson.Num(found.Json, "firstBadSeq", 0);
                Check.True(bad == editedSeq || bad == editedSeq + 1, "audit-check does not find the changed row " + editedSeq + "; it reports firstBadSeq " + bad + " (the row itself, or the row after it, whose prev_hash no longer fits)");
                return "lab 20 is no lab; both exercise keys show a fingerprint and non-exportable; sign works, derive is steady per label, export is refused, audit-check passes then finds the audit row the suite changed (" + bad + ")";
            }
        }

        // ---------------------------------------------------------------- labs read through Export, and the audit shows the caller

        [Clause("A17.vault.export-audited-with-caller")]
        public static string ExportAuditedWithCaller(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-vault-caller"))
            {
                A17.RunFlow(h, "my-login");
                int before = A17.FileAuditRows(c, h).Count;
                SessionRun run = HostSession.Run(h, 10, "glass", null);
                if (run.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson 10 as not built yet");
                Check.True(run.Error == null && run.Finished != null, "lesson 10 on a vault key did not finish");
                List<Dictionary<string, object>> rows = A17.FileAuditRows(c, h);
                Check.True(rows.Count > before, "lesson 10 added no audit row to the vault file");
                Dictionary<string, object> export = null;
                foreach (Dictionary<string, object> r in rows)
                    if (MiniJson.Str(r, "op") == "export" && (MiniJson.Str(r, "name") ?? "").StartsWith("token.issuer") && (MiniJson.Str(r, "caller") ?? "").StartsWith("host/lab-") && MiniJson.Str(r, "result") == "ok") export = r;
                Check.True(export != null, "the vault file holds no export row for token.issuer by a caller 'host/lab-<n>' after lesson 10 (an exportable key left the box, and the audit says who took it)");
                Check.True(RowWhere(rows, "export", "token.issuer", "refused") == null, "an export of token.issuer was refused: a flow key is exportable");
                Check.True(RowWhere(rows, "export", "exercise/", "ok") == null, "an export of an exercise/ key succeeded, and those keys have no route to their bytes");
                string chain = ChainProblem(rows);
                Check.True(chain == null, chain);
                return "lesson 10 on a vault key left an ok export row for token.issuer by " + MiniJson.Str(export, "caller") + " in the vault file, and no refused row; the exercise keys were never exported";
            }
        }

        // ---------------------------------------------------------------- a changed row is refused

        [Clause("A17.vault.tampered-row-refused")]
        public static string TamperedRowRefused(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-vault-tamper"))
            {
                A17.RunFlow(h, "my-login");
                SessionRun ok = HostSession.Run(h, 10, "glass", null);
                if (ok.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson 10 as not built yet");
                Check.True(ok.Error == null && ok.Finished != null, "control: lesson 10 on the untouched vault key did not finish");

                Dictionary<string, object> changed = MiniJson.AsObject(A17.VaultDb(c, h, "tamper-wrapped"));
                Check.True(MiniJson.Num(changed, "changed", 0) > 0, "the suite changed no wrapped key row, so the tamper did nothing");
                SessionRun bad = HostSession.Run(h, 10, "glass", null);
                Check.Equal("error code of a lab on a changed row", "VAULT_UNWRAP_FAILED", bad.ErrorCode);
                Check.True(bad.Events.Count == 0, "a lab on a changed row still sent " + bad.Events.Count + " trace events");
                Reply key = A17.Key(h, "token.issuer");
                Check.True(!key.Ok && key.Code == "VAULT_UNWRAP_FAILED", "the key route on a changed row got " + key + "; expected VAULT_UNWRAP_FAILED");
                // The exercise keys are not under the tamper, and they still work.
                Check.True(Post(h, "sign", A17.Obj("text", "still works")).Ok, "the exercise sign stopped working after flow keys changed");
                return "control runs; after the wrapped bytes of " + (int)MiniJson.Num(changed, "changed", 0) + " rows change, the lab and the key route refuse with VAULT_UNWRAP_FAILED and send no event";
            }
        }

        // ---------------------------------------------------------------- an audit that cannot be written stops the call

        [Clause("A17.vault.audit-failure-refuses")]
        public static string AuditFailureRefuses(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-vault-auditfail"))
            {
                A17.RunFlow(h, "my-login");
                SessionRun ok = HostSession.Run(h, 10, "glass", null);
                if (ok.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson 10 as not built yet");
                Check.True(ok.Error == null && ok.Finished != null, "control: lesson 10 with a working audit did not finish");

                A17.VaultDb(c, h, "block-audit");
                try
                {
                    SessionRun bad = HostSession.Run(h, 10, "glass", null);
                    Check.True(bad.Error != null, "lesson 10 ran although no audit row could be written. A call whose audit cannot be written must be refused");
                    Check.Equal("error code when the audit cannot be written", "VAULT_AUDIT_FAILED", bad.ErrorCode);
                    Check.True(bad.Events.Count == 0, "the refused lab still sent " + bad.Events.Count + " trace events");
                    Reply key = A17.Key(h, "token.issuer");
                    Check.True(!key.Ok, "the key route served a key although no audit row could be written: " + key);
                    Reply export = Post(h, "export", "{}");
                    Check.True(export.Code == "VAULT_AUDIT_FAILED" || export.Code == "VAULT_EXPORT_REFUSED", "the exercise export with a blocked audit got " + export);
                }
                finally { A17.VaultDb(c, h, "unblock-audit"); }
                SessionRun again = HostSession.Run(h, 10, "glass", null);
                Check.True(again.Error == null && again.Finished != null, "after the audit works again, lesson 10 still fails: " + (again.Frames.Count == 0 ? "no frames" : again.Frames[again.Frames.Count - 1]));
                return "with an audit insert that fails, the lab and the key route refuse with VAULT_AUDIT_FAILED and send no event; with it restored the lab runs again";
            }
        }

        // ---------------------------------------------------------------- exportable is set once

        [Clause("A17.vault.exportable-is-one-way")]
        public static string ExportableIsOneWay(Ctx c)
        {
            using (HostProc h = A17.Host(c, "a17-vault-oneway"))
            {
                // The policy is set when a key is made. Flows make exportable keys. Only the exercise's keys are non-exportable.
                A17.RunFlow(h, "my-login");
                Check.True(MiniJson.Bool(VaultKey(h, "token.issuer"), "exportable", false), "a flow key is not exportable, but flows make exportable keys");
                foreach (string name in new string[] { "exercise/signing", "exercise/derive" })
                    Check.True(!MiniJson.Bool(VaultKey(h, name), "exportable", true), name + " is exportable");

                // Whatever the learner does next, it stays so: more flow runs, every exercise call, and an export asked for again and again.
                A17.RunFlow(h, "my-login");
                Post(h, "sign", A17.Obj("text", "x"));
                Post(h, "derive", A17.Obj("label", "x"));
                for (int i = 0; i < 3; i++)
                {
                    Reply export = Post(h, "export", "{}");
                    Check.True(export.Status == 409 && export.Code == "VAULT_EXPORT_REFUSED", "export ask " + (i + 1) + " got " + export);
                }
                foreach (string name in new string[] { "exercise/signing", "exercise/derive" })
                {
                    Dictionary<string, object> k = VaultKey(h, name);
                    Check.True(!MiniJson.Bool(k, "exportable", true), name + " became exportable");
                    Check.True(string.IsNullOrEmpty(MiniJson.Str(k, "hex")) && string.IsNullOrEmpty(MiniJson.Str(k, "privateHex")), name + " shows key bytes in the key list");
                }
                Check.True(MiniJson.Bool(VaultKey(h, "token.issuer"), "exportable", false), "the flow key stopped being exportable");
                Reply key = A17.Key(h, "token.issuer");
                Check.True(key.Ok && !string.IsNullOrEmpty(MiniJson.Str(key.Json, "hex")), "a flow key stopped showing its bytes: " + key);
                return "flow keys are exportable and the exercise keys are not; after another flow run, every exercise call and three more export asks, the policy has not changed and export is refused each time";
            }
        }
    }
}
