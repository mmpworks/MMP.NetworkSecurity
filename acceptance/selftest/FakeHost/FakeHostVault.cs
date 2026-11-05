using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Acceptance
{
    // The practice vault of the fake Host: a real SQLite file (made by fakevault.py) with an audit chain, plus the exercise lab 20.
    public sealed partial class FakeHost
    {
        sealed class VaultError : Exception
        {
            public readonly string Code;
            public VaultError(string code, string message) : base(message) { Code = code; }
        }

        sealed class VaultKey { public string Name, Algorithm = "ed25519", Provenance = "generated"; public bool Exportable = true; public List<int> Versions = new List<int>(); public string PublicHex; }

        readonly Dictionary<string, VaultKey> _vault = new Dictionary<string, VaultKey>();
        string _vaultScript;
        string VaultDbPath { get { return Path.Combine(Dir, "vault", "vault.db"); } }

        void VaultInit(string script)
        {
            _vaultScript = script;
            string o;
            if (Py(out o, "init") != 0) throw new InvalidOperationException("fake: vault init failed: " + o);
        }

        int Py(out string output, params string[] args)
        {
            StringBuilder sb = new StringBuilder("-I \"" + _vaultScript + "\" \"" + VaultDbPath + "\"");
            foreach (string a in args) sb.Append(" \"").Append(a.Replace("\"", "'")).Append('"');
            return Proc.Run("python", sb.ToString(), Dir, 60000, out output);
        }

        static string Sha256Hex(byte[] b) { using (SHA256 sha = SHA256.Create()) return Hex.Encode(sha.ComputeHash(b)); }

        /// <summary>Writes one audit row. False when the insert failed (for instance a trigger that refuses it).</summary>
        bool VaultAudit(string caller, string op, string name, string version, string result, string detail)
        {
            string o;
            return Py(out o, "audit", caller, op, name, version, result, detail.Length == 0 ? "-" : detail) == 0;
        }

        void VaultStore(TypeState t, bool hidden)
        {
            VaultKey k;
            if (!_vault.TryGetValue(t.TypeId, out k))
            {
                k = new VaultKey { Name = t.TypeId, Exportable = !hidden };
                _vault[t.TypeId] = k;
                VaultAudit("wizard", "create", t.TypeId, "-", "ok", "");
            }
            if (M("exportable-flips")) k.Exportable = !hidden;
            k.Versions.Add(t.Version);
            string o;
            Py(out o, "put", t.TypeId, t.Version.ToString(), Sha256Hex(t.Seed));
            VaultAudit("wizard", "generate", t.TypeId, t.Version.ToString(), "ok", "");
            if (t.TypeId == "token.issuer" && t.Key != null) k.PublicHex = t.Key.PublicHex;
        }

        /// <summary>How a lab (or the security page) gets a vault key's bytes. Always works for a sound key, and is audited as a course read, never an export.</summary>
        void CourseRead(TypeState t, string caller)
        {
            if (t.Provider != "vault" || !Active(t)) return;
            string o;
            Py(out o, "get", t.TypeId, t.Version.ToString());
            if (o.Trim() != Sha256Hex(t.Seed) && !M("tamper-ignored"))
            {
                VaultAudit(caller, "course-read", t.TypeId, t.Version.ToString(), "refused", "VAULT_UNWRAP_FAILED");
                throw new VaultError("VAULT_UNWRAP_FAILED", "the stored row or the master key changed (" + t.TypeId + ")");
            }
            if (M("course-read-unaudited")) return;
            bool wrote = VaultAudit(caller, M("course-read-as-export") ? "export" : "course-read", t.TypeId, t.Version.ToString(), "ok", "");
            if (!wrote && !M("audit-failure-ignored")) throw new VaultError("VAULT_AUDIT_FAILED", "the audit row for " + t.TypeId + " could not be written, so the call is refused");
        }

        // ------------------------------------------------------------ routes

        partial void Route2Hook(HttpListenerContext ctx, string method, string path, Dictionary<string, object> body, ref bool handled)
        {
            if (path == "/api/security/vault/keys")
            {
                List<object> keys = new List<object>();
                foreach (VaultKey k in _vault.Values)
                {
                    Dictionary<string, object> d = D("name", k.Name, "algorithm", k.Algorithm, "exportable", k.Exportable, "provenance", k.Provenance,
                        "versions", new List<object>(k.Versions.ConvertAll(v => (object)(double)v).ToArray()));
                    if (k.PublicHex != null) d["publicHex"] = k.PublicHex;
                    keys.Add(d);
                }
                Write(ctx, 200, D("keys", keys));
                handled = true;
            }
            else if (path == "/api/security/vault/audit")
            {
                string o;
                Py(out o, "rows");
                double after = double.Parse(ctx.Request.QueryString["after"] ?? "0");
                List<object> rows = new List<object>();
                foreach (object r in (List<object>)MiniJson.Parse(o.Trim()))
                    if (MiniJson.Num(MiniJson.AsObject(r), "seq", 0) > after) rows.Add(r);
                Write(ctx, 200, D("rows", rows));
                handled = true;
            }
        }

        // ------------------------------------------------------------ the exercise, lab 20

        KeyPair _exerciseKey;

        void BuildExercise(Session s)
        {
            if (_exerciseKey == null)
            {
                _exerciseKey = NewKey("exercise-signing");
                _vault["exercise/signing"] = new VaultKey { Name = "exercise/signing", Exportable = false, Versions = new List<int> { 1 }, PublicHex = _exerciseKey.PublicHex };
                _vault["exercise/bdk"] = new VaultKey { Name = "exercise/bdk", Algorithm = "aes-128", Exportable = false, Versions = new List<int> { 1 } };
                VaultAudit("exercise", "create", "exercise/signing", "-", "ok", "");
                VaultAudit("exercise", "create", "exercise/bdk", "-", "ok", "");
            }
            byte[] input = RandomBytes(32), ksn = RandomBytes(10);
            string msg = Path.Combine(Dir, "ex-msg-" + (++_next) + ".bin"), sig = msg + ".sig", o;
            File.WriteAllBytes(msg, input);
            Proc.Run(_openssl, "pkeyutl -sign -inkey \"" + _exerciseKey.Pem + "\" -rawin -in \"" + msg + "\" -out \"" + sig + "\"", Dir, 30000, out o);
            byte[] signature = File.ReadAllBytes(sig);
            if (M("sign-bad-signature")) signature = RandomBytes(64);
            VaultAudit("exercise", "sign", "exercise/signing", "1", "ok", "");
            VaultAudit("exercise", "derive", "exercise/bdk", "1", "ok", "");
            if (!M("export-not-audited")) VaultAudit("exercise", "export", "exercise/signing", "1", "refused", "VAULT_EXPORT_REFUSED");

            List<SessionEv> evs = new List<SessionEv>();
            SessionEv sign = new SessionEv { Base = D("type", "vault.sign", "name", "exercise/signing", "version", 1.0, "inputHash", Sha256Hex(input), "inputHex", Hex.Encode(input), "signatureHex", Hex.Encode(signature)) };
            SessionEv derive = new SessionEv { Base = D("type", "vault.derive", "name", "exercise/bdk", "version", 1.0, "ksn", Hex.Encode(ksn)) };
            SessionEv refused = M("export-allowed")
                ? new SessionEv { Base = D("type", "vault.exported", "name", "exercise/signing") }
                : new SessionEv { Base = D("type", "vault.refused", "name", "exercise/signing", "code", "VAULT_EXPORT_REFUSED") };
            Py(out o, "rows");
            SessionEv audit = new SessionEv { Base = D("type", "vault.audit", "rows", MiniJson.Parse(o.Trim())) };
            if (M("walk-order-wrong")) { evs.Add(derive); evs.Add(sign); } else { evs.Add(sign); evs.Add(derive); }
            evs.Add(refused); evs.Add(audit);
            int n = 0;
            foreach (SessionEv e in evs) { n++; e.Base["eventId"] = "e" + n; e.Base["streamId"] = s.Id + "/vault"; e.Base["streamSeq"] = (double)n; s.Events.Add(e); }
        }
    }
}
