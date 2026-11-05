using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Acceptance
{
    // The practice vault of the fake Host: a real SQLite file (made by fakevault.py) with an audit chain, keys wrapped with AES-256-GCM under vault/master.key
    // (name#version as additional data), labs that read keys through Export with a caller, and the exercise on its four routes (modes-design.md section 4).
    public sealed partial class FakeHost
    {
        sealed class VaultError : Exception
        {
            public readonly string Code;
            public VaultError(string code, string message) : base(message) { Code = code; }
        }

        sealed class VaultKey { public string Name, Algorithm = "ed25519", Provenance = "generated"; public bool Exportable = true; public List<int> Versions = new List<int>(); public string PublicHex; public byte[] Plain; }

        readonly Dictionary<string, VaultKey> _vault = new Dictionary<string, VaultKey>();
        string _vaultScript;
        byte[] _master;
        KeyPair _exerciseSigning;
        string VaultDir { get { return Path.Combine(Dir, "vault"); } }
        string VaultDbPath { get { return Path.Combine(VaultDir, "vault.db"); } }

        void VaultInit(string script)
        {
            _vaultScript = script;
            Directory.CreateDirectory(VaultDir);
            _master = RandomBytes(32);
            File.WriteAllBytes(Path.Combine(VaultDir, "master.key"), _master);
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

        byte[] Aad(string name, int version) { return Encoding.UTF8.GetBytes(name + "#" + version); }

        void Wrap(string name, int version, byte[] plain, out byte[] nonce, out byte[] wrapped)
        {
            nonce = RandomBytes(12);
            byte[] ct = new byte[plain.Length], tag = new byte[16];
            using (AesGcm g = new AesGcm(_master, 16)) g.Encrypt(nonce, plain, ct, tag, Aad(name, version));
            wrapped = Hex.Concat(ct, tag);
        }

        /// <summary>Writes one audit row. False when the insert failed (for instance a trigger that refuses it).</summary>
        bool VaultAudit(string caller, string op, string name, string version, string result, string detail)
        {
            string o;
            return Py(out o, "audit", caller, op, name, version, result, detail.Length == 0 ? "-" : detail) == 0;
        }

        void PutKey(string name, int version, byte[] plain)
        {
            byte[] nonce, wrapped;
            Wrap(name, version, plain, out nonce, out wrapped);
            string o;
            Py(out o, "put", name, version.ToString(), Hex.Encode(wrapped), Hex.Encode(nonce));
        }

        void VaultStore(TypeState t)
        {
            VaultKey k;
            if (!_vault.TryGetValue(t.TypeId, out k))
            {
                k = new VaultKey { Name = t.TypeId, Exportable = true };
                _vault[t.TypeId] = k;
                VaultAudit("wizard", "create", t.TypeId, "-", "ok", "");
            }
            k.Versions.Add(t.Version);
            PutKey(t.TypeId, t.Version, t.Seed);
            VaultAudit("wizard", "generate", t.TypeId, t.Version.ToString(), "ok", "");
            if (t.TypeId == "token.issuer" && t.Key != null) k.PublicHex = t.Key.PublicHex;
        }

        void EnsureExercise()
        {
            _exerciseSigning = NewKey("exercise-signing");
            byte[] derive = RandomBytes(32);
            _vault["exercise/signing"] = new VaultKey { Name = "exercise/signing", Exportable = M("exercise-key-exportable"), Versions = new List<int> { 1 }, PublicHex = _exerciseSigning.PublicHex, Plain = _exerciseSigning.Seed };
            _vault["exercise/derive"] = new VaultKey { Name = "exercise/derive", Algorithm = "hkdf-sha256", Exportable = M("exercise-key-exportable"), Versions = new List<int> { 1 }, Plain = derive };
            PutKey("exercise/signing", 1, _exerciseSigning.Seed);
            PutKey("exercise/derive", 1, derive);
            VaultAudit("exercise", "create", "exercise/signing", "-", "ok", "");
            VaultAudit("exercise", "create", "exercise/derive", "-", "ok", "");
        }

        /// <summary>How a lab gets an exportable key's bytes: Export with a caller. Audited as an export that names who took it.</summary>
        void CourseRead(TypeState t, string caller)
        {
            if (t.Provider != "vault" || !Active(t)) return;
            string o;
            Py(out o, "get", t.TypeId, t.Version.ToString());
            string[] parts = o.Trim().Split(' ');
            bool sound = false;
            if (parts.Length == 2 && parts[0].Length == 24)
            {
                byte[] wrapped = Hex.Decode(parts[1]);
                try
                {
                    byte[] ct = Hex.Slice(wrapped, 0, wrapped.Length - 16), tag = Hex.Slice(wrapped, wrapped.Length - 16, 16), pt = new byte[ct.Length];
                    using (AesGcm g = new AesGcm(_master, 16)) g.Decrypt(Hex.Decode(parts[0]), ct, tag, pt, Aad(t.TypeId, t.Version));
                    sound = Hex.Eq(pt, t.Seed);
                }
                catch (CryptographicException) { sound = false; }
            }
            if (!sound && !M("tamper-ignored"))
            {
                VaultAudit(caller, "export", t.TypeId, t.Version.ToString(), "refused", "VAULT_UNWRAP_FAILED");
                throw new VaultError("VAULT_UNWRAP_FAILED", "the stored row or the master key changed (" + t.TypeId + ")");
            }
            if (M("course-read-unaudited")) return;
            bool wrote = VaultAudit(M("export-caller-missing") ? "host" : caller, M("export-as-course-read") ? "course-read" : "export", t.TypeId, t.Version.ToString(), "ok", "");
            if (!wrote && !M("audit-failure-ignored")) throw new VaultError("VAULT_AUDIT_FAILED", "the audit row for " + t.TypeId + " could not be written, so the call is refused");
        }

        // ------------------------------------------------------------ routes

        Dictionary<string, object> VaultKeyJson(VaultKey k)
        {
            Dictionary<string, object> d = D("name", k.Name, "algorithm", k.Algorithm, "exportable", k.Exportable, "provenance", k.Provenance,
                "versions", new List<object>(k.Versions.ConvertAll(v => (object)(double)v).ToArray()));
            if (k.PublicHex != null) d["publicHex"] = k.PublicHex;
            if (k.Plain != null) d["fingerprint"] = Fingerprint(k.Plain);
            if (!k.Exportable) d["hidden"] = "non-exportable";
            if (!k.Exportable && M("exercise-key-leaks") && k.Plain != null) d["hex"] = Hex.Encode(k.Plain);
            return d;
        }

        List<Dictionary<string, object>> AuditRows()
        {
            string o;
            Py(out o, "rows");
            List<Dictionary<string, object>> rows = new List<Dictionary<string, object>>();
            foreach (object r in (List<object>)MiniJson.Parse(o.Trim())) rows.Add(MiniJson.AsObject(r));
            return rows;
        }

        void ExerciseRoute(HttpListenerContext ctx, string route, Dictionary<string, object> body)
        {
            switch (route)
            {
                case "sign":
                {
                    byte[] input = Encoding.UTF8.GetBytes(MiniJson.Str(body, "text") ?? "");
                    string msg = Path.Combine(Dir, "ex-msg-" + (++_next) + ".bin"), sig = msg + ".sig", pub = msg + ".pub.pem", o;
                    File.WriteAllBytes(msg, input);
                    Proc.Run(_openssl, "pkeyutl -sign -inkey \"" + _exerciseSigning.Pem + "\" -rawin -in \"" + msg + "\" -out \"" + sig + "\"", Dir, 30000, out o);
                    byte[] signature = File.ReadAllBytes(sig);
                    if (M("sign-bad-signature")) signature[0] ^= 0x01;
                    File.WriteAllText(pub, V0Clauses.Ed25519Pem(Hex.Decode(_exerciseSigning.PublicHex)));
                    File.WriteAllBytes(sig, signature);
                    string cmd = "openssl pkeyutl -verify -pubin -inkey exercise-signing.pub -rawin -in input.bin -sigfile signature.bin";
                    Proc.Run(_openssl, "pkeyutl -verify -pubin -inkey \"" + pub + "\" -rawin -in \"" + msg + "\" -sigfile \"" + sig + "\"", Dir, 30000, out o);
                    if (!VaultAudit("exercise", "sign", "exercise/signing", "1", "ok", "")) { Fail(ctx, 409, "VAULT_AUDIT_FAILED", "the audit row could not be written"); return; }
                    Write(ctx, 200, D("keyName", "exercise/signing", "version", 1.0, "inputHex", Hex.Encode(input), "signatureHex", Hex.Encode(signature),
                        "publicKeyHex", _exerciseSigning.PublicHex, "command", cmd, "output", o.Trim(), "code", null));
                    return;
                }
                case "derive":
                {
                    string label = MiniJson.Str(body, "label") ?? "";
                    byte[] key = _vault["exercise/derive"].Plain;
                    byte[] output = HKDF.DeriveKey(HashAlgorithmName.SHA256, key, 32, null, Encoding.UTF8.GetBytes(label));
                    if (M("derive-random")) output = RandomBytes(32);
                    if (!VaultAudit("exercise", "derive", "exercise/derive", "1", "ok", "")) { Fail(ctx, 409, "VAULT_AUDIT_FAILED", "the audit row could not be written"); return; }
                    Write(ctx, 200, D("keyName", "exercise/derive", "version", 1.0, "label", label, "outputHex", Hex.Encode(output), "code", null));
                    return;
                }
                case "export":
                {
                    if (M("export-allowed")) { Write(ctx, 200, D("keyName", "exercise/signing", "hex", Hex.Encode(_exerciseSigning.Seed), "code", null)); return; }
                    if (!M("export-not-audited") && !VaultAudit("exercise", "export", "exercise/signing", "1", "refused", "VAULT_EXPORT_REFUSED")) { Fail(ctx, 409, "VAULT_AUDIT_FAILED", "the audit row could not be written"); return; }
                    Fail(ctx, 409, "VAULT_EXPORT_REFUSED", "this key was made non-exportable, as an HSM key is");
                    return;
                }
                case "audit-check":
                {
                    List<Dictionary<string, object>> rows = AuditRows();
                    double firstBad = 0;
                    for (int i = 1; i < rows.Count && firstBad == 0 && !M("audit-check-blind"); i++)
                    {
                        Dictionary<string, object> p = rows[i - 1];
                        string joined = string.Join("|", new string[] { MiniJson.Num(p, "seq", 0).ToString("0"), MiniJson.Str(p, "at"), MiniJson.Str(p, "caller"), MiniJson.Str(p, "op"), MiniJson.Str(p, "name"), MiniJson.Str(p, "version"), MiniJson.Str(p, "result"), MiniJson.Str(p, "detail"), MiniJson.Str(p, "prev_hash") });
                        if (Sha256Hex(Encoding.UTF8.GetBytes(joined)) != MiniJson.Str(rows[i], "prev_hash")) firstBad = MiniJson.Num(rows[i], "seq", 0);
                    }
                    Write(ctx, 200, D("rows", new List<object>(rows.ToArray()), "firstBadSeq", firstBad, "code", null));
                    return;
                }
            }
            Fail(ctx, 404, "HOST_ROUTE_UNKNOWN", "exercise/" + route);
        }

        partial void Route2Hook(HttpListenerContext ctx, string method, string path, Dictionary<string, object> body, ref bool handled)
        {
            if (path == "/api/security/vault/keys")
            {
                List<object> keys = new List<object>();
                foreach (VaultKey k in _vault.Values) keys.Add(VaultKeyJson(k));
                Write(ctx, 200, D("keys", keys));
                handled = true;
            }
            else if (path == "/api/security/vault/audit")
            {
                double after = double.Parse(ctx.Request.QueryString["after"] ?? "0");
                List<object> rows = new List<object>();
                foreach (Dictionary<string, object> r in AuditRows()) if (MiniJson.Num(r, "seq", 0) > after) rows.Add(r);
                Write(ctx, 200, D("rows", rows));
                handled = true;
            }
            else if (path.StartsWith("/api/security/vault/exercise/") && method == "POST")
            {
                ExerciseRoute(ctx, path.Substring("/api/security/vault/exercise/".Length), body);
                handled = true;
            }
        }
    }
}
