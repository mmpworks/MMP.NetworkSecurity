using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// A17.cold.lesson-10-fresh-clone: the kill condition's human half (modes-design.md section 9.1, "Kill condition"). A cold reader runs lesson 10 on their own
    /// test keys from a fresh clone. This clause does not pretend to be that reader. It reads the reader's verdict file and checks every part of it that a
    /// program can check: a Go referee verifies the token the reader's run produced under the public key of the reader's own key, the key is
    /// not the built-in one, the reading grade of the words the reader saw passes, and the reader is named and is not a builder.
    /// Until the file exists the clause reads NOT RUN COLD_READER_PENDING. The product's word "Verified" never counts.
    /// File: docs/_verdicts/cold-reader-lesson-10.json. Shape in acceptance/CONTRACT.md.
    /// </summary>
    public static class ColdClauses
    {
        public const string VerdictFile = "cold-reader-lesson-10.json";
        const string Issuer = "https://pump.training/issuer", Audience = "https://pump.training/api";
        static readonly string[] Builders = new string[] { "echo", "richard", "jared", "nancy", "heather", "max", "glenn", "kody", "iolo", "rosanne", "tom", "laura", "claude", "codex", "builder" };

        static byte[] B64Url(string s)
        {
            string t = s.Replace('-', '+').Replace('_', '/');
            while (t.Length % 4 != 0) t += "=";
            return Convert.FromBase64String(t);
        }

        [Clause("A17.cold.lesson-10-fresh-clone")]
        public static string ColdLesson10(Ctx c)
        {
            string path = Path.Combine(c.RepoRoot, "docs", "_verdicts", VerdictFile);
            if (!File.Exists(path))
                throw new NotRunException("COLD_READER_PENDING", "no cold reader has run lesson 10 on their own test keys from a fresh clone yet: " + path + " does not exist. The clause reads NOT RUN until a named reader files it");
            Dictionary<string, object> v = MiniJson.AsObject(MiniJson.Parse(File.ReadAllText(path)));
            Dictionary<string, object> reader = MiniJson.Obj(v, "reader"), clone = MiniJson.Obj(v, "clone"), run = MiniJson.Obj(v, "run"), keys = MiniJson.Obj(v, "keys");

            // 1. A named reader who is not a builder.
            string name = (MiniJson.Str(reader, "name") ?? "").Trim(), kind = MiniJson.Str(reader, "kind");
            Check.True(name.Length > 0, "the verdict names no reader");
            foreach (string b in Builders) Check.True(name.IndexOf(b, StringComparison.OrdinalIgnoreCase) < 0, "the reader '" + name + "' is a builder of this plan, not a cold reader");
            Check.True(kind == "human" || kind == "agent", "reader.kind is '" + kind + "'; expected human or agent");
            if (kind == "agent") Check.True(MiniJson.Bool(reader, "freshContext", false), "an agent reader must say freshContext true: it read only the repository, with no memory of building it");
            Check.True(MiniJson.Bool(v, "understoodWithoutHelp", false), "the reader did not report that they got through lesson 10 on their own keys without help");

            // 2. A fresh clone at a real commit.
            Check.True(MiniJson.Bool(clone, "fresh", false), "clone.fresh is not true");
            string commit = (MiniJson.Str(clone, "commit") ?? "").Trim().ToLowerInvariant();
            Check.True(System.Text.RegularExpressions.Regex.IsMatch(commit, "^[0-9a-f]{40}$"), "clone.commit '" + commit + "' is no 40-character commit hash");
            string o;
            if (Directory.Exists(Path.Combine(c.RepoRoot, ".git")) || File.Exists(Path.Combine(c.RepoRoot, ".git")))
                Check.True(Proc.Run("git", "-C \"" + c.RepoRoot + "\" cat-file -e " + commit + "^{commit}", c.RepoRoot, 30000, out o) == 0, "clone.commit " + commit + " is not a commit of this repository");

            // 3. The reader's own key made the token. A Go referee, from acceptance/, verifies it.
            string pubHex = (MiniJson.Str(keys, "issuerPublicHex") ?? "").Trim().ToLowerInvariant();
            Check.True(pubHex.Length == 64, "keys.issuerPublicHex is not 32 bytes of hex");
            string token = (MiniJson.Str(run, "token") ?? "").Trim();
            Check.Equal("lesson of the run", 10.0, MiniJson.Num(run, "lesson", 0));
            string[] parts = token.Split('.');
            Check.True(parts.Length == 3, "run.token is not a compact JWS");
            Dictionary<string, object> claims = MiniJson.AsObject(MiniJson.Parse(Encoding.UTF8.GetString(B64Url(parts[1]))));
            Check.Equal("iss of the token", Issuer, MiniJson.Str(claims, "iss"));
            Check.Equal("aud of the token", Audience, MiniJson.Str(claims, "aud"));
            string verify = Referees.GoTool(c, "tokenverify");
            string dir = A17.TempDir(c, "cold");
            string pubPem = Path.Combine(dir, "reader-issuer.pub.pem");
            File.WriteAllText(pubPem, V0Clauses.Ed25519Pem(Hex.Decode(pubHex)));
            Proc.Run(verify, "-pub \"" + pubPem + "\" -token " + token, dir, 30000, out o);
            Check.True(o.Contains("TOKEN_OK"), "tokenverify does not accept the reader's token under the reader's public key: " + o.Trim());

            // 4. It really is not the built-in key. A built-in lesson 10 run on this Host shows the built-in issuer public key.
            using (HostProc h = A17.Host(c, "a17-cold"))
            {
                SessionRun builtin = HostSession.Run(h, 10, "glass", null);
                if (builtin.ErrorCode == "LESSON_NOT_BUILT") throw new NotRunException("LESSON_NOT_BUILT", "the Host reports lesson 10 as not built yet");
                string builtinPub = null;
                foreach (A17.SecretRef s in A17.Secrets(builtin)) if (s.Name == "auth.issuer-public") builtinPub = s.Hex.ToLowerInvariant();
                Check.True(builtinPub != null, "a built-in run of lesson 10 shows no auth.issuer-public to compare with");
                Check.True(builtinPub != pubHex, "the reader's issuer key is the built-in one, so the reader ran on built-in keys");
            }

            // 5. Paired with the reading grade: the words the reader saw must read at the limit or lower.
            string script = Path.Combine(c.AcceptanceDir, "checks", "docs_checks.py");
            Proc.Run("python", "-I \"" + script + "\" --root \"" + c.RepoRoot + "\" --ids A15.tours.reading-grade,A17.copy.grade-and-tics", c.AcceptanceDir, 120000, out o);
            foreach (string line in o.Split('\n'))
            {
                if (!line.StartsWith("@@CLAUSE ")) continue;
                Dictionary<string, object> d = MiniJson.AsObject(MiniJson.Parse(line.Substring(9)));
                string status = MiniJson.Str(d, "status");
                if (status == "NOT RUN") throw new NotRunException(MiniJson.Str(d, "reason"), "the reading grade that pairs with the cold read could not run: " + MiniJson.Str(d, "detail"));
                Check.True(status == "PASS", "the reading grade that pairs with the cold read failed: " + MiniJson.Str(d, "id") + " " + MiniJson.Str(d, "detail"));
            }
            return "reader " + name + " (" + kind + ") ran lesson 10 on their own keys from a fresh clone at " + commit.Substring(0, 8) + "; tokenverify accepts the token under their public key, the key is not the built-in one, and the reading grade of the words passes";
        }
    }
}
