using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Acceptance
{
    /// <summary>
    /// A17.repo.no-key-tracked (modes-design.md section 5.2). A git hook would not travel with a clone and can be skipped. A clause cannot.
    /// Leg A is the suite's own scan of what git tracks, so it needs no product tool. Leg B runs the product's tools/secret_guard.py on a temp clone,
    /// beside a control: a planted private key file and a planted .security/ file must each fail by name, and the unchanged clone must pass.
    /// The words of a PEM private key header are put together at run time, so no file of the suite holds them as one literal.
    /// </summary>
    public static class RepoClauses
    {
        // The three files that hold a PEM header today (modes-design.md section 5.2).
        static readonly string[] PemAllowList = new string[]
        {
            "src/NetSec.Core/Pki/TrainingPki.cs", "tests/NetSec.Tests/Tls13Tests.cs", "acceptance/lib/Harness/OpenSshKey.cs"
        };

        static readonly Regex ForbiddenPath = new Regex(@"(^|/)\.security/|\.(pfx|p12|db|key|ndjson|bin)$|(^|/)(master\.key|id_rsa|id_ed25519|known_hosts)$", RegexOptions.IgnoreCase);

        /// <summary>
        /// The golden traces (acceptance/golden/**/*.ndjson) are tracked on purpose. They hold only the built-in training keys, which are public by design.
        /// Only the .ndjson rule is lifted for them: any other forbidden name under that folder, and the PEM scan, still apply.
        /// </summary>
        static bool IsGoldenTrace(string path)
        {
            return path.StartsWith("acceptance/golden/", StringComparison.Ordinal) && path.EndsWith(".ndjson", StringComparison.OrdinalIgnoreCase);
        }

        static string Marker { get { return "PRIV" + "ATE KEY"; } }

        // A PEM block of key material: the header line, a body of base64, and the footer. A sentence that names the header (a document, a test message)
        // has no body and no footer, so it is no key. The words are put together here so this file holds no header itself.
        static readonly Regex PemBlock = new Regex("-----BEGIN [A-Z ]*" + "PRIV" + "ATE KEY-----[A-Za-z0-9+/=\\s]{16,}?-----END [A-Z ]*" + "PRIV" + "ATE KEY-----", RegexOptions.Singleline);

        static string Git(string dir, string args)
        {
            string o;
            int code = Proc.Run("git", "-C \"" + dir + "\" " + args, dir, 120000, out o);
            if (code != 0) throw new FailException("git " + args + " exited " + code + ": " + o.Trim());
            return o;
        }

        static List<string> Tracked(string root)
        {
            List<string> files = new List<string>();
            foreach (string line in Git(root, "ls-files").Split('\n'))
                if (line.Trim().Length > 0) files.Add(line.Trim().Replace('\\', '/'));
            return files;
        }

        /// <summary>The problems found in the tracked files and the ignore rule of one repository, by the suite's own rules.</summary>
        public static List<string> Scan(string root, out string ignoreProblem)
        {
            ignoreProblem = null;
            List<string> problems = new List<string>();
            List<string> files = Tracked(root);
            foreach (string f in files)
            {
                if (ForbiddenPath.IsMatch(f) && !IsGoldenTrace(f)) { problems.Add(f + ": a path that holds keys or session data is tracked"); continue; }
                if (Array.IndexOf(PemAllowList, f) >= 0) continue;
                string full = Path.Combine(root, f.Replace('/', Path.DirectorySeparatorChar));
                FileInfo fi = new FileInfo(full);
                if (!fi.Exists || fi.Length > 8 * 1024 * 1024) continue;
                if (PemBlock.IsMatch(Encoding.GetEncoding("iso-8859-1").GetString(File.ReadAllBytes(full)))) problems.Add(f + ": holds a PEM private key block and is not on the allow-list");
            }
            string ignore = Path.Combine(root, ".gitignore");
            if (!File.Exists(ignore) || !Regex.IsMatch(File.ReadAllText(ignore), @"(?m)^\s*/?\.security/?\s*$"))
                ignoreProblem = ".gitignore has no .security/ line";
            else
            {
                string o;
                int code = Proc.Run("git", "-C \"" + root + "\" check-ignore -q .security/x", root, 30000, out o);
                if (code != 0) ignoreProblem = "git does not ignore .security/x although .gitignore has the line";
            }
            return problems;
        }

        static int IndexOf(byte[] hay, byte[] needle)
        {
            for (int i = 0; i + needle.Length <= hay.Length; i++)
            {
                int j = 0;
                while (j < needle.Length && hay[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        static void CloneTo(string root, string dest)
        {
            if (Directory.Exists(dest)) throw new FailException("the clone folder " + dest + " exists; each run needs its own");
            string o;
            if (Proc.Run("git", "clone --quiet --local --no-hardlinks \"" + root + "\" \"" + dest + "\"", root, 120000, out o) != 0) throw new FailException("git clone failed: " + o.Trim());
            Proc.Run("git", "-C \"" + dest + "\" config user.email acceptance@example.invalid", dest, 30000, out o);
            Proc.Run("git", "-C \"" + dest + "\" config user.name acceptance", dest, 30000, out o);
        }

        static int RunGuard(string cloneDir, out string output)
        {
            return Proc.Run("python", "-I tools/secret_guard.py", cloneDir, 120000, out output);
        }

        [Clause("A17.repo.no-key-tracked")]
        public static string NoKeyTracked(Ctx c)
        {
            string root = c.RepoRoot;
            if (!Directory.Exists(Path.Combine(root, ".git")) && !File.Exists(Path.Combine(root, ".git"))) throw new NotRunException("PRODUCT_MISSING", root + " is no git repository");
            // Leg A: the suite's own scan.
            string ignoreProblem;
            List<string> problems = Scan(root, out ignoreProblem);
            Check.True(problems.Count == 0, "the repository tracks a key or session file: " + string.Join("; ", problems.ToArray(), 0, Math.Min(4, problems.Count)));
            bool guardExists = File.Exists(Path.Combine(root, "tools", "secret_guard.py"));
            if (ignoreProblem != null)
            {
                // Before the product starts the .security/ folder there is nothing to ignore and no guard: the feature is not built. After either exists, the line is required.
                if (!guardExists && !Directory.Exists(Path.Combine(root, ".security")))
                    throw new NotRunException("PRODUCT_MISSING", "the product has not started the .security/ folder yet: " + ignoreProblem + ", and tools/secret_guard.py does not exist. Leg A found no key or session file among " + Tracked(root).Count + " tracked files");
                Check.True(false, ignoreProblem);
            }

            // Leg B: the product's guard, run on a clone, beside its control.
            string guard = Path.Combine(root, "tools", "secret_guard.py");
            if (!File.Exists(guard)) throw new NotRunException("PRODUCT_MISSING", "tools/secret_guard.py does not exist yet. Leg A found nothing tracked: " + Tracked(root).Count + " files scanned");
            string work = Path.Combine(c.WorkDir, "a17-repo");
            Directory.CreateDirectory(work);
            string unchanged = Path.Combine(work, "clone-unchanged"), pem = Path.Combine(work, "clone-pem"), sec = Path.Combine(work, "clone-security"), o;

            CloneTo(root, unchanged);
            File.Copy(guard, Path.Combine(unchanged, "tools", "secret_guard.py"), true);               // test the script as it stands in the working tree
            int clean = RunGuard(unchanged, out o);
            Check.True(clean == 0, "tools/secret_guard.py fails the unchanged clone (exit " + clean + "): " + o.Trim());

            CloneTo(root, pem);
            File.Copy(guard, Path.Combine(pem, "tools", "secret_guard.py"), true);
            Directory.CreateDirectory(Path.Combine(pem, "planted"));
            File.WriteAllText(Path.Combine(pem, "planted", "leak.pem"), "-----BEGIN " + Marker + "-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END " + Marker + "-----\n");
            Git(pem, "add planted/leak.pem");
            int rp = RunGuard(pem, out o);
            Check.True(rp != 0, "tools/secret_guard.py passes a clone with a private key file planted at planted/leak.pem");
            Check.True(o.Replace('\\', '/').Contains("planted/leak.pem"), "tools/secret_guard.py fails the planted key but does not name planted/leak.pem: " + o.Trim());

            CloneTo(root, sec);
            File.Copy(guard, Path.Combine(sec, "tools", "secret_guard.py"), true);
            Directory.CreateDirectory(Path.Combine(sec, ".security"));
            File.WriteAllText(Path.Combine(sec, ".security", "modes.json"), "{\"showKeys\":true}");
            Git(sec, "add -f .security/modes.json");
            int rs = RunGuard(sec, out o);
            Check.True(rs != 0, "tools/secret_guard.py passes a clone with a .security/ file staged");
            Check.True(o.Replace('\\', '/').Contains(".security/modes.json"), "tools/secret_guard.py fails the staged .security/ file but does not name .security/modes.json: " + o.Trim());
            return "no key or session file is tracked (" + Tracked(root).Count + " files, 3 allow-listed PEM files); tools/secret_guard.py passes the unchanged clone and fails a planted key file and a staged .security/ file, each by name";
        }
    }
}
