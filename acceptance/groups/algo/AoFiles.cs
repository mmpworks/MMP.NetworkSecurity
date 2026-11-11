using System;

namespace Acceptance
{
    /// <summary>AO-7, second half: the golden traces and the lesson tours hold the same bytes as at 5c5d4a4 (PRD non-goal 2).</summary>
    public static class AoFiles
    {
        public const string Base = "5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc";
        public static readonly string[] Paths = { "acceptance/golden", "app/src/tours" };

        static string Git(string root, string args)
        {
            string output;
            int code = Proc.Run("git", "-C \"" + root + "\" " + args, root, 120000, out output);
            if (code != 0) throw new NotRunException("GIT_FAILED", "git " + args + " exited " + code + ": " + output);
            return output.Trim();
        }

        /// <summary>PASS detail, or FailException naming each changed, added or removed file under the paths.</summary>
        public static string Unchanged(string root, string baseCommit, string[] paths)
        {
            string list = string.Join(" ", Array.ConvertAll(paths, delegate (string p) { return "\"" + p + "\""; }));
            string committed = Git(root, "diff --name-status " + baseCommit + " -- " + list);
            string working = Git(root, "status --porcelain --untracked-files=all -- " + list);
            string tracked = Git(root, "ls-files -- " + list);
            int files = tracked.Length == 0 ? 0 : tracked.Split('\n').Length;
            if (committed.Length > 0 || working.Length > 0)
                throw new FailException("AO_FILES_CHANGED", "changed since " + baseCommit.Substring(0, 7) + ": " + (committed + " " + working).Replace('\n', ';').Trim());
            if (files == 0) throw new NotRunException("NO_FILES", "git tracks no file under " + list);
            return files + " tracked files under " + list + " equal " + baseCommit.Substring(0, 7) + ", and the working tree adds or changes none";
        }

        static readonly System.Text.RegularExpressions.Regex Declared = new System.Text.RegularExpressions.Regex(
            @"^\s*(?:(?:public|internal|private|protected|static|readonly|unsafe|override|sealed)\s+)*[\w\[\]<>,]+\s+(?<name>[A-Z_]\w*)\s*\((?<params>[^()]*)\)\s*(?:\{|=>|$)",
            System.Text.RegularExpressions.RegexOptions.Multiline);
        static readonly System.Text.RegularExpressions.Regex Called = new System.Text.RegularExpressions.Regex(@"\b(?<name>[A-Za-z_]\w*)\s*\(");

        /// <summary>
        /// PRD 3 AO-7: the walk keeps its own byte helpers and reaches the word path only through EncryptBlock and DecryptBlock.
        /// Fails on any call in walkFile to a method declared in another AesKey file. Comments are stripped first.
        /// </summary>
        public static string WalkCallsOnlyBlockEntries(string walkFile, string[] otherFiles)
        {
            System.Collections.Generic.Dictionary<string, string> declared = new System.Collections.Generic.Dictionary<string, string>();
            foreach (string f in otherFiles)
                foreach (System.Text.RegularExpressions.Match m in Declared.Matches(StripComments(System.IO.File.ReadAllText(f))))
                    declared[m.Groups["name"].Value] = System.IO.Path.GetFileName(f);
            System.Collections.Generic.Dictionary<string, bool> own = new System.Collections.Generic.Dictionary<string, bool>();
            string walk = StripComments(System.IO.File.ReadAllText(walkFile));
            foreach (System.Text.RegularExpressions.Match m in Declared.Matches(walk)) own[m.Groups["name"].Value] = true;
            System.Collections.Generic.List<string> bad = new System.Collections.Generic.List<string>();
            foreach (System.Text.RegularExpressions.Match m in Called.Matches(walk))
            {
                string n = m.Groups["name"].Value;
                if (n == "EncryptBlock" || n == "DecryptBlock" || n == "AesKey" || own.ContainsKey(n) || !declared.ContainsKey(n)) continue;
                string hit = n + " (" + declared[n] + ")";
                if (!bad.Contains(hit)) bad.Add(hit);
            }
            if (declared.Count == 0) throw new NotRunException("NO_METHODS", "no method declarations read from " + string.Join(", ", otherFiles));
            if (bad.Count > 0) throw new FailException("AO_WALK_CALLS_AESKEY_HELPER", System.IO.Path.GetFileName(walkFile) + " calls " + string.Join(", ", bad.ToArray()));
            return System.IO.Path.GetFileName(walkFile) + " calls no AesKey method other than EncryptBlock and DecryptBlock (" + declared.Count + " methods declared in the other files)";
        }

        static string StripComments(string s)
        {
            s = System.Text.RegularExpressions.Regex.Replace(s, @"/\*(?<body>.*?)\*/", "", System.Text.RegularExpressions.RegexOptions.Singleline);
            return System.Text.RegularExpressions.Regex.Replace(s, @"//(?<rest>[^\n]*)", "");
        }

        [Clause("AO-7.walk-calls-only-block-entries")]
        public static string WalkHelpers(Ctx c)
        {
            string dir = System.IO.Path.Combine(c.RepoRoot, "src", "NetSec.Core", "Crypto");
            string walk = System.IO.Path.Combine(dir, "AesKey.Walk.cs");
            if (!System.IO.File.Exists(walk)) throw new NotRunException("PRODUCT_MISSING", walk + " does not exist");
            System.Collections.Generic.List<string> others = new System.Collections.Generic.List<string>();
            foreach (string f in System.IO.Directory.GetFiles(dir, "AesKey*.cs")) if (!f.EndsWith("AesKey.Walk.cs")) others.Add(f);
            return WalkCallsOnlyBlockEntries(walk, others.ToArray());
        }

        [Clause("AO-7.golden-and-tours-unchanged")]
        public static string GoldenAndTours(Ctx c) { return Unchanged(c.RepoRoot, Base, Paths); }
    }
}
