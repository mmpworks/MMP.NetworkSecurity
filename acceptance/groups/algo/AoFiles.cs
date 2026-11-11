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

        [Clause("AO-7.golden-and-tours-unchanged")]
        public static string GoldenAndTours(Ctx c) { return Unchanged(c.RepoRoot, Base, Paths); }
    }
}
