using System;
using System.Collections.Generic;
using System.IO;

namespace Acceptance
{
    /// <summary>
    /// A17: where the Host keeps .security/ when NETSEC_SECURITY_DIR is not set (SecurityStore.ResolveRoot). Every other suite run sets the variable, so only this clause runs the fallback a learner gets.
    /// The clause copies the built Host into a folder under a stand-in repository, so the run never touches the real .security/. A .git folder and a .git file (a worktree) each mark a repository.
    /// With the variable set, the variable wins and the stand-in repository stays clean. A value written on one start must read back on the next.
    /// </summary>
    public static class SecurityFolderClauses
    {
        const string Variable = "NETSEC_SECURITY_DIR";

        /// <summary>The judge, over files only, so SELF.a17-security-folder-bites can hold it to stand-in trees.</summary>
        public static void JudgeFallback(string repo, string hostDir, string label)
        {
            string modes = Path.Combine(repo, ".security", "modes.json");
            Check.True(File.Exists(modes), label + ": no modes.json at " + modes + ". The Host keeps .security/ beside the .git it found");
            string beside = Path.Combine(hostDir, ".security");
            Check.True(!Directory.Exists(beside), label + ": the Host made .security/ beside its own files, at " + beside + ", with a .git above it");
        }

        public static void JudgeVariableWins(string repo, string chosen, string label)
        {
            Check.True(File.Exists(Path.Combine(chosen, "modes.json")), label + ": no modes.json in the folder " + Variable + " names");
            Check.True(!Directory.Exists(Path.Combine(repo, ".security")), label + ": the Host wrote .security/ in the repository, although " + Variable + " is set");
        }

        static void CopyTree(string from, string to)
        {
            Directory.CreateDirectory(to);
            foreach (string f in Directory.GetFiles(from)) File.Copy(f, Path.Combine(to, Path.GetFileName(f)), true);
            foreach (string d in Directory.GetDirectories(from)) CopyTree(d, Path.Combine(to, Path.GetFileName(d)));
        }

        static Ctx WithHost(Ctx c, string dll, string work)
        {
            Ctx n = new Ctx();
            n.Build = c.Build; n.VectorsDir = c.VectorsDir; n.AcceptanceDir = c.AcceptanceDir; n.RepoRoot = c.RepoRoot; n.WorkDir = work;
            foreach (KeyValuePair<string, string> kv in c.Props) n.Props[kv.Key] = kv.Value;
            n.Props["host"] = dll;
            return n;
        }

        static bool ShowKeysAfterStart(Ctx c, string name, Dictionary<string, string> env, bool? setTo)
        {
            using (HostProc h = HostProc.Start(c, name, env))
            {
                if (setTo.HasValue)
                {
                    Reply put = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", setTo.Value));
                    Check.True(put.Ok, "PUT show-keys got " + put);
                }
                Reply health = HostHttp.Get(h, "/api/health");
                Check.True(health.Ok && health.Json != null, "GET /api/health got " + health);
                return MiniJson.Bool(health.Json, "showKeys", true);
            }
        }

        [Clause("A17.security.fallback-finds-the-repo-folder")]
        public static string FallbackFindsRepoFolder(Ctx c)
        {
            string built = c.Prop("host", "");
            if (built.Length == 0 || !File.Exists(built)) throw new NotRunException("PRODUCT_MISSING", "NetSec.Host is not built (host=" + built + ")");
            string root = Path.Combine(c.WorkDir, "security-fallback");
            if (Directory.Exists(root)) Directory.Delete(root, true);
            Dictionary<string, string> unset = new Dictionary<string, string>();
            unset[Variable] = "";       // ResolveRoot treats an empty value as not set

            foreach (string form in new string[] { "folder", "file" })
            {
                string repo = Path.Combine(root, "repo-" + form), hostDir = Path.Combine(repo, "bin", "host");
                CopyTree(Path.GetDirectoryName(built), hostDir);
                if (form == "folder") Directory.CreateDirectory(Path.Combine(repo, ".git"));
                else File.WriteAllText(Path.Combine(repo, ".git"), "gitdir: elsewhere\n");
                Ctx run = WithHost(c, Path.Combine(hostDir, Path.GetFileName(built)), Path.Combine(root, "work-" + form));
                bool first = ShowKeysAfterStart(run, "first", unset, false);
                Check.True(!first, ".git " + form + ": Show keys did not turn OFF");
                JudgeFallback(repo, hostDir, ".git " + form);
                bool second = ShowKeysAfterStart(run, "second", unset, null);
                Check.True(!second, ".git " + form + ": the second start read Show keys ON, so the setting did not stay in .security/");
            }

            string withVar = Path.Combine(root, "repo-variable"), varHost = Path.Combine(withVar, "bin", "host"), chosen = Path.Combine(root, "chosen");
            CopyTree(Path.GetDirectoryName(built), varHost);
            Directory.CreateDirectory(Path.Combine(withVar, ".git"));
            Directory.CreateDirectory(chosen);
            Dictionary<string, string> set = new Dictionary<string, string>();
            set[Variable] = chosen;
            ShowKeysAfterStart(WithHost(c, Path.Combine(varHost, Path.GetFileName(built)), Path.Combine(root, "work-variable")), "variable", set, false);
            JudgeVariableWins(withVar, chosen, "variable set");
            return "with no " + Variable + ", the Host keeps .security/ beside a .git folder and a .git file, and the setting survives a restart. With it set, the variable wins";
        }
    }
}
