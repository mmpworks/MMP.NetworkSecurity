using System;
using System.Collections.Generic;
using System.IO;

namespace Acceptance
{
    /// <summary>Proof that A17.repo.no-key-tracked bites: a small git repository stands in for the product, with a guard script that is right, or wrong in one way.</summary>
    public static class SelfA17Repo
    {
        // A faithful guard in Python, written to follow modes-design.md section 5.2. The mode argument breaks it in one way.
        static string Guard(string mode)
        {
            if (mode == "always-pass") return "import sys\nsys.exit(0)\n";
            string exempt = mode == "no-golden-exempt" ? "" : " and not (f.startswith('acceptance/golden/') and f.endswith('.ndjson'))";
            string securityRule = mode == "pem-only" ? "" : "    if PATH.search(f)" + exempt + ": bad.append(f + ': forbidden path'); continue\n";
            return @"import re, subprocess, sys
ALLOW = {'src/NetSec.Core/Pki/TrainingPki.cs', 'tests/NetSec.Tests/Tls13Tests.cs', 'acceptance/lib/Harness/OpenSshKey.cs'}
MARK = 'PRIV' + 'ATE KEY'
PATH = re.compile(r'(^|/)\.security/|\.(pfx|p12|db|key|ndjson)$|(^|/)(master\.key|id_rsa|id_ed25519|known_hosts)$', re.I)
files = [f for f in subprocess.run(['git', 'ls-files'], capture_output=True, text=True).stdout.split('\n') if f]
bad = []
for f in files:
" + securityRule + @"    if f in ALLOW: continue
    try: data = open(f, 'rb').read()
    except OSError: continue
    if MARK.encode() in data: bad.append(f + ': PEM private key header')
print('\n'.join(bad))
sys.exit(1 if bad else 0)
";
        }

        static void G(string dir, string args)
        {
            string o;
            if (Proc.Run("git", "-C \"" + dir + "\" " + args, dir, 60000, out o) != 0) throw new FailException("self-test setup: git " + args + ": " + o.Trim());
        }

        /// <summary>A repository with a source file, an ignore file, and a guard of the given kind ("none" writes no guard). Extra edits go in before the commit.</summary>
        static string MakeRepo(Ctx c, string name, string guardMode, bool ignoreLine, Action<string> extra)
        {
            string dir = Path.Combine(c.WorkDir, "repo-" + name);
            Directory.CreateDirectory(dir);
            G(dir, "init --quiet");
            G(dir, "config user.email self@example.invalid");
            G(dir, "config user.name self");
            File.WriteAllText(Path.Combine(dir, ".gitignore"), ignoreLine ? ".security/\n*.pfx\n" : "*.pfx\n");
            Directory.CreateDirectory(Path.Combine(dir, "src"));
            File.WriteAllText(Path.Combine(dir, "src", "x.cs"), "class X {}\n");
            if (guardMode != "none")
            {
                Directory.CreateDirectory(Path.Combine(dir, "tools"));
                File.WriteAllText(Path.Combine(dir, "tools", "secret_guard.py"), Guard(guardMode));
            }
            if (extra != null) extra(dir);
            G(dir, "add -f .");
            G(dir, "commit --quiet -m init");
            return dir;
        }

        static Ctx On(Ctx c, string dir, string tag)
        {
            Ctx n = new Ctx();
            n.Build = "net10"; n.VectorsDir = c.VectorsDir; n.AcceptanceDir = c.AcceptanceDir; n.RepoRoot = dir;
            n.WorkDir = Path.Combine(c.WorkDir, "run-" + tag);
            Directory.CreateDirectory(n.WorkDir);
            return n;
        }

        static string Outcome(Ctx c)
        {
            try { return "PASS: " + RepoClauses.NoKeyTracked(c); }
            catch (NotRunException ex) { return "NOT RUN " + ex.Reason + ": " + ex.Message; }
            catch (FailException ex) { return "FAIL: " + ex.Message; }
        }

        static void Expect(string got, string prefix, string label)
        {
            Check.True(got.StartsWith(prefix), label + ": expected " + prefix + ", gave " + got);
        }

        [Clause("SELF.a17-repo-guard-bites")]
        public static string RepoGuardBites(Ctx c)
        {
            string marker = "-----BEGIN PRIV" + "ATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIV" + "ATE KEY-----\n";
            Expect(Outcome(On(c, MakeRepo(c, "good", "good", true, null), "good")), "PASS", "a clean repository with a sound guard");
            int bites = 0;
            Expect(Outcome(On(c, MakeRepo(c, "pem", "good", true, d => { File.WriteAllText(Path.Combine(d, "src", "leak.pem"), marker); }), "pem")), "FAIL", "a tracked file with a private key header"); bites++;
            Expect(Outcome(On(c, MakeRepo(c, "sec", "good", true, d => { Directory.CreateDirectory(Path.Combine(d, ".security")); File.WriteAllText(Path.Combine(d, ".security", "modes.json"), "{}"); }), "sec")), "FAIL", "a tracked .security/ file"); bites++;
            Expect(Outcome(On(c, MakeRepo(c, "db", "good", true, d => { File.WriteAllText(Path.Combine(d, "src", "vault.db"), "x"); }), "db")), "FAIL", "a tracked .db file"); bites++;
            Expect(Outcome(On(c, MakeRepo(c, "noignore", "good", false, null), "noignore")), "FAIL", "a .gitignore with no .security/ line, beside a guard"); bites++;
            Expect(Outcome(On(c, MakeRepo(c, "unstarted", "none", false, null), "unstarted")), "NOT RUN PRODUCT_MISSING", "a product that has not started the .security/ folder");
            Expect(Outcome(On(c, MakeRepo(c, "alwayspass", "always-pass", true, null), "alwayspass")), "FAIL", "a guard that passes everything"); bites++;
            Expect(Outcome(On(c, MakeRepo(c, "pemonly", "pem-only", true, null), "pemonly")), "FAIL", "a guard that ignores .security/"); bites++;
            Action<string> golden = d => { Directory.CreateDirectory(Path.Combine(d, "acceptance", "golden", "net10")); File.WriteAllText(Path.Combine(d, "acceptance", "golden", "net10", "lab-00.ndjson"), "{}\n"); };
            Expect(Outcome(On(c, MakeRepo(c, "golden", "good", true, golden), "golden")), "PASS", "tracked golden traces under acceptance/golden/");
            Expect(Outcome(On(c, MakeRepo(c, "goldenguard", "no-golden-exempt", true, golden), "goldenguard")), "FAIL", "a guard that flags the golden traces"); bites++;
            Expect(Outcome(On(c, MakeRepo(c, "ndjson", "good", true, d => { File.WriteAllText(Path.Combine(d, "src", "session.ndjson"), "{}\n"); }), "ndjson")), "FAIL", "a tracked .ndjson outside acceptance/golden/"); bites++;
            Expect(Outcome(On(c, MakeRepo(c, "goldenkey", "good", true, d => { golden(d); File.WriteAllText(Path.Combine(d, "acceptance", "golden", "net10", "host.key"), "x"); }), "goldenkey")), "FAIL", "a tracked .key under acceptance/golden/"); bites++;
            Expect(Outcome(On(c, MakeRepo(c, "noguard", "none", true, null), "noguard")), "NOT RUN PRODUCT_MISSING", "no tools/secret_guard.py");
            string nogit = Path.Combine(c.WorkDir, "repo-nogit");
            Directory.CreateDirectory(nogit);
            Expect(Outcome(On(c, nogit, "nogit")), "NOT RUN PRODUCT_MISSING", "a folder that is no git repository");
            return "a clean repository with a sound guard PASSes; " + bites + " defects (tracked key header, tracked .security/ file, tracked .db, no ignore line, a guard that passes all, a guard that ignores .security/, a guard that flags the golden traces, a tracked .ndjson outside the golden folder, a tracked .key inside it) each FAIL; the golden traces alone PASS; no guard or no git reads NOT RUN PRODUCT_MISSING";
        }
    }
}
