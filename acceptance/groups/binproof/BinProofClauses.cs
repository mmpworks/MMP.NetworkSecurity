using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace Acceptance
{
    /// <summary>
    /// A9: the shared code compiles against the Compact Framework 3.5 reference assemblies with LangVersion 3; each CF binary
    /// references the CF mscorlib key token; the same suite passes with CF binaries on net48, with skips matching the pinned list;
    /// git tracks no CF binary. The binaries are read from outside, with System.Reflection.Metadata, never through the code under test.
    /// </summary>
    public static class BinProofClauses
    {
        const string CfMscorlibToken = "969db8053d3322ac";

        static string RefDir(Ctx c)
        {
            string d = c.Prop("netcf", @"E:\dev\tools\netcf35-ref");
            if (!File.Exists(Path.Combine(d, "mscorlib.dll"))) throw new NotRunException("CF_REFERENCES_MISSING", "CF 3.5 reference assemblies not found at " + d);
            return d;
        }

        /// <summary>Public key token of the mscorlib reference of a managed binary, or null when it references no mscorlib.</summary>
        public static string MscorlibToken(string path, out string assemblyName)
        {
            using (FileStream fs = File.OpenRead(path))
            using (PEReader pe = new PEReader(fs))
            {
                MetadataReader r = pe.GetMetadataReader();
                assemblyName = r.GetString(r.GetAssemblyDefinition().Name);
                foreach (AssemblyReferenceHandle h in r.AssemblyReferences)
                {
                    AssemblyReference ar = r.GetAssemblyReference(h);
                    if (r.GetString(ar.Name) == "mscorlib")
                    {
                        byte[] tok = r.GetBlobBytes(ar.PublicKeyOrToken);
                        return Hex.Encode(tok);
                    }
                }
                return null;
            }
        }

        public static bool IsManaged(string path)
        {
            try { using (FileStream fs = File.OpenRead(path)) using (PEReader pe = new PEReader(fs)) return pe.HasMetadata; }
            catch (Exception) { return false; }
        }

        static string Run(string exe, string args, string dir, int ms, out int code)
        {
            string output;
            code = Proc.Run(exe, args, dir, ms, out output);
            return output;
        }

        static string Tail(string s) { s = s.Trim(); return s.Length > 700 ? s.Substring(s.Length - 700) : s; }

        // ---------------------------------------------------------------- compile

        [Clause("A9.cf.compiles-against-reference-assemblies-with-langversion-3")]
        public static string Compiles(Ctx c)
        {
            c.RequireProduct();
            string refDir = RefDir(c);
            string coreCf = Path.Combine(c.RepoRoot, "src", "NetSec.Core.NetCF", "NetSec.Core.NetCF.csproj");
            string core = Path.Combine(c.RepoRoot, "src", "NetSec.Core", "NetSec.Core.csproj");
            if (!File.Exists(coreCf) || !File.Exists(core)) throw new NotRunException("PRODUCT_MISSING", "src/NetSec.Core and src/NetSec.Core.NetCF are not in the repo yet (slice S0)");
            foreach (string proj in new string[] { core, coreCf })
            {
                string lang = (string)XDocument.Load(proj).Descendants("LangVersion").Select(delegate (XElement e) { return e.Value.Trim(); }).FirstOrDefault();
                Check.Equal(Path.GetFileName(proj) + " LangVersion", "3", lang);
            }
            int code;
            string output = Run("dotnet", "build \"" + coreCf + "\" -c Release -p:NetCFRefDir=\"" + refDir + "\" --no-incremental -v q", c.RepoRoot, 600000, out code);
            Check.True(code == 0, "dotnet build of the CF project exited " + code + ": " + Tail(output));
            string dll = Path.Combine(c.RepoRoot, "src", "NetSec.Core.NetCF", "bin", "Release", "net35", "NetSec.Core.dll");
            Check.True(File.Exists(dll), "the CF build wrote no NetSec.Core.dll at " + dll);
            string name;
            string token = MscorlibToken(dll, out name);
            Check.Equal("assembly name of the CF build (one name for both builds, D1)", "NetSec.Core", name);
            Check.Equal("mscorlib token of the CF build", CfMscorlibToken, token);
            return "src/NetSec.Core and src/NetSec.Core.NetCF use LangVersion 3; the CF project builds against " + refDir;
        }

        // ---------------------------------------------------------------- binary proof

        [Clause("A9.cf.binaries-reference-cf-mscorlib")]
        public static string BinariesReferenceCfMscorlib(Ctx c)
        {
            c.RequireProduct();
            string[] cfBinaries = new string[]
            {
                Path.Combine(c.RepoRoot, "src", "NetSec.Core.NetCF", "bin", "Release", "net35", "NetSec.Core.dll"),
                Path.Combine(c.RepoRoot, "src", "NetSec.CeDevice", "bin", "Release", "net35", "NetSec.CeDevice.exe"),
                c.Prop("asyncproxy.cf", @"E:\dev\MMP.AsyncProxy\src\MMP.AsyncProxy.NetCF\bin\Release\net35\MMP.AsyncProxy.dll")
            };
            Tally t = new Tally();
            foreach (string f in cfBinaries)
            {
                if (!File.Exists(f)) throw new NotRunException("PRODUCT_MISSING", f + " is not built yet");
                string name;
                string tok = MscorlibToken(f, out name);
                t.Expect(Path.GetFileName(f), tok == CfMscorlibToken, "mscorlib token is " + (tok ?? "<no mscorlib reference>") + ", expected " + CfMscorlibToken);
            }
            // Control: the .NET 10 build must NOT carry the CF token, so the check tells the two builds apart.
            string net10 = Path.Combine(c.RepoRoot, "src", "NetSec.Core", "bin", "Release", "net10.0", "NetSec.Core.dll");
            if (File.Exists(net10))
            {
                string n2;
                string tok = MscorlibToken(net10, out n2);
                t.Expect("control: the net10.0 build", tok != CfMscorlibToken, "the net10.0 build also carries the CF mscorlib token; the check cannot tell the builds apart");
            }
            return t.Done();
        }

        // ---------------------------------------------------------------- the same suite on net48, skips pinned

        sealed class TrxResult
        {
            public HashSet<string> Passed = new HashSet<string>(), Failed = new HashSet<string>(), Skipped = new HashSet<string>();
            public string Output;
        }

        static TrxResult RunSuite(Ctx c, string framework, string dirTag)
        {
            string tests = Path.Combine(c.RepoRoot, "tests", "NetSec.Tests", "NetSec.Tests.csproj");
            if (!File.Exists(tests)) throw new NotRunException("PRODUCT_MISSING", "tests/NetSec.Tests does not exist yet");
            string trxDir = Path.Combine(c.WorkDir, "trx-" + dirTag);
            Directory.CreateDirectory(trxDir);
            int code;
            string output = Run("dotnet", "test \"" + tests + "\" -c Release -f " + framework + " -p:NetCFRefDir=\"" + RefDir(c) + "\" --logger \"trx;LogFileName=" + dirTag + ".trx\" --results-directory \"" + trxDir + "\" --blame-hang-timeout 3m --blame-hang-dump-type none", c.RepoRoot, 1800000, out code);   // a test that hangs ends the run after 3 minutes and is named
            string[] files = Directory.GetFiles(trxDir, "*.trx");
            if (files.Length == 0) throw new FailException("dotnet test (" + framework + ") wrote no TRX file (exit " + code + "): " + Tail(output));
            XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
            TrxResult r = new TrxResult();
            r.Output = output;
            foreach (XElement u in XDocument.Load(files[0]).Descendants(ns + "UnitTestResult"))
            {
                string name = (string)u.Attribute("testName"), outcome = (string)u.Attribute("outcome");
                if (outcome == "Passed") r.Passed.Add(name);
                else if (outcome == "NotExecuted") r.Skipped.Add(name);
                else r.Failed.Add(name);
            }
            return r;
        }

        static HashSet<string> PinnedSkips(Ctx c)
        {
            string path = Path.Combine(c.AcceptanceDir, "skiplist.json");
            HashSet<string> pinned = new HashSet<string>();
            Dictionary<string, object> d = MiniJson.AsObject(MiniJson.Parse(File.ReadAllText(path)));
            foreach (object o in MiniJson.Arr(d, "skips") ?? new List<object>())
            {
                Dictionary<string, object> s = MiniJson.AsObject(o);
                string test = MiniJson.Str(s, "test"), reason = MiniJson.Str(s, "reason");
                if (string.IsNullOrWhiteSpace(test) || string.IsNullOrWhiteSpace(reason)) throw new FailException("skiplist.json has an entry with no test name or no reason");
                pinned.Add(test);
            }
            return pinned;
        }

        [Clause("A9.cf.same-suite-passes-on-net48-skips-pinned")]
        public static string SameSuiteOnNet48(Ctx c)
        {
            c.RequireProduct();
            TrxResult net10 = RunSuite(c, "net10.0", "net10");
            TrxResult net48 = RunSuite(c, "net48", "net48");
            HashSet<string> pinned = PinnedSkips(c);
            Tally t = new Tally();
            t.Expect("net10.0 run", net10.Failed.Count == 0 && net10.Passed.Count > 0, net10.Failed.Count + " failed, " + net10.Passed.Count + " passed. First failures: " + string.Join("; ", net10.Failed.Take(3).ToArray()));
            t.Expect("net48 run on the CF binaries", net48.Failed.Count == 0 && net48.Passed.Count > 0, net48.Failed.Count + " failed, " + net48.Passed.Count + " passed. First failures: " + string.Join("; ", net48.Failed.Take(3).ToArray()));
            foreach (string s in net48.Skipped.Concat(net10.Skipped))
                t.Expect("skip '" + s + "'", pinned.Contains(s), "this test is skipped and acceptance/skiplist.json does not pin it with a reason");
            foreach (string n in net10.Passed)
                if (!net48.Passed.Contains(n) && !pinned.Contains(n))
                    t.Miss("test '" + n + "'", "passes on net10.0 and did not pass on net48, and the skip list does not pin it");
            return t.Done() + "; net10.0 " + net10.Passed.Count + " passed, net48 " + net48.Passed.Count + " passed, " + net48.Skipped.Count + " skipped (all pinned)";
        }

        // ---------------------------------------------------------------- git ls-files

        static List<string> Tracked(Ctx c)
        {
            int code;
            string output = Run("git", "ls-files", c.RepoRoot, 60000, out code);
            if (code != 0) throw new NotRunException("NOT_A_GIT_REPO", "git ls-files exited " + code + " in " + c.RepoRoot);
            List<string> files = new List<string>();
            foreach (string ln in output.Split('\n')) { string t = ln.Trim(); if (t.Length > 0) files.Add(t); }
            return files;
        }

        /// <summary>The names of tracked files that are CF binaries: they reference the CF mscorlib, or they equal a file of the reference set.</summary>
        public static List<string> CfBinariesIn(string root, List<string> files, string refDir)
        {
            HashSet<string> refHashes = new HashSet<string>();
            foreach (string f in Directory.GetFiles(refDir))
                using (SHA256 sha = SHA256.Create()) refHashes.Add(Hex.Encode(sha.ComputeHash(File.ReadAllBytes(f))));
            List<string> hits = new List<string>();
            foreach (string rel in files)
            {
                string full = Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar));
                if (!File.Exists(full)) continue;
                string ext = Path.GetExtension(full).ToLowerInvariant();
                if (ext != ".dll" && ext != ".exe" && ext != ".winmd" && ext != ".mdb" && ext != ".pdb" && ext != ".xml") continue;
                string hash;
                using (SHA256 sha = SHA256.Create()) hash = Hex.Encode(sha.ComputeHash(File.ReadAllBytes(full)));
                if (refHashes.Contains(hash)) { hits.Add(rel + " (identical to a CF reference file)"); continue; }
                if ((ext == ".dll" || ext == ".exe") && IsManaged(full))
                {
                    string n;
                    if (MscorlibToken(full, out n) == CfMscorlibToken) hits.Add(rel + " (references the CF mscorlib)");
                }
            }
            return hits;
        }

        [Clause("A9.git-ls-files.no-cf-binary")]
        public static string NoCfBinaryTracked(Ctx c)
        {
            c.RequireProduct();
            string refDir = RefDir(c);
            List<string> files = Tracked(c);
            // Positive control: the detector flags a real CF binary and a copy of a reference assembly.
            string tmp = Path.Combine(c.WorkDir, "ctl-cf");
            Directory.CreateDirectory(tmp);
            File.Copy(Path.Combine(refDir, "mscorlib.dll"), Path.Combine(tmp, "planted-ref.dll"), true);
            List<string> ctl = CfBinariesIn(tmp, new List<string> { "planted-ref.dll" }, refDir);
            Check.True(ctl.Count == 1, "control failed: the detector missed a copy of the CF reference mscorlib");
            string cfBuilt = Path.Combine(c.RepoRoot, "src", "NetSec.Core.NetCF", "bin", "Release", "net35", "NetSec.Core.dll");
            if (File.Exists(cfBuilt))
            {
                File.Copy(cfBuilt, Path.Combine(tmp, "planted-cf.dll"), true);
                Check.True(CfBinariesIn(tmp, new List<string> { "planted-cf.dll" }, refDir).Count == 1, "control failed: the detector missed a CF-compiled NetSec.Core.dll");
            }
            List<string> hits = CfBinariesIn(c.RepoRoot, files, refDir);
            Check.True(hits.Count == 0, "git tracks CF binaries: " + string.Join("; ", hits.ToArray()));
            foreach (string rel in files)
                Check.True(rel.IndexOf("netcf35-ref", StringComparison.OrdinalIgnoreCase) < 0, "git tracks a path that names the CF reference folder: " + rel);
            // The CF output folder is ignored.
            int code;
            Run("git", "check-ignore -q src/NetSec.Core.NetCF/bin/Release/net35/NetSec.Core.dll", c.RepoRoot, 30000, out code);
            Check.True(code == 0, "git does not ignore src/NetSec.Core.NetCF/bin/, so a CF binary could be committed by accident");
            return files.Count + " tracked files checked against " + Directory.GetFiles(refDir).Length + " CF reference files and the CF mscorlib token; none match";
        }
    }
}
