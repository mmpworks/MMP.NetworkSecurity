using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;

namespace Acceptance
{
    /// <summary>Marks a static method as one acceptance clause. PerBuild clauses report as "id.net10" and "id.cf".</summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
    public sealed class ClauseAttribute : Attribute
    {
        public readonly string Id;
        public bool PerBuild;
        public ClauseAttribute(string id) { Id = id; }
    }

    /// <summary>The clause cannot run. The reason is a stable code, for example PRODUCT_MISSING.</summary>
    public class NotRunException : Exception
    {
        public readonly string Reason;
        public NotRunException(string reason, string detail) : base(detail) { Reason = reason; }
    }

    /// <summary>The clause ran and the product is wrong.</summary>
    public class FailException : Exception
    {
        public FailException(string detail) : base(detail) { }
    }

    public sealed class Ctx
    {
        public string Build = "none";            // net10, cf, or none
        public string VectorsDir = "";
        public string RepoRoot = "";             // product repo root (the folder that holds src/)
        public string AcceptanceDir = "";
        public string WorkDir = "";
        public string RefereeDir { get { return Path.Combine(AcceptanceDir, "referees"); } }
        public Dictionary<string, string> Props = new Dictionary<string, string>();
        public string Prop(string k, string dflt) { string v; return Props.TryGetValue(k, out v) ? v : dflt; }
        public List<VectorRecord> Vectors(string file, string group) { return Nsv.Load(VectorsDir, file, group); }
        /// <summary>
        /// A clause about the shipped product holds vacuously when nothing is built. Call this first in such a clause:
        /// no src/NetSec.Core in the repo means NOT RUN PRODUCT_MISSING, never PASS.
        /// </summary>
        public void RequireProduct()
        {
            if (!File.Exists(Path.Combine(RepoRoot, "src", "NetSec.Core", "NetSec.Core.csproj")))
                throw new NotRunException("PRODUCT_MISSING", "src/NetSec.Core/NetSec.Core.csproj does not exist yet (slice S0)");
        }
    }

    public static class Check
    {
        public static void True(bool ok, string detail) { if (!ok) throw new FailException(detail); }
        public static void Bytes(string label, byte[] expected, byte[] actual)
        {
            if (!Hex.Eq(expected, actual))
                throw new FailException(label + ": expected " + Hex.Short(expected) + " got " + Hex.Short(actual));
        }
        public static void Equal(string label, object expected, object actual)
        {
            if (!object.Equals(expected, actual)) throw new FailException(label + ": expected " + expected + " got " + actual);
        }
    }

    /// <summary>Counts failures across many vector records, then fails once with the first few.</summary>
    public sealed class Tally
    {
        public int Total, Bad;
        readonly List<string> _first = new List<string>();
        public void Ok() { Total++; }
        public void Miss(string where, string detail)
        {
            Total++; Bad++;
            if (_first.Count < 3) _first.Add(where + ": " + detail);
        }
        public void Compare(string where, byte[] expected, byte[] actual)
        {
            if (Hex.Eq(expected, actual)) Ok();
            else Miss(where, "expected " + Hex.Short(expected) + " got " + Hex.Short(actual));
        }
        public void Expect(string where, bool ok, string detail)
        {
            if (ok) Ok(); else Miss(where, detail);
        }
        public string Summary { get { return (Total - Bad) + " of " + Total + " vectors"; } }
        public string Done()
        {
            if (Total == 0) throw new NotRunException("NO_VECTORS_RAN", "the clause ran zero checks");
            if (Bad > 0) throw new FailException(Summary + " pass. First misses: " + string.Join(" | ", _first.ToArray()));
            return Summary;
        }
    }

    /// <summary>Runs the clauses of one group in one build and prints one @@CLAUSE json line per clause.</summary>
    public static class ClauseRunner
    {
        public static int Run(string[] args, Assembly asm)
        {
            Ctx c = new Ctx();
            List<string> ids = null;
            bool list = false;
            int timeoutSec = 900;
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--build": c.Build = args[++i]; break;
                    case "--ids": ids = new List<string>(args[++i].Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries)); break;
                    case "--vectors": c.VectorsDir = args[++i]; break;
                    case "--root": c.RepoRoot = args[++i]; break;
                    case "--acceptance": c.AcceptanceDir = args[++i]; break;
                    case "--work": c.WorkDir = args[++i]; break;
                    case "--timeout": timeoutSec = int.Parse(args[++i]); break;
                    case "--prop": { string kv = args[++i]; int eq = kv.IndexOf('='); c.Props[kv.Substring(0, eq)] = kv.Substring(eq + 1); break; }
                    case "--list": list = true; break;
                    default: Console.Error.WriteLine("unknown argument " + args[i]); return 2;
                }
            }
            if (c.AcceptanceDir.Length == 0) c.AcceptanceDir = FindAcceptanceDir();
            if (c.VectorsDir.Length == 0) c.VectorsDir = Path.Combine(c.AcceptanceDir, "vectors");
            if (c.RepoRoot.Length == 0) c.RepoRoot = Path.GetDirectoryName(c.AcceptanceDir);
            if (c.WorkDir.Length == 0) c.WorkDir = Path.Combine(c.AcceptanceDir, ".work", Process.GetCurrentProcess().Id.ToString());
            Directory.CreateDirectory(c.WorkDir);

            List<KeyValuePair<string, MethodInfo>> all = Discover(asm, c.Build);
            if (list)
            {
                foreach (KeyValuePair<string, MethodInfo> kv in all) Console.WriteLine(kv.Key);
                return 0;
            }
            foreach (KeyValuePair<string, MethodInfo> kv in all)
            {
                if (ids != null && !ids.Contains(kv.Key)) continue;
                Emit(Execute(kv.Key, kv.Value, c, timeoutSec));
            }
            if (ids != null)
                foreach (string want in ids)
                    if (!all.Exists(delegate (KeyValuePair<string, MethodInfo> p) { return p.Key == want; }))
                        Emit(new Result(want, "NOT RUN", "NOT_IN_GROUP", "the group in build " + c.Build + " has no clause with this id", 0));
            return 0;
        }

        static string FindAcceptanceDir()
        {
            string d = AppDomain.CurrentDomain.BaseDirectory;
            while (!string.IsNullOrEmpty(d))
            {
                if (File.Exists(Path.Combine(d, "clauses.json"))) return d;
                d = Path.GetDirectoryName(d.TrimEnd(Path.DirectorySeparatorChar));
            }
            throw new InvalidOperationException("acceptance folder not found; pass --acceptance");
        }

        static List<KeyValuePair<string, MethodInfo>> Discover(Assembly asm, string build)
        {
            List<KeyValuePair<string, MethodInfo>> r = new List<KeyValuePair<string, MethodInfo>>();
            foreach (Type t in asm.GetTypes())
                foreach (MethodInfo m in t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.DeclaredOnly))
                    foreach (ClauseAttribute a in m.GetCustomAttributes(typeof(ClauseAttribute), false))
                    {
                        string id = a.PerBuild ? a.Id + "." + build : a.Id;
                        r.Add(new KeyValuePair<string, MethodInfo>(id, m));
                    }
            r.Sort(delegate (KeyValuePair<string, MethodInfo> x, KeyValuePair<string, MethodInfo> y) { return string.CompareOrdinal(x.Key, y.Key); });
            return r;
        }

        sealed class Result
        {
            public string Id, Status, Reason, Detail; public long Ms;
            public Result(string id, string status, string reason, string detail, long ms) { Id = id; Status = status; Reason = reason; Detail = detail; Ms = ms; }
        }

        static Result Execute(string id, MethodInfo m, Ctx c, int timeoutSec)
        {
            Stopwatch sw = Stopwatch.StartNew();
            Result result = null;
            Thread th = new Thread(delegate ()
            {
                try
                {
                    object ret = m.Invoke(null, new object[] { c });
                    string detail = ret as string;
                    result = new Result(id, "PASS", "", detail ?? "", 0);
                }
                catch (TargetInvocationException tie) { result = Classify(id, tie.InnerException ?? tie); }
                catch (Exception ex) { result = Classify(id, ex); }
            }, 64 * 1024 * 1024);
            th.IsBackground = true;
            th.Start();
            if (!th.Join(timeoutSec * 1000))
                return new Result(id, "FAIL", "TIMEOUT", "no result after " + timeoutSec + " s", sw.ElapsedMilliseconds);
            result.Ms = sw.ElapsedMilliseconds;
            return result;
        }

        /// <summary>Maps an exception to a status. A product that is absent is NOT RUN, never PASS.</summary>
        static Result Classify(string id, Exception ex)
        {
            NotRunException nr = ex as NotRunException;
            if (nr != null) return new Result(id, "NOT RUN", nr.Reason, nr.Message, 0);
            FailException fe = ex as FailException;
            if (fe != null) return new Result(id, "FAIL", "ASSERTION", fe.Message, 0);
            if (ex is NotImplementedException || ex is TypeLoadException || ex is MissingMethodException || ex is MissingMemberException
                || (ex is FileNotFoundException && ex.Message.IndexOf("NetSec", StringComparison.Ordinal) >= 0)
                || (ex is TypeInitializationException && ex.InnerException is NotImplementedException))
                return new Result(id, "NOT RUN", "PRODUCT_MISSING", ex.GetType().Name + ": " + ex.Message, 0);
            return new Result(id, "FAIL", "UNEXPECTED_EXCEPTION", ex.GetType().Name + ": " + ex.Message + " @ " + FirstFrame(ex), 0);
        }

        /// <summary>Status a clause would get if it threw this exception. Exposed for the self-test.</summary>
        public static string StatusOf(Exception ex)
        {
            Result r = Classify("probe", ex);
            return r.Status + ":" + r.Reason;
        }

        static string FirstFrame(Exception ex)
        {
            string st = ex.StackTrace;
            if (string.IsNullOrEmpty(st)) return "";
            int nl = st.IndexOf('\n');
            return (nl < 0 ? st : st.Substring(0, nl)).Trim();
        }

        static void Emit(Result r)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("@@CLAUSE {\"id\":").Append(Q(r.Id)).Append(",\"status\":").Append(Q(r.Status))
              .Append(",\"reason\":").Append(Q(r.Reason)).Append(",\"detail\":").Append(Q(r.Detail))
              .Append(",\"ms\":").Append(r.Ms).Append('}');
            Console.Out.WriteLine(sb.ToString());
            Console.Out.Flush();
        }

        public static string Q(string s)
        {
            if (s == null) s = "";
            if (s.Length > 1500) s = s.Substring(0, 1500) + "...";
            StringBuilder sb = new StringBuilder("\"");
            foreach (char ch in s)
            {
                switch (ch)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (ch < 0x20) sb.Append("\\u").Append(((int)ch).ToString("x4"));
                        else sb.Append(ch);
                        break;
                }
            }
            return sb.Append('"').ToString();
        }
    }
}
