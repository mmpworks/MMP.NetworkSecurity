using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace Acceptance
{
    /// <summary>
    /// A16, type half (D5): a real IKeyHandle given to the glass-box factory fails by type. The suite compiles small programs against the
    /// built NetSec.Core.dll. The control program passes an ITrainingKeySource and must compile. The attack programs pass an IKeyHandle
    /// (or an IKeyHandleSource) and must fail with the named compiler error. The suite also reads the public surface of the assembly:
    /// no type in Core implements IKeyHandle, and no public member of the Io folder takes or exposes one.
    /// </summary>
    public static class KeysClauses
    {
        static string CoreDll(Ctx c)
        {
            string p = c.Prop("core.net10", "");
            if (p.Length == 0 || !File.Exists(p)) throw new NotRunException("PRODUCT_MISSING", "NetSec.Core.dll (net10.0 build) is not built (core.net10=" + p + ")");
            return p;
        }

        static string AsyncProxyDll(Ctx c)
        {
            string p = c.Prop("asyncproxy.ns2", "");
            if (p.Length == 0 || !File.Exists(p)) throw new NotRunException("SIBLING_NOT_BUILT", "MMP.AsyncProxy (netstandard2.0) is not built (asyncproxy.ns2=" + p + ")");
            return p;
        }

        /// <summary>Builds one tiny program and returns the compiler's error codes (empty when it compiles).</summary>
        static List<string> Compile(Ctx c, string name, string source, out string output)
        {
            string dir = Path.Combine(c.WorkDir, "a16-" + name);
            Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, "P.cs"), source);
            File.WriteAllText(Path.Combine(dir, "p.csproj"),
                "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup><OutputType>Library</OutputType><TargetFramework>net10.0</TargetFramework><LangVersion>latest</LangVersion><Nullable>disable</Nullable><ImplicitUsings>disable</ImplicitUsings></PropertyGroup>\n" +
                "  <ItemGroup>\n    <Reference Include=\"NetSec.Core\"><HintPath>" + CoreDll(c) + "</HintPath></Reference>\n    <Reference Include=\"MMP.AsyncProxy\"><HintPath>" + AsyncProxyDll(c) + "</HintPath></Reference>\n  </ItemGroup>\n</Project>\n");
            int code = Proc.Run("dotnet", "build \"" + Path.Combine(dir, "p.csproj") + "\" -c Release --nologo -v q", dir, 300000, out output);
            List<string> errors = new List<string>();
            foreach (Match m in Regex.Matches(output, @"error (?<c>CS\d{4}):"))
                if (!errors.Contains(m.Groups["c"].Value)) errors.Add(m.Groups["c"].Value);
            if (code != 0 && errors.Count == 0) throw new NotRunException("TOOL_FAILED", "dotnet build exited " + code + " with no compiler error: " + Tail(output));
            return errors;
        }

        static string Tail(string s) { s = s.Trim(); return s.Length > 500 ? s.Substring(s.Length - 500) : s; }

        const string Header = "using System;\nusing NetSec.Io;\nusing NetSec.Keys;\nnamespace Probe {\n";

        [Clause("A16.type.keyhandle-cannot-reach-glass-factory")]
        public static string KeyHandleCannotReachGlass(Ctx c)
        {
            string output;
            // Control: the training key source is what the glass factory takes.
            List<string> ctl = Compile(c, "control", Header + "public class P { public static object M(ITrainingKeySource s) { return new GlassTransportFactory(s); } }\n}\n", out output);
            Check.True(ctl.Count == 0, "the control program does not compile (" + string.Join(",", ctl.ToArray()) + "). The probe setup or the GlassTransportFactory constructor changed: " + Tail(output));

            // Attacks: one thing changes in each, an IKeyHandle (or its source) takes the place of the training key source.
            Dictionary<string, string[]> attacks = new Dictionary<string, string[]>();
            attacks["handle-source-to-factory"] = new string[] { "public class P { public static object M(IKeyHandleSource s) { return new GlassTransportFactory(s); } }", "CS1503" };
            attacks["handle-to-factory"] = new string[] { "public class P { public static object M(IKeyHandle h) { return new GlassTransportFactory(h); } }", "CS1503" };
            attacks["handle-to-training-key"] = new string[] { "public class P { public static ITrainingKey M(IKeyHandle h) { ITrainingKey t = h; return t; } }", "CS0266,CS0029" };
            attacks["handle-into-request"] = new string[] { "public class P { public static void M(IKeyHandle h, TransportRequest r) { r.Key = h; } }", "CS1061" };
            Tally t = new Tally();
            foreach (KeyValuePair<string, string[]> a in attacks)
            {
                List<string> errs = Compile(c, a.Key, Header + a.Value[0] + "\n}\n", out output);
                bool named = false;
                foreach (string want in a.Value[1].Split(',')) if (errs.Contains(want)) named = true;
                t.Expect(a.Key, errs.Count > 0 && named, errs.Count == 0 ? "the program COMPILED: an IKeyHandle reaches the glass-box path" : "failed with [" + string.Join(",", errs.ToArray()) + "], expected " + a.Value[1]);
            }
            return t.Done();
        }

        [Clause("A16.type.core-holds-no-keyhandle-implementation-and-no-io-member-takes-one")]
        public static string SurfaceHoldsNoKeyHandle(Ctx c)
        {
            string core = CoreDll(c), proxy = AsyncProxyDll(c);
            AppDomain.CurrentDomain.AssemblyResolve += delegate (object s, ResolveEventArgs e)
            {
                if (e.Name.StartsWith("MMP.AsyncProxy", StringComparison.Ordinal)) return Assembly.LoadFrom(proxy);
                return null;
            };
            Assembly asm = Assembly.LoadFrom(core);
            Type[] types;
            try { types = asm.GetTypes(); }
            catch (ReflectionTypeLoadException ex) { types = Array.FindAll(ex.Types, delegate (Type t) { return t != null; }); }
            Type handle = asm.GetType("NetSec.Keys.IKeyHandle");
            Type handleSource = asm.GetType("NetSec.Keys.IKeyHandleSource");
            Check.True(handle != null && handleSource != null, "NetSec.Keys.IKeyHandle and IKeyHandleSource must exist in NetSec.Core (program-design.md section 2.2)");
            Tally t2 = new Tally();
            foreach (Type t in types)
            {
                if (t == handle || t == handleSource) continue;
                bool implementsHandle = handle.IsAssignableFrom(t) || handleSource.IsAssignableFrom(t);
                t2.Expect("type " + t.FullName, !implementsHandle, "NetSec.Core must hold no IKeyHandle implementation; the Host owns it (D5)");
                if (t.Namespace != "NetSec.Io" || !t.IsPublic) continue;
                foreach (MemberInfo m in t.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
                {
                    List<Type> used = new List<Type>();
                    FieldInfo f = m as FieldInfo; if (f != null) used.Add(f.FieldType);
                    PropertyInfo p = m as PropertyInfo; if (p != null) used.Add(p.PropertyType);
                    MethodBase mb = m as MethodBase;
                    if (mb != null) { foreach (ParameterInfo pi in mb.GetParameters()) used.Add(pi.ParameterType); MethodInfo mi = mb as MethodInfo; if (mi != null) used.Add(mi.ReturnType); }
                    foreach (Type u in used)
                        t2.Expect("member " + t.Name + "." + m.Name, u != handle && u != handleSource, "a public member of the Io folder takes or returns " + u.Name);
                }
            }
            return t2.Done();
        }
    }
}
