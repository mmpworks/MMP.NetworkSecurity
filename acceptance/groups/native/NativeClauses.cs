using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// A12: the C++ library builds with cl.exe and loads from .NET 10 and from the net48 run; the timing lab takes 100,000
    /// samples per case and the leaky compare separates from the constant-time compare by a stated threshold on a Welch t statistic.
    /// The suite builds native/netsec_ct.c itself, calls the C ABI of program-design.md section 7 through its own P/Invoke, and
    /// computes t itself. The product's own wrappers and judge are checked in groups/nativeprod.
    /// </summary>
    public static class NativeClauses
    {
        const int Samples = 100000, BufferSize = 4096;
        const double LeakyMinT = 4.5, LeakyOverConstantFactor = 3.0;

        static class Api
        {
            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr LoadLibraryW(string path);
            [DllImport("netsec_ct.dll")] public static extern uint nsct_abi_version();
            [DllImport("netsec_ct.dll")] public static extern int nsct_compare_leaky(byte[] a, byte[] b, uint n);
            [DllImport("netsec_ct.dll")] public static extern int nsct_compare_ct(byte[] a, byte[] b, uint n);
            [DllImport("netsec_ct.dll")] public static extern int nsct_sample(int which, byte[] a, byte[] b, uint n, uint[] ticks, uint samples, out uint freq);
        }

        static string BuiltDll;

        /// <summary>Builds the library from the product sources into the work folder. Runs once per program.</summary>
        static string Build(Ctx c)
        {
            if (BuiltDll != null) return BuiltDll;
            string src = Path.Combine(c.RepoRoot, "native", "netsec_ct.c");
            if (!File.Exists(src)) throw new NotRunException("PRODUCT_MISSING", "native/netsec_ct.c does not exist yet (slice S7)");
            string vcvars = c.Prop("vcvars64", @"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat");
            if (!File.Exists(vcvars)) throw new NotRunException("TOOL_MISSING", "vcvars64.bat not found at " + vcvars);
            string outDir = Path.Combine(c.WorkDir, "native-x64");
            Directory.CreateDirectory(outDir);
            string cmd = Path.Combine(outDir, "build.cmd");
            File.WriteAllText(cmd,
                "@echo off\r\n" +
                "call \"" + vcvars + "\" >nul\r\n" +
                "if errorlevel 1 exit /b 91\r\n" +
                "cd /d \"" + c.RepoRoot + "\"\r\n" +
                "cl /nologo /W4 /WX /O2 /TP /LD /DNSCT_BUILD native\\netsec_ct.c /Fe\"" + outDir + "\\netsec_ct.dll\" /Fo\"" + outDir + "\\netsec_ct.obj\"\r\n" +
                "if errorlevel 1 exit /b 92\r\n" +
                "cl /nologo /W4 /WX /O2 /TC /c native\\netsec_ct.c /Fo\"" + outDir + "\\c_check.obj\"\r\n" +
                "if errorlevel 1 exit /b 93\r\n");
            string output;
            int code = Proc.Run("cmd.exe", "/c \"" + cmd + "\"", c.RepoRoot, 300000, out output);
            if (code == 92) throw new FailException("cl.exe failed to build the DLL as C++ (/TP /W4 /WX): " + Tail(output));
            if (code == 93) throw new FailException("cl.exe failed to compile the same file as C (/TC): the library must stay plain C-compatible so a CE compiler can take it. " + Tail(output));
            if (code != 0) throw new NotRunException("TOOL_FAILED", "build.cmd exited " + code + ": " + Tail(output));
            string dll = Path.Combine(outDir, "netsec_ct.dll");
            if (!File.Exists(dll)) throw new FailException("cl.exe reported success and wrote no DLL");
            BuiltDll = dll;
            return dll;
        }

        static string Tail(string s) { s = s.Trim(); return s.Length > 600 ? s.Substring(s.Length - 600) : s; }

        static void Load(Ctx c)
        {
            string dll = Build(c);
            if (Api.LoadLibraryW(dll) == IntPtr.Zero) throw new FailException("LoadLibrary failed for " + dll + " (Win32 error " + Marshal.GetLastWin32Error() + ")");
        }

        [Clause("A12.native.build-cl")]
        public static string BuildClause(Ctx c)
        {
            string dll = Build(c);
            string header = Path.Combine(c.RepoRoot, "native", "netsec_ct.h");
            Check.True(File.Exists(header), "native/netsec_ct.h is missing");
            string text = File.ReadAllText(header);
            foreach (string name in new string[] { "nsct_abi_version", "nsct_compare_leaky", "nsct_compare_ct", "nsct_sample" })
                Check.True(text.Contains(name), "native/netsec_ct.h does not declare " + name);
            return "cl.exe builds the DLL as C++ and the same file as C, warnings as errors; " + new FileInfo(dll).Length + " bytes";
        }

        /// <summary>Compare outcomes by "is zero", the memcmp convention, without assuming which value means equal.</summary>
        static bool Zero(int r) { return r == 0; }

        [Clause("A12.native.load-direct", PerBuild = true)]
        public static string LoadDirect(Ctx c)
        {
            Load(c);
            Check.True(Api.nsct_abi_version() != 0, "nsct_abi_version returned 0");
            byte[] a = new byte[BufferSize], same = new byte[BufferSize];
            new Rng(12).Bytes(BufferSize).CopyTo(a, 0); a.CopyTo(same, 0);
            byte[] diffFirst = (byte[])a.Clone(), diffLast = (byte[])a.Clone();
            diffFirst[0] ^= 0x01; diffLast[BufferSize - 1] ^= 0x01;
            Tally t = new Tally();
            foreach (string kind in new string[] { "leaky", "ct" })
            {
                Func<byte[], byte[], int> cmp = kind == "leaky"
                    ? (Func<byte[], byte[], int>)delegate (byte[] x, byte[] y) { return Api.nsct_compare_leaky(x, y, (uint)BufferSize); }
                    : delegate (byte[] x, byte[] y) { return Api.nsct_compare_ct(x, y, (uint)BufferSize); };
                int eq = cmp(a, same), d0 = cmp(a, diffFirst), d1 = cmp(a, diffLast);
                t.Expect(kind + ": equal buffers differ from unequal in result", Zero(eq) != Zero(d0), "equal gave " + eq + ", first-byte difference gave " + d0);
                t.Expect(kind + ": first and last byte difference both count as unequal", Zero(d0) == Zero(d1), "first-byte gave " + d0 + ", last-byte gave " + d1);
            }
            int le = Api.nsct_compare_leaky(a, same, (uint)BufferSize), ce = Api.nsct_compare_ct(a, same, (uint)BufferSize);
            int ld = Api.nsct_compare_leaky(a, diffLast, (uint)BufferSize), cd = Api.nsct_compare_ct(a, diffLast, (uint)BufferSize);
            t.Expect("leaky and constant-time agree on equal buffers", Zero(le) == Zero(ce), "leaky " + le + ", ct " + ce);
            t.Expect("leaky and constant-time agree on unequal buffers", Zero(ld) == Zero(cd), "leaky " + ld + ", ct " + cd);
            return t.Done();
        }

        // ---------------------------------------------------------------- timing

        static double[] Sample(int which, int diffPos, out uint freq)
        {
            byte[] a = new Rng(120 + (ulong)which).Bytes(BufferSize), b = (byte[])a.Clone();
            b[diffPos] ^= 0x01;
            uint[] ticks = new uint[Samples];
            int rc = Api.nsct_sample(which, a, b, (uint)BufferSize, ticks, (uint)Samples, out freq);
            if (rc != 0) throw new FailException("nsct_sample(which=" + which + ") returned " + rc);
            double[] d = new double[Samples];
            for (int i = 0; i < Samples; i++) d[i] = ticks[i];
            return d;
        }

        /// <summary>Welch t between two sample sets. With crop, both sets lose every sample above the 99th percentile of the two sets together (scheduler noise).</summary>
        public static double Welch(double[] x, double[] y, bool crop)
        {
            if (crop)
            {
                double[] all = new double[x.Length + y.Length];
                x.CopyTo(all, 0); y.CopyTo(all, x.Length);
                Array.Sort(all);
                double cut = all[(int)(all.Length * 0.99)];
                x = Keep(x, cut); y = Keep(y, cut);
            }
            double mx = Mean(x), my = Mean(y), vx = Var(x, mx), vy = Var(y, my);
            double se = Math.Sqrt(vx / x.Length + vy / y.Length);
            return se == 0 ? (mx == my ? 0 : double.PositiveInfinity) : (mx - my) / se;
        }

        static double Mean(double[] v) { double s = 0; for (int i = 0; i < v.Length; i++) s += v[i]; return s / v.Length; }
        static double Var(double[] v, double m) { double s = 0; for (int i = 0; i < v.Length; i++) { double d = v[i] - m; s += d * d; } return s / (v.Length - 1); }
        static double[] Keep(double[] v, double cut)
        {
            List<double> keep = new List<double>(v.Length);
            foreach (double d in v) if (d <= cut) keep.Add(d);
            return keep.ToArray();
        }

        [Clause("A12.timing.leaky-separates-from-constant-time")]
        public static string Timing(Ctx c)
        {
            Load(c);
            // nsct_sample's "which" picks the compare. The header names it. The suite does not assume the numbers: it measures
            // both and the one with the larger |t| is the leaky one. The constant-time one must then stay under the stated bound.
            double[] t = new double[2];
            double[] tRaw = new double[2];
            for (int which = 0; which < 2; which++)
            {
                uint f1, f2;
                double[] first = Sample(which, 0, out f1), last = Sample(which, BufferSize - 1, out f2);
                Check.True(f1 != 0 && f1 == f2, "nsct_sample reported tick frequency " + f1 + " and " + f2);
                tRaw[which] = Welch(first, last, false);
                t[which] = Welch(first, last, true);
            }
            int leaky = Math.Abs(t[0]) >= Math.Abs(t[1]) ? 0 : 1, ct = 1 - leaky;
            double tl = Math.Abs(t[leaky]), tc = Math.Abs(t[ct]);
            string detail = "samples " + Samples + " per case, buffer " + BufferSize + " bytes. which=" + leaky + " (leaky) |t|=" + tl.ToString("F1") + " (uncropped " + Math.Abs(tRaw[leaky]).ToString("F1") + "), which=" + ct + " (constant time) |t|=" + tc.ToString("F2") + " (uncropped " + Math.Abs(tRaw[ct]).ToString("F2") + ")";
            Check.True(tl > LeakyMinT, "the leaky compare does not separate: |t| = " + tl.ToString("F2") + " is not above " + LeakyMinT + ". " + detail);
            Check.True(tl > LeakyOverConstantFactor * tc, "the leaky |t| " + tl.ToString("F1") + " is not above " + LeakyOverConstantFactor + " times the constant-time |t| " + tc.ToString("F2") + ". " + detail);
            return detail + ". Thresholds: leaky |t| > " + LeakyMinT + " and above " + LeakyOverConstantFactor + " x constant-time |t|. Optimizer-dependent (accuracy rule 5).";
        }
    }
}
