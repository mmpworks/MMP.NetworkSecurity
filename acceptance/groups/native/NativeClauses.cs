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

        static string Build(Ctx c) { return NativeBuild.Build(c); }

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

        static double[] Sample(int which, int diffPos, int count, out uint freq)
        {
            byte[] a = new Rng(120 + (ulong)which).Bytes(BufferSize), b = (byte[])a.Clone();
            b[diffPos] ^= 0x01;
            uint[] ticks = new uint[count];
            int rc = Api.nsct_sample(which, a, b, (uint)BufferSize, ticks, (uint)count, out freq);
            if (rc != 0) throw new FailException("nsct_sample(which=" + which + ") returned " + rc);
            double[] d = new double[count];
            for (int i = 0; i < count; i++) d[i] = ticks[i];
            return d;
        }

        const int Rounds = 100;

        /// <summary>
        /// One measurement of six cases, taken in interleaved rounds: for each of the two compares (which = 0 and 1), the first-byte case,
        /// the last-byte case, and the first-byte case again. Each round takes a small batch of every case in turn, so a slow moment on the
        /// machine lands in every case and cancels in the t statistic. Taking each case whole lets drift decide the result (constant-time |t|
        /// read 3.7 to 230 that way). The repeated first-byte case is the identical-case control: two samples of the same case, whose t is the
        /// noise floor of this run. Result order: w0 first, w0 last, w0 repeat, w1 first, w1 last, w1 repeat.
        /// </summary>
        static double[][] Interleaved(out uint freq)
        {
            int per = Samples / Rounds;
            List<double>[] acc = new List<double>[6];
            for (int i = 0; i < 6; i++) acc[i] = new List<double>(Samples);
            freq = 0;
            for (int r = 0; r < Rounds; r++)
            {
                for (int which = 0; which < 2; which++)
                {
                    uint f;
                    acc[which * 3].AddRange(Sample(which, 0, per, out f));
                    if (freq == 0) freq = f; else if (f != freq) throw new FailException("nsct_sample changed its tick frequency between rounds: " + freq + " and " + f);
                    acc[which * 3 + 1].AddRange(Sample(which, BufferSize - 1, per, out f));
                    acc[which * 3 + 2].AddRange(Sample(which, 0, per, out f));
                }
            }
            double[][] r6 = new double[6][];
            for (int i = 0; i < 6; i++) r6[i] = acc[i].ToArray();
            return r6;
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
            // both and the one with the larger |t| is the leaky one.
            // Decision, from measured runs of the product (100,000 samples, 20 runs, interleaved): leaky median |t| 781, constant-time
            // median 1.97, identical-case control median 1.49. Constant time went over 4.5 in 5 of 20 runs and the control in 1 of 20,
            // so this clause never promises a constant-time |t| under 4.5. It asks for three things that a real defect breaks:
            //   1. the leaky compare shows a leak: |t| > LeakyMinT (a leaky compare with no leak FAILs);
            //   2. the constant-time compare is far below the leaky one: leaky |t| > 3 x constant-time |t| (a leak in the constant-time path FAILs);
            //   3. the identical-case control of the constant-time compare is far below the leaky |t| too. If it is not, the run was too noisy
            //      to judge. The clause measures again, up to three times, and is NOT RUN TIMING_UNSTABLE when no run is quiet enough.
            //      It never passes on a noisy run.
            string last = "";
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                uint freq;
                double[][] m = Interleaved(out freq);
                Check.True(freq != 0, "nsct_sample reported tick frequency 0");
                double[] t = new double[2];
                t[0] = Welch(m[0], m[1], true);
                t[1] = Welch(m[3], m[4], true);
                int leaky = Math.Abs(t[0]) >= Math.Abs(t[1]) ? 0 : 1, ct = 1 - leaky;
                double tl = Math.Abs(t[leaky]), tc = Math.Abs(t[ct]);
                double control = Math.Abs(Welch(m[ct * 3], m[ct * 3 + 2], true));
                last = "attempt " + attempt + ": samples " + Samples + " per case in " + Rounds + " interleaved rounds, buffer " + BufferSize + " bytes. which=" + leaky + " (leaky) |t|=" + tl.ToString("F1") + ", which=" + ct + " (constant time) |t|=" + tc.ToString("F2") + ", identical-case control |t|=" + control.ToString("F2");
                Check.True(tl > LeakyMinT, "the leaky compare does not separate: |t| = " + tl.ToString("F2") + " is not above " + LeakyMinT + ". " + last);
                Check.True(tl > LeakyOverConstantFactor * tc, "the leaky |t| " + tl.ToString("F1") + " is not above " + LeakyOverConstantFactor + " times the constant-time |t| " + tc.ToString("F2") + ". " + last);
                if (tl > LeakyOverConstantFactor * control)
                    return last + ". Thresholds: leaky |t| > " + LeakyMinT + ", above " + LeakyOverConstantFactor + " x constant-time |t|, and above " + LeakyOverConstantFactor + " x the control. Optimizer-dependent (accuracy rule 5).";
            }
            throw new NotRunException("TIMING_UNSTABLE", "three runs were too noisy to judge: the identical-case control was not far below the leaky |t|. Last: " + last);
        }
    }
}
