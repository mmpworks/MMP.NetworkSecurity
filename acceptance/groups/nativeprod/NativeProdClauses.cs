using System;
using System.IO;
using System.Runtime.InteropServices;
using NetSec.Native;

namespace Acceptance
{
    /// <summary>
    /// A12, product side: the library loads from the product's own NativeCompare on .NET 10 and from the CF binaries on net48, and the
    /// product's TimingJudge agrees with the suite's Welch t (groups/native). The suite builds native/netsec_ct.c itself and puts the
    /// DLL where the product's DllImport("netsec_ct.dll") finds it: next to this program.
    /// </summary>
    public static class NativeProdClauses
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr LoadLibraryW(string path);

        static void PrepareDll(Ctx c)
        {
            string dll = c.Prop("native.dll", Path.Combine(c.WorkDir, "native-x64", "netsec_ct.dll"));
            if (!File.Exists(dll)) throw new NotRunException("NATIVE_DLL_NOT_BUILT", "run groups/native first with the same --work folder (A12.native.build-cl); expected " + dll);
            if (LoadLibraryW(dll) == IntPtr.Zero) throw new FailException("LoadLibrary failed for " + dll);
        }

        static bool Zero(bool equalResult) { return equalResult; }

        [Clause("A12.product.native-compare-loads", PerBuild = true)]
        public static string Loads(Ctx c)
        {
            PrepareDll(c);
            Check.True(NativeCompare.AbiVersion() != 0, "NativeCompare.AbiVersion returned 0");
            byte[] a = new Rng(12).Bytes(64), same = (byte[])a.Clone(), diff = (byte[])a.Clone();
            diff[63] ^= 0x01;
            Check.True(NativeCompare.Leaky(a, same) && NativeCompare.ConstantTime(a, same), "equal buffers must compare equal (true) in both");
            Check.True(!NativeCompare.Leaky(a, diff) && !NativeCompare.ConstantTime(a, diff), "buffers that differ in the last byte must compare unequal (false) in both");
            return "NativeCompare loaded netsec_ct.dll and both compares agree on equal and unequal buffers";
        }

        [Clause("A12.product.timing-judge-agrees")]
        public static string JudgeAgrees(Ctx c)
        {
            PrepareDll(c);
            TimingCase lf = TimingLab.Sample(CompareKind.Leaky, 4096, 100000, 0), ll = TimingLab.Sample(CompareKind.Leaky, 4096, 100000, 4095);
            TimingCase cf = TimingLab.Sample(CompareKind.ConstantTime, 4096, 100000, 0), cl = TimingLab.Sample(CompareKind.ConstantTime, 4096, 100000, 4095);
            TimingVerdict v = TimingJudge.Judge(lf, ll, cf, cl);
            Check.True(v.Separated && Math.Abs(v.LeakyT) > v.Threshold, "the product's judge says the leaky compare does not separate: t = " + v.LeakyT + ", threshold " + v.Threshold);
            Check.True(Math.Abs(v.LeakyT) > 3.0 * Math.Abs(v.ConstantT), "the product's leaky |t| " + Math.Abs(v.LeakyT).ToString("F1") + " is not 3 times the constant-time |t| " + Math.Abs(v.ConstantT).ToString("F2"));
            return "product judge: leaky |t| " + Math.Abs(v.LeakyT).ToString("F1") + " vs constant time |t| " + Math.Abs(v.ConstantT).ToString("F2");
        }
    }
}
