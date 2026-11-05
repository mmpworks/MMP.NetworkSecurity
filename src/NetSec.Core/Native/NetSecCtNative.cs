using System.Runtime.InteropServices;

namespace NetSec.Native
{
    /// <summary>One DllImport per export of native/netsec_ct.h. One file, both builds, default calling convention, blittable arguments.</summary>
    internal static class NetSecCtNative
    {
        const string Library = "netsec_ct.dll";

        public const int Ok = 0;

        [DllImport(Library)]
        public static extern uint nsct_abi_version();

        [DllImport(Library)]
        public static extern int nsct_compare_leaky(byte[] a, byte[] b, uint n);

        [DllImport(Library)]
        public static extern int nsct_compare_ct(byte[] a, byte[] b, uint n);

        [DllImport(Library)]
        public static extern int nsct_sample(int which, byte[] a, byte[] b, uint n, uint[] outTicks, uint samples, out uint outFreq);
    }
}
