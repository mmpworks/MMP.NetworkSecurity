using System;
using NetSec.Errors;

namespace NetSec.Native
{
    public enum CompareKind { Leaky, ConstantTime }

    /// <summary>Runs a native call and turns a library that will not load into NATIVE_LIB_MISSING.</summary>
    public static class NativeLoad
    {
        public const string CheckName = "native library load";

        public static T Run<T>(Func<T> call)
        {
            try { return call(); }
            catch (Exception e)
            {
                if (!MeansMissingLibrary(e)) throw;
                NetSecError error = NetSecError.Of(ErrorCodes.NativeLibMissing, "netsec_ct.dll did not load. Install the C++ tools of Visual Studio 2022, then run native\\build.cmd and build the program again. " + e.Message);
                error.CheckName = CheckName;
                throw new NetSecException(error);
            }
        }

        /// <summary>The desktop CLR throws DllNotFoundException or EntryPointNotFoundException, both TypeLoadException. CF throws MissingMethodException. A DLL of the wrong architecture gives BadImageFormatException.</summary>
        static bool MeansMissingLibrary(Exception e)
        {
            return e is TypeLoadException || e is MissingMethodException || e is BadImageFormatException;
        }
    }

    /// <summary>The two native compares. Each returns true when the buffers are equal. A length difference is public, so it returns false at once.</summary>
    public static class NativeCompare
    {
        public static bool Leaky(byte[] a, byte[] b)
        {
            if (!SameLength(a, b)) return false;
            return NativeLoad.Run<int>(delegate { return NetSecCtNative.nsct_compare_leaky(a, b, (uint)a.Length); }) == 0;
        }

        public static bool ConstantTime(byte[] a, byte[] b)
        {
            if (!SameLength(a, b)) return false;
            return NativeLoad.Run<int>(delegate { return NetSecCtNative.nsct_compare_ct(a, b, (uint)a.Length); }) == 0;
        }

        public static uint AbiVersion()
        {
            return NativeLoad.Run<uint>(delegate { return NetSecCtNative.nsct_abi_version(); });
        }

        static bool SameLength(byte[] a, byte[] b)
        {
            if (a == null) throw new ArgumentNullException("a");
            if (b == null) throw new ArgumentNullException("b");
            return a.Length == b.Length;
        }
    }

    /// <summary>
    /// The same loop shape as nsct_compare_ct, in managed code. Managed code has no constant-time guarantee: the JIT may
    /// change this code while it runs, and a garbage collection can stop it at any point. The lab measures this compare to show
    /// that a flat result on one run proves nothing about the next.
    /// </summary>
    public static class ManagedCompare
    {
        public static bool FixedShape(byte[] a, byte[] b)
        {
            if (a == null) throw new ArgumentNullException("a");
            if (b == null) throw new ArgumentNullException("b");
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
