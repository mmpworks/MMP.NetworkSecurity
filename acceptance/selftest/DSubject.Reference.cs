using System;

namespace Acceptance
{
    /// <summary>The self-test's stand-in for the product's DUKPT host side: the reference in lib/Harness/DukptReference.cs.</summary>
    static class DSubject
    {
        public const string Name = "BCL reference (host side only)";
        public static byte[] InitialKey(byte[] bdk, byte[] ikid) { return DukptReference.InitialKey(bdk, ikid); }
        public static byte[] DerivationKey(byte[] bdk, byte[] ikid, uint counter) { return DukptReference.DerivationKey(bdk, ikid, counter); }
        public static byte[] WorkingKey(byte[] bdk, byte[] ikid, uint counter, int use, int keyBytes) { return DukptReference.WorkingKey(bdk, ikid, counter, use, keyBytes); }
        public static PadSession NewPad(byte[] bdk, byte[] ikid) { throw new NotRunException("SELFTEST_NO_REFERENCE", "terminal-side DUKPT has no reference in the self-test"); }
        public static byte[] PinBlockEncrypt(byte[] pinKey, string pin, string pan, byte[] random8) { return DukptReference.PinBlockEncrypt(pinKey, pin, pan, random8); }
        public static string PinBlockDecrypt(byte[] pinKey, byte[] block, string pan) { return DukptReference.PinBlockDecrypt(pinKey, block, pan); }
    }
}
