using System;

namespace Acceptance
{
    /// <summary>The result of one key request on a pad: the counter used, the 12-byte KSN, and the working key.</summary>
    sealed class PadUse { public uint Counter; public byte[] Ksn; public byte[] Key; }

    /// <summary>One PIN pad in a test. The product adapter wraps DukptPinPad. The clause code sees only this type.</summary>
    abstract class PadSession
    {
        /// <summary>One key request for a usage code (0x1000 PIN, 0x2000 MAC, 0x3000 data). Each request uses the next counter.</summary>
        public abstract PadUse Next(int use, int keyBytes);
        /// <summary>Every key register the pad holds right now. Used by the erasure check.</summary>
        public abstract byte[][] State();
    }
}
