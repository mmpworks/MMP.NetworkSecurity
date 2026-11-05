using System;

namespace Acceptance
{
    /// <summary>One PIN pad in a test. The product adapter wraps DukptPinPad. The clause code sees only this type.</summary>
    abstract class PadSession
    {
        public abstract uint Counter { get; }
        public abstract uint Next();
        public abstract byte[] WorkingKey(int use, int keyBytes);
        /// <summary>Every key register the pad holds right now. Used by the erasure check.</summary>
        public abstract byte[][] State();
    }
}
