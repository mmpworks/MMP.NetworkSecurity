// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from src/NetSec.Core/Crypto/Arg.cs at 5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc (blob sha256 fc058258144820ed3da7ad5706e8af53e0d1660876aa3a2574f6461aec940fd3). Do not edit.
using System;

namespace Acceptance.Frozen.Crypto
{
    /// <summary>Argument checks for the (byte[], offset, count) methods in this folder.</summary>
    static class Arg
    {
        public static void Range(byte[] b, int off, int n)
        {
            if (b == null) throw new ArgumentNullException("b");
            if (off < 0 || n < 0 || n > b.Length - off) throw new ArgumentOutOfRangeException("off", "offset and count fall outside the array");
        }

        public static void NotNull(object value, string name)
        {
            if (value == null) throw new ArgumentNullException(name);
        }
    }
}
