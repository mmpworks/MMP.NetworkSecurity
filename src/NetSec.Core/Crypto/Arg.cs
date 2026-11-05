using System;

namespace NetSec.Crypto
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
