namespace NetSec.Crypto
{
    /// <summary>
    /// Compares secret bytes with no early exit, so the time taken does not show where the first difference sits.
    /// This is managed code, and the JIT gives no constant-time guarantee. Lesson 11 measures that.
    /// </summary>
    public static class ConstantTime
    {
        public static bool Equal(byte[] a, int aOff, byte[] b, int bOff, int n)
        {
            int difference = 0;
            for (int i = 0; i < n; i++) difference |= a[aOff + i] ^ b[bOff + i];
            return difference == 0;
        }
    }
}
