// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from src/NetSec.Core/Crypto/ConstantTime.cs at 5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc (blob sha256 4f42b901f293f223ed5e7125be9c0486281bf44d9384d9c23f729b61e46a287d). Do not edit.
namespace Acceptance.Frozen.Crypto
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
