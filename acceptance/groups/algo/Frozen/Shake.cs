// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from src/NetSec.Core/Crypto/Shake.cs at 5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc (blob sha256 3c6f30a0ef66b0ccb0a0af16dc7268a4cb4ca2dded578b0a22ee9ec3d586fb6f). Do not edit.
namespace Acceptance.Frozen.Crypto
{
    /// <summary>
    /// SHAKE128 and SHAKE256, FIPS 202 section 6.2: a hash with output of any length.
    /// Absorb all input first. Squeeze can then run many times and continues the same output stream.
    /// </summary>
    public sealed class Shake
    {
        readonly Keccak _sponge;

        Shake(int rate) { _sponge = new Keccak(rate, 0x1f); }

        public static Shake New128() { return new Shake(168); }
        public static Shake New256() { return new Shake(136); }

        public void Absorb(byte[] b, int off, int n) { _sponge.Absorb(b, off, n); }
        public void Squeeze(byte[] b, int off, int n) { _sponge.Squeeze(b, off, n); }
    }
}
