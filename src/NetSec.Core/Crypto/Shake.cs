namespace NetSec.Crypto
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
