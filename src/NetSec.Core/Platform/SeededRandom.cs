using System;
using NetSec.Crypto;

namespace NetSec.Platform
{
    /// <summary>
    /// A repeatable byte stream: SHAKE256 of a fixed label and the seed. Two runs with one seed draw the same bytes on both
    /// builds, so a lab replays. An observer who knows the seed knows every "random" byte. Training use only.
    /// </summary>
    public sealed class SeededRandom : IRandomSource
    {
        static readonly byte[] Label = { (byte)'N', (byte)'e', (byte)'t', (byte)'S', (byte)'e', (byte)'c', (byte)'.', (byte)'S', (byte)'e', (byte)'e', (byte)'d' };

        readonly Shake _stream = Shake.New256();

        public SeededRandom(int seed) : this(BigEndian(seed)) { }

        public SeededRandom(byte[] seed)
        {
            if (seed == null) throw new ArgumentNullException("seed");
            _stream.Absorb(Label, 0, Label.Length);
            _stream.Absorb(seed, 0, seed.Length);
        }

        public void Fill(byte[] b, int off, int n)
        {
            lock (_stream) _stream.Squeeze(b, off, n);
        }

        static byte[] BigEndian(int value)
        {
            return new byte[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value };
        }
    }
}
