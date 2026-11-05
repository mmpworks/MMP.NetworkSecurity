using System;

namespace NetSec.Crypto
{
    /// <summary>
    /// The sponge under SHA-3 and SHAKE, FIPS 202. Input is XORed into the first Rate bytes of a 200-byte state,
    /// and Keccak-f[1600] mixes the state each time those bytes fill. Output comes from the same bytes.
    /// The state is 25 64-bit lanes, little-endian, addressed as x + 5y.
    /// </summary>
    sealed class Keccak
    {
        static readonly ulong[] RoundConstants =
        {
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
            0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
        };

        static readonly int[] RhoOffsets =
        {
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14,
        };

        readonly int _rate;
        readonly byte _suffix;
        ulong[] _lanes = new ulong[25];
        int _position;
        bool _squeezing;

        /// <param name="rate">Bytes of the state that take input and give output.</param>
        /// <param name="suffix">The domain bits and first pad bit: 0x06 for SHA-3, 0x1f for SHAKE.</param>
        public Keccak(int rate, byte suffix)
        {
            _rate = rate;
            _suffix = suffix;
        }

        public void Absorb(byte[] b, int off, int n)
        {
            Arg.Range(b, off, n);
            if (_squeezing) throw new InvalidOperationException("this sponge has started to give output and takes no more input");
            for (int i = 0; i < n; i++)
            {
                XorByte(_position, b[off + i]);
                _position++;
                if (_position == _rate)
                {
                    Permute(_lanes);
                    _position = 0;
                }
            }
        }

        public void Squeeze(byte[] b, int off, int n)
        {
            Arg.Range(b, off, n);
            if (!_squeezing) Pad();
            for (int i = 0; i < n; i++)
            {
                if (_position == _rate)
                {
                    Permute(_lanes);
                    _position = 0;
                }
                b[off + i] = (byte)(_lanes[_position / 8] >> (8 * (_position % 8)));
                _position++;
            }
        }

        public Keccak Clone()
        {
            Keccak copy = (Keccak)MemberwiseClone();
            copy._lanes = (ulong[])_lanes.Clone();
            return copy;
        }

        void Pad()
        {
            XorByte(_position, _suffix);
            XorByte(_rate - 1, 0x80);
            Permute(_lanes);
            _position = 0;
            _squeezing = true;
        }

        void XorByte(int position, byte value)
        {
            _lanes[position / 8] ^= (ulong)value << (8 * (position % 8));
        }

        /// <summary>Keccak-f[1600]: 24 rounds of the steps theta, rho, pi, chi, iota.</summary>
        static void Permute(ulong[] a)
        {
            ulong[] column = new ulong[5];
            ulong[] b = new ulong[25];
            for (int round = 0; round < 24; round++)
            {
                Theta(a, column);
                RhoPi(a, b);
                Chi(a, b);
                a[0] ^= RoundConstants[round];
            }
        }

        static void Theta(ulong[] a, ulong[] column)
        {
            for (int x = 0; x < 5; x++) column[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            for (int x = 0; x < 5; x++)
            {
                ulong d = column[(x + 4) % 5] ^ Rotl(column[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5) a[x + y] ^= d;
            }
        }

        /// <summary>Rho rotates each lane by its own offset. Pi moves lane (x, y) to (y, 2x + 3y).</summary>
        static void RhoPi(ulong[] a, ulong[] b)
        {
            for (int y = 0; y < 5; y++)
                for (int x = 0; x < 5; x++)
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = Rotl(a[x + 5 * y], RhoOffsets[x + 5 * y]);
        }

        static void Chi(ulong[] a, ulong[] b)
        {
            for (int y = 0; y < 25; y += 5)
                for (int x = 0; x < 5; x++)
                    a[x + y] = b[x + y] ^ (~b[(x + 1) % 5 + y] & b[(x + 2) % 5 + y]);
        }

        // A shift count of 64 reads as 0 in C#, so offset 0 returns x unchanged.
        static ulong Rotl(ulong x, int n) { return (x << n) | (x >> (64 - n)); }
    }
}
