// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from src/NetSec.Core/Crypto/Sha1Hash.cs at 5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc (blob sha256 1d332ad1eb0b8163ad736c9d2c7b739dbce69bd9c26c9361bb6a012aad232133). Do not edit.
namespace Acceptance.Frozen.Crypto
{
    /// <summary>SHA-1, FIPS 180-4 section 6.1.</summary>
    sealed class Sha1Hash : BlockHash
    {
        uint[] _h = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
        uint[] _w = new uint[80];

        public Sha1Hash() : base(20, 64, 8, false) { }

        protected override void DetachState()
        {
            _h = (uint[])_h.Clone();
            _w = new uint[80];
        }

        protected override byte[] Digest()
        {
            byte[] digest = new byte[20];
            for (int i = 0; i < 5; i++) Endian.StoreBe32(_h[i], digest, i * 4);
            return digest;
        }

        protected override void Compress(byte[] block, int off)
        {
            uint[] w = _w;
            for (int t = 0; t < 16; t++) w[t] = Endian.LoadBe32(block, off + t * 4);
            for (int t = 16; t < 80; t++)
            {
                uint x = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
                w[t] = (x << 1) | (x >> 31);
            }

            uint a = _h[0], b = _h[1], c = _h[2], d = _h[3], e = _h[4];
            for (int t = 0; t < 80; t++)
            {
                uint f, k;
                if (t < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
                else if (t < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
                else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
                else { f = b ^ c ^ d; k = 0xca62c1d6; }

                uint temp = ((a << 5) | (a >> 27)) + f + e + k + w[t];
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;
            }
            _h[0] += a; _h[1] += b; _h[2] += c; _h[3] += d; _h[4] += e;
        }
    }
}
