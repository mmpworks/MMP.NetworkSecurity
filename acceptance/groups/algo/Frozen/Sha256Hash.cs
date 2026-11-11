// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from src/NetSec.Core/Crypto/Sha256Hash.cs at 5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc (blob sha256 a60bfd90d9036c190e54f762e6c13922890936fee9fbf451234a8bb5185ddf50). Do not edit.
using System;

namespace Acceptance.Frozen.Crypto
{
    /// <summary>One compressed block, for the walk: the 64 bytes, the chaining value in, W[0..63], each round's T1, T2 and a..h after it, and the value out.</summary>
    internal sealed class Sha256BlockTrace
    {
        public byte[] Block;
        public uint[] HIn, W, T1 = new uint[64], T2 = new uint[64], HOut;
        public uint[][] Rounds = new uint[64][];
    }

    /// <summary>SHA-256, FIPS 180-4 section 6.2. The function names follow the standard.</summary>
    sealed class Sha256Hash : BlockHash
    {
        /// <summary>When set, each Compress call appends its block's steps. The walk sets it; every other caller leaves it null.</summary>
        internal System.Collections.Generic.List<Sha256BlockTrace> Trace;

        /// <summary>The 64 round constants, for the walk to show beside each round.</summary>
        internal static uint[] RoundConstants { get { return (uint[])K.Clone(); } }

        static readonly uint[] K =
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        };

        uint[] _h = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
        uint[] _w = new uint[64];

        public Sha256Hash() : base(32, 64, 8, false) { }

        public static Sha256Hash Resume(byte[] digest, long bytesAlreadyHashed)
        {
            Arg.NotNull(digest, "digest");
            if (digest.Length != 32) throw new ArgumentException("a SHA-256 digest is 32 bytes", "digest");
            if (bytesAlreadyHashed < 0 || bytesAlreadyHashed % 64 != 0)
                throw new ArgumentOutOfRangeException("bytesAlreadyHashed", "the state exists only at a block boundary, so this is a multiple of 64");

            Sha256Hash hash = new Sha256Hash();
            for (int i = 0; i < 8; i++) hash._h[i] = Endian.LoadBe32(digest, i * 4);
            hash.CountBytesAlreadyHashed((ulong)bytesAlreadyHashed);
            return hash;
        }

        protected override void DetachState()
        {
            _h = (uint[])_h.Clone();
            _w = new uint[64];
        }

        protected override byte[] Digest()
        {
            byte[] digest = new byte[32];
            for (int i = 0; i < 8; i++) Endian.StoreBe32(_h[i], digest, i * 4);
            return digest;
        }

        static uint Rotr(uint x, int n) { return (x >> n) | (x << (32 - n)); }
        static uint BigSigma0(uint x) { return Rotr(x, 2) ^ Rotr(x, 13) ^ Rotr(x, 22); }
        static uint BigSigma1(uint x) { return Rotr(x, 6) ^ Rotr(x, 11) ^ Rotr(x, 25); }
        static uint SmallSigma0(uint x) { return Rotr(x, 7) ^ Rotr(x, 18) ^ (x >> 3); }
        static uint SmallSigma1(uint x) { return Rotr(x, 17) ^ Rotr(x, 19) ^ (x >> 10); }

        protected override void Compress(byte[] block, int off)
        {
            uint[] w = _w;
            for (int t = 0; t < 16; t++) w[t] = Endian.LoadBe32(block, off + t * 4);
            for (int t = 16; t < 64; t++) w[t] = SmallSigma1(w[t - 2]) + w[t - 7] + SmallSigma0(w[t - 15]) + w[t - 16];

            Sha256BlockTrace trace = null;
            if (Trace != null)
            {
                trace = new Sha256BlockTrace();
                trace.Block = new byte[64];
                Buffer.BlockCopy(block, off, trace.Block, 0, 64);
                trace.HIn = (uint[])_h.Clone();
                trace.W = (uint[])w.Clone();
            }
            uint a = _h[0], b = _h[1], c = _h[2], d = _h[3], e = _h[4], f = _h[5], g = _h[6], h = _h[7];
            for (int t = 0; t < 64; t++)
            {
                uint t1 = h + BigSigma1(e) + ((e & f) ^ (~e & g)) + K[t] + w[t];
                uint t2 = BigSigma0(a) + ((a & b) ^ (a & c) ^ (b & c));
                h = g; g = f; f = e; e = d + t1;
                d = c; c = b; b = a; a = t1 + t2;
                if (trace != null) { trace.T1[t] = t1; trace.T2[t] = t2; trace.Rounds[t] = new uint[] { a, b, c, d, e, f, g, h }; }
            }
            _h[0] += a; _h[1] += b; _h[2] += c; _h[3] += d; _h[4] += e; _h[5] += f; _h[6] += g; _h[7] += h;
            if (trace != null) { trace.HOut = (uint[])_h.Clone(); Trace.Add(trace); }
        }
    }
}
