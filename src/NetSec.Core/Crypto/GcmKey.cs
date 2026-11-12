using System;
using NetSec.Errors;

namespace NetSec.Crypto
{
    /// <summary>
    /// An AES-GCM key (SP 800-38D, 12-byte nonce, 16-byte tag): the AES key with its hash key H and H's 4-bit table, made once (PRD 7.3
    /// items 2 and 15). Immutable after the constructor, so one instance serves any number of threads (AO-4). Code that seals many records
    /// under one key holds a GcmKey; the static Gcm forms build one per call.
    /// Rule: use one key and nonce pair for one message only. A second message under the same pair exposes the xor of the two plaintexts
    /// and lets an attacker forge tags. GcmKey keeps no per-message state, so it cannot detect reuse. The caller owns this rule.
    /// </summary>
    public sealed class GcmKey
    {
        const int BlockSize = 16;
        const int NonceSize = 12;
        const int TagSize = 16;

        readonly AesKey _key;
        readonly uint[] _table;   // 16 products i H, 4 words each (Gf128.Table)

        public GcmKey(AesKey key)
        {
            Arg.NotNull(key, "key");
            _key = key;
            uint h0 = 0, h1 = 0, h2 = 0, h3 = 0;
            key.EncryptWords(ref h0, ref h1, ref h2, ref h3);   // H = AES of the zero block
            _table = Gf128.Table(h0, h1, h2, h3);
        }

        // ---- forms that return a new array: the behaviour and the checks of 5c5d4a4's Gcm.Seal and Gcm.TryOpen ----

        /// <summary>Returns the ciphertext followed by the 16-byte tag.</summary>
        public byte[] Seal(byte[] nonce, byte[] aad, byte[] plain)
        {
            Gcm.CheckArguments(_key, nonce, aad);
            Arg.NotNull(plain, "plain");
            byte[] sealedBytes = new byte[plain.Length + TagSize];
            SealCore(nonce, 0, aad, 0, aad.Length, plain, 0, plain.Length, sealedBytes, 0);
            return sealedBytes;
        }

        /// <summary>Checks the tag before it decrypts anything. On a bad tag it returns false and plain is null, so no unchecked bytes leave here.</summary>
        public bool TryOpen(byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain)
        {
            plain = null;
            Gcm.CheckArguments(_key, nonce, aad);
            Arg.NotNull(sealedBytes, "sealedBytes");
            if (sealedBytes.Length < TagSize) return false;
            int cipherLength = sealedBytes.Length - TagSize;
            if (!TagMatches(nonce, 0, aad, 0, aad.Length, sealedBytes, 0, cipherLength)) return false;
            plain = new byte[cipherLength];
            CounterCrypt(nonce, 0, sealedBytes, 0, cipherLength, plain, 0);
            return true;
        }

        // ---- caller-buffer forms (PRD 7.3 item 15): no allocation, every check before the first write ----

        /// <summary>
        /// Seals count bytes at inOffset: writes the ciphertext and then the 16-byte tag at outOffset, so the output range is count + 16.
        /// Reads 12 nonce bytes at nonceOffset; fewer throws NetSecException GCM_NONCE_LENGTH. Then the overlap rule (PRD 7.1.9).
        /// </summary>
        public void Seal(byte[] nonce, int nonceOffset, byte[] aad, int aadOffset, int aadCount, byte[] input, int inOffset, int count, byte[] output, int outOffset)
        {
            CheckNonce(nonce, nonceOffset);
            Arg.Range(aad, aadOffset, aadCount);
            Arg.Range(input, inOffset, count);
            Arg.Range(output, outOffset, count + TagSize);
            Overlap.Refuse(input, inOffset, count, output, outOffset, count + TagSize);
            SealCore(nonce, nonceOffset, aad, aadOffset, aadCount, input, inOffset, count, output, outOffset);
        }

        /// <summary>
        /// Opens count bytes at inOffset (ciphertext then tag): checks the tag first, in constant time where it lies, and only on a match
        /// decrypts count - 16 bytes to outOffset. On a bad tag it sets that whole output range to 0 and returns false, so for in-place use
        /// the caller then has neither text. A second pass over the ciphertext is the price of no plaintext before the check (PRD 7.4.3).
        /// </summary>
        public bool TryOpen(byte[] nonce, int nonceOffset, byte[] aad, int aadOffset, int aadCount, byte[] input, int inOffset, int count, byte[] output, int outOffset)
        {
            CheckNonce(nonce, nonceOffset);
            Arg.Range(aad, aadOffset, aadCount);
            Arg.Range(input, inOffset, count);
            Arg.Range(output, outOffset, count - TagSize);
            Overlap.Refuse(input, inOffset, count, output, outOffset, count - TagSize);
            int cipherLength = count - TagSize;
            if (!TagMatches(nonce, nonceOffset, aad, aadOffset, aadCount, input, inOffset, cipherLength))
            {
                Array.Clear(output, outOffset, cipherLength);
                return false;
            }
            CounterCrypt(nonce, nonceOffset, input, inOffset, cipherLength, output, outOffset);
            return true;
        }

        // ---- the core ----

        void SealCore(byte[] nonce, int no, byte[] aad, int ao, int an, byte[] input, int io, int n, byte[] output, int oo)
        {
            CounterCrypt(nonce, no, input, io, n, output, oo);
            uint t0, t1, t2, t3;
            Tag(nonce, no, aad, ao, an, output, oo, n, out t0, out t1, out t2, out t3);
            AesKey.StoreBlock(t0, t1, t2, t3, output, oo + n);
        }

        bool TagMatches(byte[] nonce, int no, byte[] aad, int ao, int an, byte[] sealedBytes, int so, int cipherLength)
        {
            uint t0, t1, t2, t3;
            Tag(nonce, no, aad, ao, an, sealedBytes, so, cipherLength, out t0, out t1, out t2, out t3);
            return Subkeys.SameTag(t0, t1, t2, t3, sealedBytes, so + cipherLength);
        }

        /// <summary>GHASH over the AAD, zero padded, then the ciphertext, zero padded, then both lengths in bits, masked by AES of J0.</summary>
        void Tag(byte[] nonce, int no, byte[] aad, int ao, int an, byte[] cipher, int co, int cn, out uint t0, out uint t1, out uint t2, out uint t3)
        {
            uint y0 = 0, y1 = 0, y2 = 0, y3 = 0;
            Absorb(aad, ao, an, ref y0, ref y1, ref y2, ref y3);
            Absorb(cipher, co, cn, ref y0, ref y1, ref y2, ref y3);
            ulong aadBits = (ulong)an << 3, cipherBits = (ulong)cn << 3;
            y0 ^= (uint)(aadBits >> 32); y1 ^= (uint)aadBits; y2 ^= (uint)(cipherBits >> 32); y3 ^= (uint)cipherBits;
            Gf128.Multiply(_table, ref y0, ref y1, ref y2, ref y3);
            uint j0 = Endian.LoadBe32(nonce, no), j1 = Endian.LoadBe32(nonce, no + 4), j2 = Endian.LoadBe32(nonce, no + 8), j3 = 1;
            _key.EncryptWords(ref j0, ref j1, ref j2, ref j3);
            t0 = y0 ^ j0; t1 = y1 ^ j1; t2 = y2 ^ j2; t3 = y3 ^ j3;
        }

        void Absorb(byte[] data, int off, int length, ref uint y0, ref uint y1, ref uint y2, ref uint y3)
        {
            uint[] t = _table;
            ushort[] r = Gf128.Reduce4;
            uint a0 = y0, a1 = y1, a2 = y2, a3 = y3;
            for (int at = 0; at < length; at += BlockSize)
            {
                int take = Math.Min(BlockSize, length - at);
                if (take == BlockSize)
                {
                    a0 ^= Endian.LoadBe32(data, off + at); a1 ^= Endian.LoadBe32(data, off + at + 4);
                    a2 ^= Endian.LoadBe32(data, off + at + 8); a3 ^= Endian.LoadBe32(data, off + at + 12);
                }
                else
                {
                    // A partial last block loads byte by byte with zero fill, so there is no temp block.
                    a0 ^= PartWord(data, off + at, take, 0); a1 ^= PartWord(data, off + at, take, 1);
                    a2 ^= PartWord(data, off + at, take, 2); a3 ^= PartWord(data, off + at, take, 3);
                }
                // BEND (PRD 7.5; bent rule: DRY). Gf128.Multiply is written out here, on locals, with no call and no ref parameters per
                // block, because GHASH is the larger half of a GCM block and the net10 code ratio stood at 4.40 against the 5x target.
                // Gf128.Multiply stays the reference copy: Tag uses it for the length block, so AO-2 runs both copies on every call.
                uint z0 = 0, z1 = 0, z2 = 0, z3 = 0;
                for (int w = 3; w >= 0; w--)
                {
                    uint word = w == 3 ? a3 : w == 2 ? a2 : w == 1 ? a1 : a0;
                    for (int shift = 0; shift < 32; shift += 4)
                    {
                        uint fall = z3 & 0xF;
                        z3 = (z3 >> 4) | (z2 << 28);
                        z2 = (z2 >> 4) | (z1 << 28);
                        z1 = (z1 >> 4) | (z0 << 28);
                        z0 = (z0 >> 4) ^ ((uint)r[fall] << 16);
                        int e = (int)((word >> shift) & 0xF) << 2;
                        z0 ^= t[e]; z1 ^= t[e + 1]; z2 ^= t[e + 2]; z3 ^= t[e + 3];
                    }
                }
                a0 = z0; a1 = z1; a2 = z2; a3 = z3;
            }
            y0 = a0; y1 = a1; y2 = a2; y3 = a3;
        }

        static uint PartWord(byte[] b, int off, int length, int w)
        {
            uint v = 0;
            for (int i = 0; i < 4; i++)
            {
                int at = 4 * w + i;
                if (at < length) v |= (uint)b[off + at] << (24 - 8 * i);
            }
            return v;
        }

        /// <summary>Counter mode from inc32(J0): the nonce words stay, and only the low 32 bits count (unlike Modes.Ctr). Reads before it writes.</summary>
        void CounterCrypt(byte[] nonce, int no, byte[] input, int io, int n, byte[] output, int oo)
        {
            uint c0 = Endian.LoadBe32(nonce, no), c1 = Endian.LoadBe32(nonce, no + 4), c2 = Endian.LoadBe32(nonce, no + 8);
            uint count = 1;
            for (int off = 0; off < n; off += BlockSize)
            {
                count++;
                uint s0 = c0, s1 = c1, s2 = c2, s3 = count;
                _key.EncryptWords(ref s0, ref s1, ref s2, ref s3);
                int take = Math.Min(BlockSize, n - off);
                if (take == BlockSize)
                {
                    uint p0 = Endian.LoadBe32(input, io + off), p1 = Endian.LoadBe32(input, io + off + 4);
                    uint p2 = Endian.LoadBe32(input, io + off + 8), p3 = Endian.LoadBe32(input, io + off + 12);
                    AesKey.StoreBlock(p0 ^ s0, p1 ^ s1, p2 ^ s2, p3 ^ s3, output, oo + off);
                }
                else
                {
                    for (int b = 0; b < take; b++)
                    {
                        uint w = b < 4 ? s0 : b < 8 ? s1 : b < 12 ? s2 : s3;
                        output[oo + off + b] = (byte)(input[io + off + b] ^ (byte)(w >> (24 - 8 * (b % 4))));
                    }
                }
            }
        }

        static void CheckNonce(byte[] nonce, int nonceOffset)
        {
            // A null nonce has fewer than 12 bytes from the offset, so it gets the same code (the suite's reference model does the same).
            if (nonce == null || nonceOffset < 0 || nonce.Length - nonceOffset < NonceSize)
                throw new NetSecException(NetSecError.Of(ErrorCodes.GcmNonceLength, "fewer than 12 nonce bytes at the offset"));
        }
    }
}
