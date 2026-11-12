using System;

namespace NetSec.Crypto
{
    /// <summary>
    /// AES-CMAC, RFC 4493 and SP 800-38B: CBC with a zero IV, keeping only the last block.
    /// The last block is first xored with subkey K1 when it is full, or padded and xored with K2 when it is not,
    /// so a message and its padded form give different tags.
    /// The caller-buffer forms (PRD 7.3 item 15) allocate nothing: the subkeys and the running block are words. The static forms make the
    /// subkeys on each message, which costs one AES block (PRD 7.3 item 16); CmacKey makes them once.
    /// </summary>
    public static class Cmac
    {
        const int BlockSize = 16;

        /// <summary>
        /// True when tag is the full 16-byte CMAC of message. Use this and never a plain compare, which can stop at the first wrong byte.
        /// A tag of another length gives false. A truncated tag is out of scope here.
        /// </summary>
        public static bool Verify(AesKey k, byte[] message, byte[] tag)
        {
            Arg.NotNull(tag, "tag");
            Arg.NotNull(k, "k");
            Arg.NotNull(message, "message");
            uint t0, t1, t2, t3;
            Tag(k, Subkeys.Of(k), message, 0, message.Length, out t0, out t1, out t2, out t3);
            return tag.Length == BlockSize && Subkeys.SameTag(t0, t1, t2, t3, tag, 0);
        }

        public static byte[] Compute(AesKey k, byte[] message)
        {
            Arg.NotNull(k, "k");
            Arg.NotNull(message, "message");
            byte[] tag = new byte[BlockSize];
            uint t0, t1, t2, t3;
            Tag(k, Subkeys.Of(k), message, 0, message.Length, out t0, out t1, out t2, out t3);
            AesKey.StoreBlock(t0, t1, t2, t3, tag, 0);
            return tag;
        }

        /// <summary>The CMAC of count bytes at offset, written as 16 bytes at tagOffset.</summary>
        public static void Compute(AesKey k, byte[] message, int offset, int count, byte[] tag, int tagOffset)
        {
            CheckInto(k, message, offset, count, tag, tagOffset);
            uint t0, t1, t2, t3;
            Tag(k, Subkeys.Of(k), message, offset, count, out t0, out t1, out t2, out t3);
            AesKey.StoreBlock(t0, t1, t2, t3, tag, tagOffset);
        }

        /// <summary>True when the 16 bytes at tagOffset are the CMAC of count bytes at offset, compared in constant time where they lie.</summary>
        public static bool Verify(AesKey k, byte[] message, int offset, int count, byte[] tag, int tagOffset)
        {
            CheckInto(k, message, offset, count, tag, tagOffset);
            uint t0, t1, t2, t3;
            Tag(k, Subkeys.Of(k), message, offset, count, out t0, out t1, out t2, out t3);
            return Subkeys.SameTag(t0, t1, t2, t3, tag, tagOffset);
        }

        internal static void CheckInto(AesKey k, byte[] message, int offset, int count, byte[] tag, int tagOffset)
        {
            Arg.NotNull(k, "k");
            Arg.Range(message, offset, count);
            Arg.Range(tag, tagOffset, BlockSize);
            Overlap.Refuse(message, offset, count, tag, tagOffset, BlockSize);
        }

        /// <summary>The CMAC core on words: CBC over every block but the last, then the last block xor K1 (full) or K2 (padded).</summary>
        internal static void Tag(AesKey k, Subkeys s, byte[] m, int mo, int n, out uint t0, out uint t1, out uint t2, out uint t3)
        {
            int fullBlocksBeforeLast = n == 0 ? 0 : (n - 1) / BlockSize;
            uint x0 = 0, x1 = 0, x2 = 0, x3 = 0;
            for (int block = 0; block < fullBlocksBeforeLast; block++)
            {
                int at = mo + block * BlockSize;
                x0 ^= Endian.LoadBe32(m, at); x1 ^= Endian.LoadBe32(m, at + 4); x2 ^= Endian.LoadBe32(m, at + 8); x3 ^= Endian.LoadBe32(m, at + 12);
                k.EncryptWords(ref x0, ref x1, ref x2, ref x3);
            }
            int lastOff = mo + fullBlocksBeforeLast * BlockSize;
            int lastLength = n - fullBlocksBeforeLast * BlockSize;
            uint l0 = LastWord(m, lastOff, lastLength, 0), l1 = LastWord(m, lastOff, lastLength, 1);
            uint l2 = LastWord(m, lastOff, lastLength, 2), l3 = LastWord(m, lastOff, lastLength, 3);
            if (lastLength == BlockSize) { l0 ^= s.K10; l1 ^= s.K11; l2 ^= s.K12; l3 ^= s.K13; }
            else { l0 ^= s.K20; l1 ^= s.K21; l2 ^= s.K22; l3 ^= s.K23; }
            x0 ^= l0; x1 ^= l1; x2 ^= l2; x3 ^= l3;
            k.EncryptWords(ref x0, ref x1, ref x2, ref x3);
            t0 = x0; t1 = x1; t2 = x2; t3 = x3;
        }

        /// <summary>Word w of the last block: its bytes, then the 0x80 pad byte after them, then zeros (a full block has no pad).</summary>
        static uint LastWord(byte[] m, int off, int length, int w)
        {
            uint v = 0;
            for (int b = 0; b < 4; b++)
            {
                int at = 4 * w + b;
                uint value = at < length ? m[off + at] : at == length ? 0x80u : 0u;
                v |= value << (24 - 8 * b);
            }
            return v;
        }
    }

    /// <summary>The CMAC subkeys K1 and K2 as words (RFC 4493 section 2.3), made from AES of the zero block.</summary>
    internal struct Subkeys
    {
        public uint K10, K11, K12, K13, K20, K21, K22, K23;

        public static Subkeys Of(AesKey k)
        {
            uint l0 = 0, l1 = 0, l2 = 0, l3 = 0;
            k.EncryptWords(ref l0, ref l1, ref l2, ref l3);
            Subkeys s = new Subkeys();
            Double(l0, l1, l2, l3, out s.K10, out s.K11, out s.K12, out s.K13);
            Double(s.K10, s.K11, s.K12, s.K13, out s.K20, out s.K21, out s.K22, out s.K23);
            return s;
        }

        /// <summary>Multiply by x in GF(2^128): shift left one bit, and if the top bit fell off, xor 0x87 into the last byte.</summary>
        static void Double(uint a0, uint a1, uint a2, uint a3, out uint b0, out uint b1, out uint b2, out uint b3)
        {
            bool carry = (a0 >> 31) != 0;
            b0 = (a0 << 1) | (a1 >> 31);
            b1 = (a1 << 1) | (a2 >> 31);
            b2 = (a2 << 1) | (a3 >> 31);
            b3 = (a3 << 1) ^ (carry ? 0x87u : 0u);
        }

        /// <summary>The tag words against 16 tag bytes where they lie, in constant time: every byte is compared, whatever the first difference.</summary>
        public static bool SameTag(uint t0, uint t1, uint t2, uint t3, byte[] tag, int at)
        {
            uint diff = (t0 ^ Endian.LoadBe32(tag, at)) | (t1 ^ Endian.LoadBe32(tag, at + 4)) | (t2 ^ Endian.LoadBe32(tag, at + 8)) | (t3 ^ Endian.LoadBe32(tag, at + 12));
            return diff == 0;
        }
    }

    /// <summary>
    /// A CMAC key: the AES key with its two subkeys made once (PRD 7.3 item 15). Immutable, so one instance serves any number of threads.
    /// For short messages it saves the AES block that the static Cmac forms spend on the subkeys each time (25% at 64 bytes, 100% at 16).
    /// </summary>
    public sealed class CmacKey
    {
        readonly AesKey _key;
        readonly Subkeys _subkeys;

        public CmacKey(AesKey key)
        {
            Arg.NotNull(key, "key");
            _key = key;
            _subkeys = Subkeys.Of(key);
        }

        /// <summary>The CMAC of count bytes at offset, written as 16 bytes at tagOffset.</summary>
        public void Compute(byte[] message, int offset, int count, byte[] tag, int tagOffset)
        {
            Cmac.CheckInto(_key, message, offset, count, tag, tagOffset);
            uint t0, t1, t2, t3;
            Cmac.Tag(_key, _subkeys, message, offset, count, out t0, out t1, out t2, out t3);
            AesKey.StoreBlock(t0, t1, t2, t3, tag, tagOffset);
        }

        /// <summary>True when the 16 bytes at tagOffset are the CMAC of count bytes at offset, compared in constant time.</summary>
        public bool Verify(byte[] message, int offset, int count, byte[] tag, int tagOffset)
        {
            Cmac.CheckInto(_key, message, offset, count, tag, tagOffset);
            uint t0, t1, t2, t3;
            Cmac.Tag(_key, _subkeys, message, offset, count, out t0, out t1, out t2, out t3);
            return Subkeys.SameTag(t0, t1, t2, t3, tag, tagOffset);
        }
    }
}
