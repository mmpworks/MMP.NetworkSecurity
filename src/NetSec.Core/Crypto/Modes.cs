using System;
using NetSec.Errors;

namespace NetSec.Crypto
{
    /// <summary>
    /// AES block modes, SP 800-38A. None of them pads or adds a MAC. The caller owns that, and the lessons show what goes wrong without it.
    /// ECB and CBC take whole blocks only.
    /// Each mode has three shapes over one core: the form that returns a new array (5c5d4a4, unchanged), the caller-buffer form that writes
    /// into an array the caller gives, and the streamed form that carries the chain or the counter in a CbcChain or CtrCounter between calls
    /// (PRD 7.3 item 15). The caller-buffer and streamed forms allocate nothing. Their argument checks all run before the first write, so a
    /// refused call changes neither the output nor the state object.
    /// Overlap rule (PRD 7.1.9) for the caller-buffer and streamed forms: the same array at the same index is legal and gives the
    /// separate-buffer result, ranges that do not overlap are legal, and any other overlap throws NetSecException ARG_RANGES_OVERLAP.
    /// </summary>
    public static class Modes
    {
        const int BlockSize = 16;

        // ---- forms that return a new array (5c5d4a4 behaviour, including their argument checks and messages) ----

        public static byte[] EcbEncrypt(AesKey k, byte[] data)
        {
            CheckWholeBlocks(k, data);
            byte[] output = new byte[data.Length];
            EcbCore(k, true, data, 0, data.Length, output, 0);
            return output;
        }

        public static byte[] CbcEncrypt(AesKey k, byte[] iv, byte[] data)
        {
            CheckWholeBlocks(k, data);
            CheckBlock(iv, "iv");
            byte[] output = new byte[data.Length];
            uint c0 = Endian.LoadBe32(iv, 0), c1 = Endian.LoadBe32(iv, 4), c2 = Endian.LoadBe32(iv, 8), c3 = Endian.LoadBe32(iv, 12);
            CbcEncryptCore(k, ref c0, ref c1, ref c2, ref c3, data, 0, data.Length, output, 0);
            return output;
        }

        public static byte[] CbcDecrypt(AesKey k, byte[] iv, byte[] data)
        {
            CheckWholeBlocks(k, data);
            CheckBlock(iv, "iv");
            byte[] output = new byte[data.Length];
            uint c0 = Endian.LoadBe32(iv, 0), c1 = Endian.LoadBe32(iv, 4), c2 = Endian.LoadBe32(iv, 8), c3 = Endian.LoadBe32(iv, 12);
            CbcDecryptCore(k, ref c0, ref c1, ref c2, ref c3, data, 0, data.Length, output, 0);
            return output;
        }

        /// <summary>Encrypts and decrypts alike: xor with AES of a counter. The counter is 16 bytes, big-endian, and carries across all 128 bits.</summary>
        public static byte[] Ctr(AesKey k, byte[] counter, byte[] data)
        {
            Arg.NotNull(k, "k");
            Arg.NotNull(data, "data");
            CheckBlock(counter, "counter");
            byte[] output = new byte[data.Length];
            uint n0 = Endian.LoadBe32(counter, 0), n1 = Endian.LoadBe32(counter, 4), n2 = Endian.LoadBe32(counter, 8), n3 = Endian.LoadBe32(counter, 12);
            CtrCore(k, ref n0, ref n1, ref n2, ref n3, data, 0, data.Length, output, 0);
            return output;
        }

        // ---- caller-buffer forms (PRD 7.3 item 15) ----

        public static void EcbEncrypt(AesKey k, byte[] input, int inOffset, int count, byte[] output, int outOffset)
        {
            CheckInto(k, input, inOffset, count, output, outOffset, true);
            EcbCore(k, true, input, inOffset, count, output, outOffset);
        }

        public static void EcbDecrypt(AesKey k, byte[] input, int inOffset, int count, byte[] output, int outOffset)
        {
            CheckInto(k, input, inOffset, count, output, outOffset, true);
            EcbCore(k, false, input, inOffset, count, output, outOffset);
        }

        public static void CbcEncrypt(AesKey k, byte[] iv, int ivOffset, byte[] input, int inOffset, int count, byte[] output, int outOffset)
        {
            Arg.NotNull(k, "k");
            Arg.Range(iv, ivOffset, BlockSize);
            CheckInto(k, input, inOffset, count, output, outOffset, true);
            uint c0 = Endian.LoadBe32(iv, ivOffset), c1 = Endian.LoadBe32(iv, ivOffset + 4), c2 = Endian.LoadBe32(iv, ivOffset + 8), c3 = Endian.LoadBe32(iv, ivOffset + 12);
            CbcEncryptCore(k, ref c0, ref c1, ref c2, ref c3, input, inOffset, count, output, outOffset);
        }

        public static void CbcDecrypt(AesKey k, byte[] iv, int ivOffset, byte[] input, int inOffset, int count, byte[] output, int outOffset)
        {
            Arg.NotNull(k, "k");
            Arg.Range(iv, ivOffset, BlockSize);
            CheckInto(k, input, inOffset, count, output, outOffset, true);
            uint c0 = Endian.LoadBe32(iv, ivOffset), c1 = Endian.LoadBe32(iv, ivOffset + 4), c2 = Endian.LoadBe32(iv, ivOffset + 8), c3 = Endian.LoadBe32(iv, ivOffset + 12);
            CbcDecryptCore(k, ref c0, ref c1, ref c2, ref c3, input, inOffset, count, output, outOffset);
        }

        /// <summary>CTR into a caller buffer. The counter array is read, never changed; count may end in a partial block.</summary>
        public static void Ctr(AesKey k, byte[] counter, int counterOffset, byte[] input, int inOffset, int count, byte[] output, int outOffset)
        {
            Arg.NotNull(k, "k");
            Arg.Range(counter, counterOffset, BlockSize);
            CheckInto(k, input, inOffset, count, output, outOffset, false);
            uint n0 = Endian.LoadBe32(counter, counterOffset), n1 = Endian.LoadBe32(counter, counterOffset + 4);
            uint n2 = Endian.LoadBe32(counter, counterOffset + 8), n3 = Endian.LoadBe32(counter, counterOffset + 12);
            CtrCore(k, ref n0, ref n1, ref n2, ref n3, input, inOffset, count, output, outOffset);
        }

        // ---- streamed forms: the state object takes the place of the iv or the counter, and moves forward ----

        public static void CbcEncrypt(AesKey k, CbcChain chain, byte[] input, int inOffset, int count, byte[] output, int outOffset)
        {
            Arg.NotNull(chain, "chain");
            CheckInto(k, input, inOffset, count, output, outOffset, true);
            chain.RequireReady();
            CbcEncryptCore(k, ref chain.W0, ref chain.W1, ref chain.W2, ref chain.W3, input, inOffset, count, output, outOffset);
        }

        public static void CbcDecrypt(AesKey k, CbcChain chain, byte[] input, int inOffset, int count, byte[] output, int outOffset)
        {
            Arg.NotNull(chain, "chain");
            CheckInto(k, input, inOffset, count, output, outOffset, true);
            chain.RequireReady();
            CbcDecryptCore(k, ref chain.W0, ref chain.W1, ref chain.W2, ref chain.W3, input, inOffset, count, output, outOffset);
        }

        /// <summary>CTR on a running counter. A call that ends in a partial block processes it and ends the counter: the next message needs Init.</summary>
        public static void Ctr(AesKey k, CtrCounter counter, byte[] input, int inOffset, int count, byte[] output, int outOffset)
        {
            Arg.NotNull(counter, "counter");
            CheckInto(k, input, inOffset, count, output, outOffset, false);
            counter.RequireReady();
            CtrCore(k, ref counter.W0, ref counter.W1, ref counter.W2, ref counter.W3, input, inOffset, count, output, outOffset);
            if (count % BlockSize != 0) counter.End();
        }

        // ---- the cores: no checks; each block is read into locals before its output is written, so the same index is safe ----

        static void EcbCore(AesKey k, bool encrypt, byte[] i, int io, int n, byte[] o, int oo)
        {
            for (int off = 0; off < n; off += BlockSize)
            {
                uint s0 = Endian.LoadBe32(i, io + off), s1 = Endian.LoadBe32(i, io + off + 4), s2 = Endian.LoadBe32(i, io + off + 8), s3 = Endian.LoadBe32(i, io + off + 12);
                if (encrypt) k.EncryptWords(ref s0, ref s1, ref s2, ref s3);
                else k.DecryptWords(ref s0, ref s1, ref s2, ref s3);
                AesKey.StoreBlock(s0, s1, s2, s3, o, oo + off);
            }
        }

        static void CbcEncryptCore(AesKey k, ref uint c0, ref uint c1, ref uint c2, ref uint c3, byte[] i, int io, int n, byte[] o, int oo)
        {
            for (int off = 0; off < n; off += BlockSize)
            {
                uint s0 = c0 ^ Endian.LoadBe32(i, io + off), s1 = c1 ^ Endian.LoadBe32(i, io + off + 4);
                uint s2 = c2 ^ Endian.LoadBe32(i, io + off + 8), s3 = c3 ^ Endian.LoadBe32(i, io + off + 12);
                k.EncryptWords(ref s0, ref s1, ref s2, ref s3);
                AesKey.StoreBlock(s0, s1, s2, s3, o, oo + off);
                c0 = s0; c1 = s1; c2 = s2; c3 = s3;
            }
        }

        static void CbcDecryptCore(AesKey k, ref uint c0, ref uint c1, ref uint c2, ref uint c3, byte[] i, int io, int n, byte[] o, int oo)
        {
            for (int off = 0; off < n; off += BlockSize)
            {
                // The ciphertext block stays in locals: it is the next block's chain, and with the same index its bytes are overwritten.
                uint x0 = Endian.LoadBe32(i, io + off), x1 = Endian.LoadBe32(i, io + off + 4), x2 = Endian.LoadBe32(i, io + off + 8), x3 = Endian.LoadBe32(i, io + off + 12);
                uint s0 = x0, s1 = x1, s2 = x2, s3 = x3;
                k.DecryptWords(ref s0, ref s1, ref s2, ref s3);
                AesKey.StoreBlock(s0 ^ c0, s1 ^ c1, s2 ^ c2, s3 ^ c3, o, oo + off);
                c0 = x0; c1 = x1; c2 = x2; c3 = x3;
            }
        }

        static void CtrCore(AesKey k, ref uint n0, ref uint n1, ref uint n2, ref uint n3, byte[] i, int io, int n, byte[] o, int oo)
        {
            for (int off = 0; off < n; off += BlockSize)
            {
                uint s0 = n0, s1 = n1, s2 = n2, s3 = n3;
                k.EncryptWords(ref s0, ref s1, ref s2, ref s3);
                int take = Math.Min(BlockSize, n - off);
                if (take == BlockSize)
                {
                    uint p0 = Endian.LoadBe32(i, io + off), p1 = Endian.LoadBe32(i, io + off + 4), p2 = Endian.LoadBe32(i, io + off + 8), p3 = Endian.LoadBe32(i, io + off + 12);
                    AesKey.StoreBlock(p0 ^ s0, p1 ^ s1, p2 ^ s2, p3 ^ s3, o, oo + off);
                }
                else
                {
                    for (int b = 0; b < take; b++) o[oo + off + b] = (byte)(i[io + off + b] ^ KeyStreamByte(s0, s1, s2, s3, b));
                }
                // The counter is one 128-bit big-endian number: a carry runs from the low word up.
                if (++n3 == 0 && ++n2 == 0 && ++n1 == 0) ++n0;
            }
        }

        static byte KeyStreamByte(uint s0, uint s1, uint s2, uint s3, int b)
        {
            uint w = b < 4 ? s0 : b < 8 ? s1 : b < 12 ? s2 : s3;
            return (byte)(w >> (24 - 8 * (b % 4)));
        }

        // ---- checks ----

        /// <summary>The checks of a caller-buffer or streamed call, in the order of PRD 7.3 item 15: null, ranges, the block count, the overlap.</summary>
        static void CheckInto(AesKey k, byte[] input, int inOffset, int count, byte[] output, int outOffset, bool wholeBlocks)
        {
            Arg.NotNull(k, "k");
            Arg.Range(input, inOffset, count);
            Arg.Range(output, outOffset, count);
            if (wholeBlocks && count % BlockSize != 0) throw new ArgumentException("this mode takes whole 16-byte blocks", "count");
            Overlap.Refuse(input, inOffset, count, output, outOffset, count);
        }

        static void CheckWholeBlocks(AesKey k, byte[] data)
        {
            Arg.NotNull(k, "k");
            Arg.NotNull(data, "data");
            if (data.Length % BlockSize != 0) throw new ArgumentException("this mode takes whole 16-byte blocks", "data");
        }

        static void CheckBlock(byte[] block, string name)
        {
            Arg.NotNull(block, name);
            if (block.Length != BlockSize) throw new ArgumentException("this value is 16 bytes", name);
        }
    }

    /// <summary>The overlap rule of the caller-buffer forms (PRD 7.1.9), one place for the modes, CMAC and GCM.</summary>
    static class Overlap
    {
        /// <summary>
        /// Throws NetSecException ARG_RANGES_OVERLAP when a and b are the same array, the ranges overlap, and they do not start at the same
        /// index. The same index is legal (the cores read each block before they write it); separate arrays and ranges apart are legal.
        /// </summary>
        public static void Refuse(byte[] a, int ao, int an, byte[] b, int bo, int bn)
        {
            if (a == null || b == null || !ReferenceEquals(a, b) || ao == bo) return;
            if (ao < bo + bn && bo < ao + an)
                throw new NetSecException(NetSecError.Of(ErrorCodes.ArgRangesOverlap, "input and output overlap and do not start at the same index"));
        }
    }
}
