using System;

namespace NetSec.Crypto
{
    /// <summary>
    /// AES block modes, SP 800-38A. None of them pads or adds a MAC. The caller owns that, and the lessons show what goes wrong without it.
    /// ECB and CBC take whole blocks only.
    /// </summary>
    public static class Modes
    {
        const int BlockSize = 16;

        public static byte[] EcbEncrypt(AesKey k, byte[] data)
        {
            CheckWholeBlocks(k, data);
            byte[] output = new byte[data.Length];
            for (int off = 0; off < data.Length; off += BlockSize) k.EncryptBlock(data, off, output, off);
            return output;
        }

        public static byte[] CbcEncrypt(AesKey k, byte[] iv, byte[] data)
        {
            CheckWholeBlocks(k, data);
            CheckBlock(iv, "iv");
            byte[] output = new byte[data.Length];
            byte[] previous = (byte[])iv.Clone();
            for (int off = 0; off < data.Length; off += BlockSize)
            {
                for (int i = 0; i < BlockSize; i++) previous[i] ^= data[off + i];
                k.EncryptBlock(previous, 0, output, off);
                Buffer.BlockCopy(output, off, previous, 0, BlockSize);
            }
            return output;
        }

        public static byte[] CbcDecrypt(AesKey k, byte[] iv, byte[] data)
        {
            CheckWholeBlocks(k, data);
            CheckBlock(iv, "iv");
            byte[] output = new byte[data.Length];
            for (int off = 0; off < data.Length; off += BlockSize)
            {
                k.DecryptBlock(data, off, output, off);
                byte[] previous = off == 0 ? iv : data;
                int previousOff = off == 0 ? 0 : off - BlockSize;
                for (int i = 0; i < BlockSize; i++) output[off + i] ^= previous[previousOff + i];
            }
            return output;
        }

        /// <summary>Encrypts and decrypts alike: xor with AES of a counter. The counter is 16 bytes, big-endian, and carries across all 128 bits.</summary>
        public static byte[] Ctr(AesKey k, byte[] counter, byte[] data)
        {
            Arg.NotNull(k, "k");
            Arg.NotNull(data, "data");
            CheckBlock(counter, "counter");
            byte[] output = new byte[data.Length];
            byte[] running = (byte[])counter.Clone();
            byte[] stream = new byte[BlockSize];
            for (int off = 0; off < data.Length; off += BlockSize)
            {
                k.EncryptBlock(running, 0, stream, 0);
                int take = Math.Min(BlockSize, data.Length - off);
                for (int i = 0; i < take; i++) output[off + i] = (byte)(data[off + i] ^ stream[i]);
                Increment(running);
            }
            return output;
        }

        static void Increment(byte[] counter)
        {
            for (int i = BlockSize - 1; i >= 0; i--)
            {
                counter[i]++;
                if (counter[i] != 0) return;
            }
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
}
