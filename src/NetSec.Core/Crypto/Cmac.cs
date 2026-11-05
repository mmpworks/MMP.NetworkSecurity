using System;

namespace NetSec.Crypto
{
    /// <summary>
    /// AES-CMAC, RFC 4493 and SP 800-38B: CBC with a zero IV, keeping only the last block.
    /// The last block is first xored with subkey K1 when it is full, or padded and xored with K2 when it is not,
    /// so a message and its padded form give different tags.
    /// </summary>
    public static class Cmac
    {
        const int BlockSize = 16;

        public static byte[] Compute(AesKey k, byte[] message)
        {
            Arg.NotNull(k, "k");
            Arg.NotNull(message, "message");

            byte[] k1 = new byte[BlockSize];
            k.EncryptBlock(new byte[BlockSize], 0, k1, 0);
            k1 = Double(k1);
            byte[] k2 = Double(k1);

            int fullBlocksBeforeLast = message.Length == 0 ? 0 : (message.Length - 1) / BlockSize;
            byte[] x = new byte[BlockSize];
            for (int block = 0; block < fullBlocksBeforeLast; block++)
            {
                for (int i = 0; i < BlockSize; i++) x[i] ^= message[block * BlockSize + i];
                k.EncryptBlock(x, 0, x, 0);
            }

            int lastOff = fullBlocksBeforeLast * BlockSize;
            int lastLength = message.Length - lastOff;
            byte[] last = new byte[BlockSize];
            Buffer.BlockCopy(message, lastOff, last, 0, lastLength);
            if (lastLength < BlockSize) last[lastLength] = 0x80;
            byte[] subkey = lastLength == BlockSize ? k1 : k2;
            for (int i = 0; i < BlockSize; i++) x[i] ^= (byte)(last[i] ^ subkey[i]);
            k.EncryptBlock(x, 0, x, 0);
            return x;
        }

        /// <summary>Multiply by x in GF(2^128): shift left one bit, and if the top bit fell off, xor 0x87 into the last byte.</summary>
        static byte[] Double(byte[] v)
        {
            byte[] result = new byte[BlockSize];
            int carry = 0;
            for (int i = BlockSize - 1; i >= 0; i--)
            {
                result[i] = (byte)((v[i] << 1) | carry);
                carry = v[i] >> 7;
            }
            if (carry != 0) result[BlockSize - 1] ^= 0x87;
            return result;
        }
    }
}
