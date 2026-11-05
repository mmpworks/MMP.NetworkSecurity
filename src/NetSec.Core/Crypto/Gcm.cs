using System;

namespace NetSec.Crypto
{
    /// <summary>
    /// AES-GCM, SP 800-38D, with a 12-byte nonce and a 16-byte tag, the shape TLS 1.3 uses.
    /// Counter mode encrypts. GHASH over the additional data and the ciphertext, masked by AES of the first counter, makes the tag.
    /// A byte array cannot reach the 2^36 byte limit, so the 32-bit counter cannot wrap.
    /// </summary>
    public static class Gcm
    {
        const int BlockSize = 16;
        const int NonceSize = 12;
        const int TagSize = 16;

        /// <summary>Returns the ciphertext followed by the 16-byte tag.</summary>
        public static byte[] Seal(AesKey k, byte[] nonce, byte[] aad, byte[] plain)
        {
            CheckArguments(k, nonce, aad);
            Arg.NotNull(plain, "plain");

            byte[] sealedBytes = new byte[plain.Length + TagSize];
            CounterCrypt(k, nonce, plain, sealedBytes, plain.Length);
            byte[] tag = ComputeTag(k, nonce, aad, sealedBytes, plain.Length);
            Buffer.BlockCopy(tag, 0, sealedBytes, plain.Length, TagSize);
            return sealedBytes;
        }

        /// <summary>Checks the tag before it decrypts anything. On a bad tag it returns false and plain is null, so no unchecked bytes leave here.</summary>
        public static bool TryOpen(AesKey k, byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain)
        {
            plain = null;
            CheckArguments(k, nonce, aad);
            Arg.NotNull(sealedBytes, "sealedBytes");
            if (sealedBytes.Length < TagSize) return false;

            int cipherLength = sealedBytes.Length - TagSize;
            byte[] tag = ComputeTag(k, nonce, aad, sealedBytes, cipherLength);
            if (!ConstantTime.Equal(tag, 0, sealedBytes, cipherLength, TagSize)) return false;

            plain = new byte[cipherLength];
            CounterCrypt(k, nonce, sealedBytes, plain, cipherLength);
            return true;
        }

        static byte[] ComputeTag(AesKey k, byte[] nonce, byte[] aad, byte[] cipher, int cipherLength)
        {
            byte[] hashKey = new byte[BlockSize];
            k.EncryptBlock(hashKey, 0, hashKey, 0);

            byte[] tag = Ghash(hashKey, aad, cipher, cipherLength);
            byte[] mask = new byte[BlockSize];
            k.EncryptBlock(FirstCounter(nonce), 0, mask, 0);
            for (int i = 0; i < BlockSize; i++) tag[i] ^= mask[i];
            return tag;
        }

        /// <summary>The additional data, zero padded, then the ciphertext, zero padded, then both lengths in bits.</summary>
        static byte[] Ghash(byte[] hashKey, byte[] aad, byte[] cipher, int cipherLength)
        {
            ulong hHi = Endian.LoadBe64(hashKey, 0), hLo = Endian.LoadBe64(hashKey, 8);
            ulong yHi = 0, yLo = 0;
            Absorb(aad, aad.Length, hHi, hLo, ref yHi, ref yLo);
            Absorb(cipher, cipherLength, hHi, hLo, ref yHi, ref yLo);
            Gf128.Multiply(yHi ^ ((ulong)aad.Length << 3), yLo ^ ((ulong)cipherLength << 3), hHi, hLo, out yHi, out yLo);

            byte[] result = new byte[BlockSize];
            Endian.StoreBe64(yHi, result, 0);
            Endian.StoreBe64(yLo, result, 8);
            return result;
        }

        static void Absorb(byte[] data, int length, ulong hHi, ulong hLo, ref ulong yHi, ref ulong yLo)
        {
            byte[] block = new byte[BlockSize];
            for (int off = 0; off < length; off += BlockSize)
            {
                int take = Math.Min(BlockSize, length - off);
                Array.Clear(block, 0, BlockSize);
                Buffer.BlockCopy(data, off, block, 0, take);
                Gf128.Multiply(yHi ^ Endian.LoadBe64(block, 0), yLo ^ Endian.LoadBe64(block, 8), hHi, hLo, out yHi, out yLo);
            }
        }

        /// <summary>Counter mode that starts one past the first counter. It adds to the low 32 bits only (inc32), unlike Modes.Ctr.</summary>
        static void CounterCrypt(AesKey k, byte[] nonce, byte[] input, byte[] output, int length)
        {
            byte[] counter = FirstCounter(nonce);
            byte[] stream = new byte[BlockSize];
            uint count = 1;
            for (int off = 0; off < length; off += BlockSize)
            {
                count++;
                Endian.StoreBe32(count, counter, NonceSize);
                k.EncryptBlock(counter, 0, stream, 0);
                int take = Math.Min(BlockSize, length - off);
                for (int i = 0; i < take; i++) output[off + i] = (byte)(input[off + i] ^ stream[i]);
            }
        }

        /// <summary>J0 for a 12-byte nonce: the nonce, then a 32-bit 1.</summary>
        static byte[] FirstCounter(byte[] nonce)
        {
            byte[] counter = new byte[BlockSize];
            Buffer.BlockCopy(nonce, 0, counter, 0, NonceSize);
            counter[BlockSize - 1] = 1;
            return counter;
        }

        static void CheckArguments(AesKey k, byte[] nonce, byte[] aad)
        {
            Arg.NotNull(k, "k");
            Arg.NotNull(nonce, "nonce");
            Arg.NotNull(aad, "aad");
            if (nonce.Length != NonceSize) throw new ArgumentException("the GCM nonce here is 12 bytes", "nonce");
        }
    }
}
