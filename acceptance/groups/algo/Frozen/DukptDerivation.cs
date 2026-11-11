// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from src/NetSec.Core/Dukpt/DukptDerivation.cs at 5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc (blob sha256 d5dd254ab0cc13b4193e6981e6c3968938968af66c3d18b118195687dad5da2f). Do not edit.
using System;
using Acceptance.Frozen.Crypto;

namespace Acceptance.Frozen.Dukpt
{
    /// <summary>The usage codes of ANSI X9.24-3-2017. The value goes into the derivation data.</summary>
    public enum DukptKeyUsage : ushort
    {
        KeyEncryption = 0x0002,
        PinEncryption = 0x1000,
        MacGeneration = 0x2000,
        MacVerification = 0x2001,
        MacBothWays = 0x2002,
        DataEncrypt = 0x3000,
        DataDecrypt = 0x3001,
        DataBothWays = 0x3002,
    }

    /// <summary>The algorithm codes of ANSI X9.24-3-2017.</summary>
    public enum DukptKeyType : ushort
    {
        Aes128 = 2,
        Aes192 = 3,
        Aes256 = 4,
    }

    /// <summary>The key derivation function both sides share. It is pure: bytes in, new bytes out.</summary>
    static class DukptDerivation
    {
        public const int InitialKeyIdSize = 8;
        public const int KsnSize = 12;
        const int BlockSize = 16;
        const ushort KeyDerivationUsage = 0x8000;
        const ushort InitialKeyUsage = 0x8001;

        public static byte[] InitialKey(byte[] bdk, byte[] initialKeyId)
        {
            byte[] data = NewData(InitialKeyUsage, TypeOf(bdk));
            Buffer.BlockCopy(initialKeyId, 0, data, 8, InitialKeyIdSize);
            return DeriveKey(bdk, TypeOf(bdk), data);
        }

        /// <summary>The next intermediate derivation key: its parent's key, for the counter value that adds one more 1 bit.</summary>
        public static byte[] Intermediate(byte[] parent, byte[] initialKeyId, uint counter)
        {
            DukptKeyType type = TypeOf(parent);
            return DeriveKey(parent, type, CounterData(KeyDerivationUsage, type, initialKeyId, counter));
        }

        public static byte[] Working(byte[] derivationKey, byte[] initialKeyId, uint counter, DukptKeyUsage usage, DukptKeyType type)
        {
            return DeriveKey(derivationKey, type, CounterData((ushort)usage, type, initialKeyId, counter));
        }

        /// <summary>Walks from a key at the startBit level down to the counter's own derivation key, one 1 bit at a time, high bit first.</summary>
        public static byte[] WalkDown(byte[] key, byte[] initialKeyId, uint counter, int startBit)
        {
            byte[] current = key;
            uint reached = startBit >= 32 ? 0 : counter & ~((1u << startBit) - 1);
            for (int bit = startBit - 1; bit >= 0; bit--)
            {
                uint mask = 1u << bit;
                if ((counter & mask) == 0) continue;
                reached |= mask;
                current = Intermediate(current, initialKeyId, reached);
            }
            return current;
        }

        public static byte[] Ksn(byte[] initialKeyId, uint counter)
        {
            byte[] ksn = new byte[KsnSize];
            Buffer.BlockCopy(initialKeyId, 0, ksn, 0, InitialKeyIdSize);
            ksn[8] = (byte)(counter >> 24);
            ksn[9] = (byte)(counter >> 16);
            ksn[10] = (byte)(counter >> 8);
            ksn[11] = (byte)counter;
            return ksn;
        }

        public static uint CounterOf(byte[] ksn)
        {
            if (ksn == null) throw new ArgumentNullException("ksn");
            if (ksn.Length != KsnSize) throw new ArgumentException("A KSN holds 12 bytes.", "ksn");
            return ((uint)ksn[8] << 24) | ((uint)ksn[9] << 16) | ((uint)ksn[10] << 8) | ksn[11];
        }

        public static DukptKeyType TypeOf(byte[] key)
        {
            if (key == null) throw new ArgumentNullException("key");
            switch (key.Length)
            {
                case 16: return DukptKeyType.Aes128;
                case 24: return DukptKeyType.Aes192;
                case 32: return DukptKeyType.Aes256;
                default: throw new ArgumentException("A DUKPT AES key holds 16, 24 or 32 bytes.", "key");
            }
        }

        public static void RequireInitialKeyId(byte[] initialKeyId)
        {
            if (initialKeyId == null) throw new ArgumentNullException("initialKeyId");
            if (initialKeyId.Length != InitialKeyIdSize) throw new ArgumentException("An initial key id holds 8 bytes.", "initialKeyId");
        }

        static byte[] CounterData(ushort usage, DukptKeyType type, byte[] initialKeyId, uint counter)
        {
            byte[] data = NewData(usage, type);
            Buffer.BlockCopy(initialKeyId, 4, data, 8, 4);
            data[12] = (byte)(counter >> 24);
            data[13] = (byte)(counter >> 16);
            data[14] = (byte)(counter >> 8);
            data[15] = (byte)counter;
            return data;
        }

        /// <summary>Bytes 0 to 7: version 1, block counter, usage, algorithm, key length in bits. The caller fills bytes 8 to 15.</summary>
        static byte[] NewData(ushort usage, DukptKeyType type)
        {
            int bits = KeyBytes(type) * 8;
            byte[] data = new byte[BlockSize];
            data[0] = 1;
            data[1] = 1;
            data[2] = (byte)(usage >> 8);
            data[3] = (byte)usage;
            data[4] = (byte)((ushort)type >> 8);
            data[5] = (byte)type;
            data[6] = (byte)(bits >> 8);
            data[7] = (byte)bits;
            return data;
        }

        /// <summary>AES-ECB of the data, one block per 16 key bytes. Byte 1 of the data counts the blocks. Output past the key length is dropped.</summary>
        static byte[] DeriveKey(byte[] derivationKey, DukptKeyType type, byte[] data)
        {
            int length = KeyBytes(type);
            AesKey aes = new AesKey(derivationKey);
            byte[] output = new byte[length];
            byte[] block = new byte[BlockSize];
            for (int done = 0, count = 1; done < length; done += BlockSize, count++)
            {
                data[1] = (byte)count;
                aes.EncryptBlock(data, 0, block, 0);
                Buffer.BlockCopy(block, 0, output, done, Math.Min(BlockSize, length - done));
            }
            return output;
        }

        static int KeyBytes(DukptKeyType type)
        {
            switch (type)
            {
                case DukptKeyType.Aes128: return 16;
                case DukptKeyType.Aes192: return 24;
                case DukptKeyType.Aes256: return 32;
                default: throw new ArgumentException("Unknown DUKPT key type.", "type");
            }
        }
    }
}
