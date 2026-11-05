using System;

namespace NetSec.Crypto
{
    /// <summary>
    /// Triple DES, SP 800-67: encrypt with key 1, decrypt with key 2, encrypt with key 3.
    /// A 16-byte key is keys 1 and 2, and key 3 repeats key 1. A 24-byte key is all three.
    /// </summary>
    public sealed class TdesKey
    {
        const int BlockSize = 8;

        readonly ulong[] _key1, _key2, _key3;

        public TdesKey(byte[] key)
        {
            Arg.NotNull(key, "key");
            if (key.Length != 16 && key.Length != 24) throw new ArgumentException("a TDES key is 16 or 24 bytes", "key");
            _key1 = Des.Schedule(key, 0);
            _key2 = Des.Schedule(key, 8);
            _key3 = key.Length == 24 ? Des.Schedule(key, 16) : _key1;
        }

        public void EncryptBlock(byte[] i, int io, byte[] o, int oo)
        {
            Arg.Range(i, io, BlockSize);
            Arg.Range(o, oo, BlockSize);
            ulong block = Endian.LoadBe64(i, io);
            Endian.StoreBe64(Des.Encrypt(Des.Decrypt(Des.Encrypt(block, _key1), _key2), _key3), o, oo);
        }

        public void DecryptBlock(byte[] i, int io, byte[] o, int oo)
        {
            Arg.Range(i, io, BlockSize);
            Arg.Range(o, oo, BlockSize);
            ulong block = Endian.LoadBe64(i, io);
            Endian.StoreBe64(Des.Decrypt(Des.Encrypt(Des.Decrypt(block, _key3), _key2), _key1), o, oo);
        }
    }
}
