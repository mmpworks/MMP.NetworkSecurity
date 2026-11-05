using System;

namespace NetSec.Crypto
{
    /// <summary>HMAC, RFC 2104: H((key xor opad) + H((key xor ipad) + data)).</summary>
    public static class Hmac
    {
        public static byte[] Compute(Func<IHash> h, byte[] key, byte[] data)
        {
            Arg.NotNull(h, "h");
            Arg.NotNull(key, "key");
            Arg.NotNull(data, "data");

            int blockSize = h().BlockSize;
            byte[] paddedKey = new byte[blockSize];
            byte[] shortKey = key.Length > blockSize ? HashOf(h, key) : key;
            Buffer.BlockCopy(shortKey, 0, paddedKey, 0, shortKey.Length);

            byte[] innerPad = Xored(paddedKey, 0x36);
            IHash inner = h();
            inner.Update(innerPad, 0, innerPad.Length);
            inner.Update(data, 0, data.Length);
            byte[] innerDigest = inner.Finish();

            byte[] outerPad = Xored(paddedKey, 0x5c);
            IHash outer = h();
            outer.Update(outerPad, 0, outerPad.Length);
            outer.Update(innerDigest, 0, innerDigest.Length);
            return outer.Finish();
        }

        static byte[] HashOf(Func<IHash> h, byte[] data)
        {
            IHash hash = h();
            hash.Update(data, 0, data.Length);
            return hash.Finish();
        }

        static byte[] Xored(byte[] bytes, byte mask)
        {
            byte[] result = new byte[bytes.Length];
            for (int i = 0; i < bytes.Length; i++) result[i] = (byte)(bytes[i] ^ mask);
            return result;
        }
    }
}
