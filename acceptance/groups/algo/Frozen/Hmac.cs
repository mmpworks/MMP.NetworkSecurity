// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from src/NetSec.Core/Crypto/Hmac.cs at 5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc (blob sha256 10194dbcf2bb0ceec75541734d3bd47e994083d2dd185ee0ea34fa46a9dad2eb). Do not edit.
using System;

namespace Acceptance.Frozen.Crypto
{
    /// <summary>The steps of one HMAC, for the walk: the key as used (hashed first when longer than a block), padded to a block, then each pass.</summary>
    internal sealed class HmacTrace
    {
        public bool KeyHashed;
        public byte[] KeyUsed, PaddedKey, InnerPad, InnerDigest, OuterPad, Mac;
    }

    /// <summary>HMAC, RFC 2104: H((key xor opad) + H((key xor ipad) + data)).</summary>
    public static class Hmac
    {
        /// <summary>
        /// True when tag is the full HMAC of data. Use this and never a plain compare, which can stop at the first wrong byte.
        /// A tag of another length gives false. A truncated tag is out of scope here.
        /// </summary>
        public static bool Verify(Func<IHash> h, byte[] key, byte[] data, byte[] tag)
        {
            Arg.NotNull(tag, "tag");
            byte[] expected = Compute(h, key, data);
            return tag.Length == expected.Length && ConstantTime.Equal(expected, 0, tag, 0, expected.Length);
        }

        public static byte[] Compute(Func<IHash> h, byte[] key, byte[] data) { return Compute(h, key, data, null); }

        internal static byte[] Compute(Func<IHash> h, byte[] key, byte[] data, HmacTrace trace)
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
            byte[] mac = outer.Finish();
            if (trace != null)
            {
                trace.KeyHashed = key.Length > blockSize;
                trace.KeyUsed = (byte[])shortKey.Clone();
                trace.PaddedKey = paddedKey;
                trace.InnerPad = innerPad;
                trace.InnerDigest = innerDigest;
                trace.OuterPad = outerPad;
                trace.Mac = (byte[])mac.Clone();
            }
            return mac;
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
