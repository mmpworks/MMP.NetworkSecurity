using System;
using System.Security.Cryptography;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// A host-side AES DUKPT written for the self-test and for the bridge clauses (BCL AES-ECB). It follows the derive loop printed in the X9.24-3
    /// test-vector supplement (section 2.3: key = AES-ECB(parent, derivation data)). It lets the self-test run the
    /// A3 vector clauses and prove that the vector file and the clause code agree with a second implementation.
    /// The terminal side (future key registers) has no reference here, so those clauses report NOT RUN in the self-test.
    /// </summary>
    public static class DukptReference
    {
        static byte[] Ecb(byte[] key, byte[] block)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key; aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None;
                using (ICryptoTransform t = aes.CreateEncryptor()) return t.TransformFinalBlock(block, 0, block.Length);
            }
        }

        static byte[] EcbDec(byte[] key, byte[] block)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key; aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None;
                using (ICryptoTransform t = aes.CreateDecryptor()) return t.TransformFinalBlock(block, 0, block.Length);
            }
        }

        static byte[] Derive(byte[] key, int usage, int outBytes, byte[] tail, byte[] counter4)
        {
            int alg = outBytes == 16 ? 2 : 4, bits = outBytes * 8;
            byte[] result = new byte[0];
            for (int i = 1; i <= (outBytes + 15) / 16; i++)
            {
                byte[] head = new byte[] { 1, (byte)i, (byte)(usage >> 8), (byte)usage, (byte)(alg >> 8), (byte)alg, (byte)(bits >> 8), (byte)bits };
                result = Hex.Concat(result, Ecb(key, Hex.Concat(head, tail, counter4)));
            }
            return Hex.Slice(result, 0, outBytes);
        }

        static byte[] Be(uint v) { return new byte[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v }; }

        public static byte[] InitialKey(byte[] bdk, byte[] ikid) { return Derive(bdk, 0x8001, bdk.Length, ikid, new byte[0]); }

        public static byte[] DerivationKey(byte[] bdk, byte[] ikid, uint counter)
        {
            byte[] key = InitialKey(bdk, ikid);
            uint working = 0;
            for (int bit = 31; bit >= 0; bit--)
            {
                uint mask = 1u << bit;
                if ((counter & mask) == 0) continue;
                working |= mask;
                key = Derive(key, 0x8000, key.Length, Hex.Slice(ikid, 4, 4), Be(working));
            }
            return key;
        }

        public static byte[] WorkingKey(byte[] bdk, byte[] ikid, uint counter, int use, int keyBytes)
        {
            return Derive(DerivationKey(bdk, ikid, counter), use, keyBytes, Hex.Slice(ikid, 4, 4), Be(counter));
        }


        static byte[] PanField(string pan)
        {
            string nibbles = (pan.Length - 12).ToString("x") + pan;
            nibbles = nibbles.PadRight(32, '0');
            return Hex.Decode(nibbles);
        }

        public static byte[] PinBlockEncrypt(byte[] pinKey, string pin, string pan, byte[] random8)
        {
            string nibbles = "4" + pin.Length.ToString("x") + pin;
            nibbles = nibbles.PadRight(16, 'A');
            byte[] pinField = Hex.Concat(Hex.Decode(nibbles), random8);
            byte[] a = Ecb(pinKey, pinField);
            byte[] pf = PanField(pan);
            byte[] b = new byte[16];
            for (int i = 0; i < 16; i++) b[i] = (byte)(a[i] ^ pf[i]);
            return Ecb(pinKey, b);
        }

        public static string PinBlockDecrypt(byte[] pinKey, byte[] block, string pan)
        {
            byte[] b = EcbDec(pinKey, block);
            byte[] pf = PanField(pan);
            byte[] a = new byte[16];
            for (int i = 0; i < 16; i++) a[i] = (byte)(b[i] ^ pf[i]);
            string field = Hex.Encode(EcbDec(pinKey, a));
            if (field[0] != '4') return null;
            int len = Convert.ToInt32(field.Substring(1, 1), 16);
            if (len < 4 || len > 12) return null;
            string pin = field.Substring(2, len);
            foreach (char ch in pin) if (ch < '0' || ch > '9') return null;
            return pin;
        }
    }
}
