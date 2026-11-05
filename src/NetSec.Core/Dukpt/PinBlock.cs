using System;
using System.Text;
using NetSec.Crypto;

namespace NetSec.Dukpt
{
    /// <summary>
    /// ISO 9564 format 4: an AES PIN block tied to the card number. The PIN field goes through AES, the result is XORed with the PAN field,
    /// and that goes through AES again. The same PIN and PAN give a different block each time, because the PIN field ends in 8 random bytes.
    /// The PIN travels as a string, which cannot be cleared, so the digits stay on the managed heap. The working arrays are cleared after use.
    /// </summary>
    public static class PinBlock
    {
        const int BlockSize = 16;
        const int RandomSize = 8;
        const int MinPinDigits = 4;
        const int MaxPinDigits = 12;
        const int FormatNibble = 4;
        const int FillNibble = 0xA;
        const int ShortestPan = 12;
        const int LongestPan = 19;

        public static byte[] EncryptFormat4(byte[] pinKey, string pin, string pan, byte[] random8)
        {
            if (random8 == null) throw new ArgumentNullException("random8");
            if (random8.Length != RandomSize) throw new ArgumentException("The PIN field takes 8 random bytes.", "random8");
            AesKey aes = new AesKey(pinKey);
            byte[] field = PinField(pin, random8);
            byte[] mixed = new byte[BlockSize];
            aes.EncryptBlock(field, 0, mixed, 0);
            Xor(mixed, PanField(pan));
            byte[] block = new byte[BlockSize];
            aes.EncryptBlock(mixed, 0, block, 0);
            Array.Clear(field, 0, BlockSize);
            Array.Clear(mixed, 0, BlockSize);
            return block;
        }

        /// <summary>
        /// False when the opened field has the wrong shape. A wrong key, a wrong PAN, and a changed block nearly always end here, and the result does not say which.
        /// This is a shape check and gives no integrity: a random field passes with a chance of about 6e-8, and nothing checks the 8 random bytes.
        /// A MAC is the real check, and lesson 9 adds one.
        /// </summary>
        public static bool TryDecryptFormat4(byte[] pinKey, byte[] block, string pan, out string pin)
        {
            pin = null;
            if (block == null) throw new ArgumentNullException("block");
            if (block.Length != BlockSize) return false;
            AesKey aes = new AesKey(pinKey);
            byte[] mixed = new byte[BlockSize];
            aes.DecryptBlock(block, 0, mixed, 0);
            Xor(mixed, PanField(pan));
            byte[] field = new byte[BlockSize];
            aes.DecryptBlock(mixed, 0, field, 0);
            bool opened = TryReadPin(field, out pin);
            Array.Clear(field, 0, BlockSize);
            Array.Clear(mixed, 0, BlockSize);
            return opened;
        }

        /// <summary>Nibbles: format 4, PIN length, PIN digits, then fill A up to nibble 16. Then the 8 random bytes.</summary>
        static byte[] PinField(string pin, byte[] random8)
        {
            if (pin == null) throw new ArgumentNullException("pin");
            if (pin.Length < MinPinDigits || pin.Length > MaxPinDigits || !AllDigits(pin)) throw new ArgumentException("A PIN holds 4 to 12 digits.", "pin");
            byte[] field = new byte[BlockSize];
            SetNibble(field, 0, FormatNibble);
            SetNibble(field, 1, pin.Length);
            for (int i = 0; i < RandomSize * 2 - 2; i++)
                SetNibble(field, i + 2, i < pin.Length ? pin[i] - '0' : FillNibble);
            Buffer.BlockCopy(random8, 0, field, RandomSize, RandomSize);
            return field;
        }

        /// <summary>Nibbles: the count of PAN digits past 12, then the PAN, then zeros. A PAN under 12 digits gets zeros on its left, up to 12, so 12345678901 and 012345678901 share a field.</summary>
        static byte[] PanField(string pan)
        {
            if (pan == null) throw new ArgumentNullException("pan");
            if (pan.Length == 0 || pan.Length > LongestPan || !AllDigits(pan)) throw new ArgumentException("A PAN holds 1 to 19 digits.", "pan");
            string digits = pan.PadLeft(ShortestPan, '0');
            byte[] field = new byte[BlockSize];
            SetNibble(field, 0, digits.Length - ShortestPan);
            for (int i = 0; i < digits.Length; i++) SetNibble(field, i + 1, digits[i] - '0');
            return field;
        }

        static bool TryReadPin(byte[] field, out string pin)
        {
            pin = null;
            int length = Nibble(field, 1);
            if (Nibble(field, 0) != FormatNibble || length < MinPinDigits || length > MaxPinDigits) return false;
            StringBuilder digits = new StringBuilder(length);
            for (int i = 0; i < RandomSize * 2 - 2; i++)
            {
                int nibble = Nibble(field, i + 2);
                if (i < length)
                {
                    if (nibble > 9) return false;
                    digits.Append((char)('0' + nibble));
                }
                else if (nibble != FillNibble) return false;
            }
            pin = digits.ToString();
            return true;
        }

        static bool AllDigits(string text)
        {
            for (int i = 0; i < text.Length; i++)
                if (text[i] < '0' || text[i] > '9') return false;
            return true;
        }

        static int Nibble(byte[] field, int index)
        {
            int value = field[index / 2];
            return index % 2 == 0 ? value >> 4 : value & 15;
        }

        static void SetNibble(byte[] field, int index, int value)
        {
            field[index / 2] |= (byte)(index % 2 == 0 ? value << 4 : value);
        }

        static void Xor(byte[] target, byte[] mask)
        {
            for (int i = 0; i < BlockSize; i++) target[i] ^= mask[i];
        }
    }
}
