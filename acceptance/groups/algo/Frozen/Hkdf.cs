// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from src/NetSec.Core/Crypto/Hkdf.cs at 5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc (blob sha256 92803d0a9ee2c40667e8f695a16dae497c7e412ebca9d292baadd66ce90c385c). Do not edit.
using System;
using Acceptance.Frozen.Errors;

namespace Acceptance.Frozen.Crypto
{
    /// <summary>HKDF, RFC 5869. Extract condenses input key material into a key. Expand stretches that key into output.</summary>
    public static class Hkdf
    {
        /// <param name="salt">Null means no salt. HMAC pads a short key with zeros, so null gives the RFC's string of zeros.</param>
        public static byte[] Extract(Func<IHash> h, byte[] salt, byte[] ikm)
        {
            return Hmac.Compute(h, salt == null ? new byte[0] : salt, ikm);
        }

        /// <summary>
        /// T(i) = HMAC(prk, T(i-1) + info + i), joined and cut to n bytes. The RFC allows at most 255 blocks.
        /// RFC 5869 section 2.3 requires a prk of at least one hash length. A shorter prk throws HKDF_PRK_TOO_SHORT.
        /// </summary>
        public static byte[] Expand(Func<IHash> h, byte[] prk, byte[] info, int n)
        {
            Arg.NotNull(h, "h");
            Arg.NotNull(prk, "prk");
            Arg.NotNull(info, "info");
            int hashLength = h().DigestSize;
            if (n < 0 || n > 255 * hashLength) throw new ArgumentOutOfRangeException("n", "HKDF output is from 0 to 255 hash lengths");
            if (prk.Length < hashLength)
                throw new NetSecException(NetSecError.Of(ErrorCodes.HkdfPrkTooShort, "the HKDF prk is " + prk.Length + " bytes, and this hash needs at least " + hashLength));

            byte[] output = new byte[n];
            byte[] previous = new byte[0];
            int written = 0;
            for (int i = 1; written < n; i++)
            {
                byte[] message = new byte[previous.Length + info.Length + 1];
                Buffer.BlockCopy(previous, 0, message, 0, previous.Length);
                Buffer.BlockCopy(info, 0, message, previous.Length, info.Length);
                message[message.Length - 1] = (byte)i;

                previous = Hmac.Compute(h, prk, message);
                int take = Math.Min(hashLength, n - written);
                Buffer.BlockCopy(previous, 0, output, written, take);
                written += take;
            }
            return output;
        }
    }
}
