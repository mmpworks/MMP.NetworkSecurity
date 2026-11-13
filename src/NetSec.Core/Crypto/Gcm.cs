using System;

namespace NetSec.Crypto
{
    /// <summary>
    /// AES-GCM, SP 800-38D, with a 12-byte nonce and a 16-byte tag, the shape TLS 1.3 uses.
    /// Counter mode encrypts. GHASH over the additional data and the ciphertext, masked by AES of the first counter, makes the tag.
    /// A byte array cannot reach the 2^36 byte limit, so the 32-bit counter cannot wrap.
    /// Rule: use one key and nonce pair for one message only. A second message under the same pair exposes the xor of the
    /// two plaintexts and lets an attacker forge tags. Gcm keeps no state, so it cannot detect reuse. The caller owns this rule.
    /// These static forms are for single calls: each one builds a GcmKey (H and its table), which costs bytes on every call (PRD 7.3
    /// item 16, a recorded tradeoff with a byte budget). Code that seals many records under one key holds a GcmKey (item 12).
    /// </summary>
    public static class Gcm
    {
        const int NonceSize = 12;
        const int StaticWidth = 4;   // a 4-bit table per call (312 B); a held GcmKey takes Gf128.KeyWidth

        /// <summary>Returns the ciphertext followed by the 16-byte tag.</summary>
        public static byte[] Seal(AesKey k, byte[] nonce, byte[] aad, byte[] plain)
        {
            CheckArguments(k, nonce, aad);
            Arg.NotNull(plain, "plain");
            return new GcmKey(k, StaticWidth).Seal(nonce, aad, plain);
        }

        /// <summary>Checks the tag before it decrypts anything. On a bad tag it returns false and plain is null, so no unchecked bytes leave here.</summary>
        public static bool TryOpen(AesKey k, byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain)
        {
            plain = null;
            CheckArguments(k, nonce, aad);
            Arg.NotNull(sealedBytes, "sealedBytes");
            return new GcmKey(k, StaticWidth).TryOpen(nonce, aad, sealedBytes, out plain);
        }

        /// <summary>The checks of the forms that take a whole nonce array: 5c5d4a4 accepts only a 12-byte nonce.</summary>
        internal static void CheckArguments(AesKey k, byte[] nonce, byte[] aad)
        {
            Arg.NotNull(k, "k");
            Arg.NotNull(nonce, "nonce");
            Arg.NotNull(aad, "aad");
            if (nonce.Length != NonceSize) throw new ArgumentException("the GCM nonce here is 12 bytes", "nonce");
        }
    }
}
