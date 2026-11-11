// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from src/NetSec.Core/Crypto/Hashes.cs at 5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc (blob sha256 855afe888fdf234116efe9012490aa624485c69ec9acfed160f370493e6cefe0). Do not edit.
namespace Acceptance.Frozen.Crypto
{
    /// <summary>
    /// Each method returns a new hash. MD5 and SHA-1 have known collision attacks. They are here because
    /// the TLS 1.1 key derivation and the SSH legacy suite use them, and the lessons show that.
    /// </summary>
    public static class Hashes
    {
        public static IHash Md5() { return new Md5Hash(); }
        public static IHash Sha1() { return new Sha1Hash(); }
        public static IHash Sha256() { return new Sha256Hash(); }

        /// <summary>
        /// Teaching entry point for the length-extension attack in lesson 2. No protocol in this course calls it.
        /// A SHA-256 digest is the whole internal state, so this continues a hash from its digest with no knowledge of the message.
        /// bytesAlreadyHashed counts the message and its padding, is a multiple of 64, and goes into the length that Finish writes.
        /// HMAC is not open to this attack: its outer hash covers the inner digest under the key.
        /// </summary>
        public static IHash Sha256Resume(byte[] digest, long bytesAlreadyHashed) { return Sha256Hash.Resume(digest, bytesAlreadyHashed); }

        public static IHash Sha384() { return Sha512Hash.New384(); }
        public static IHash Sha512() { return Sha512Hash.New512(); }
        public static IHash Sha3_256() { return new Sha3Hash(32); }
        public static IHash Sha3_512() { return new Sha3Hash(64); }
    }
}
