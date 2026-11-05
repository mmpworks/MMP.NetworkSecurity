namespace NetSec.Crypto
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
        public static IHash Sha384() { return Sha512Hash.New384(); }
        public static IHash Sha512() { return Sha512Hash.New512(); }
        public static IHash Sha3_256() { return new Sha3Hash(32); }
        public static IHash Sha3_512() { return new Sha3Hash(64); }
    }
}
