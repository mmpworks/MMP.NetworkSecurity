using NetSec.Crypto;

namespace NetSec.Labs
{
    /// <summary>Chapter 1's reply: one key's word rows and one block's walks.</summary>
    public sealed class AesBlockPair
    {
        public int KeyBits;
        public AesKeyWord[] KeyWords;
        public AesBlockWalk Forward;

        /// <summary>Null when no inverse input was given.</summary>
        public AesBlockWalk Inverse;
    }

    /// <summary>Pure. Same input, same output. No session and no socket.</summary>
    public static class AesWalks
    {
        public static AesBlockPair Block(byte[] key, byte[] forwardInput, byte[] inverseInputOrNull)
        {
            AesKey aes = new AesKey(key);
            AesBlockPair pair = new AesBlockPair();
            pair.KeyBits = key.Length * 8;
            pair.KeyWords = aes.WalkKeyExpansion();
            pair.Forward = aes.WalkEncrypt(forwardInput);
            pair.Inverse = inverseInputOrNull == null ? null : aes.WalkDecrypt(inverseInputOrNull);
            return pair;
        }
    }
}
