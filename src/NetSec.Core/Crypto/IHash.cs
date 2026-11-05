namespace NetSec.Crypto
{
    /// <summary>A running hash. Clone lets a protocol read a transcript hash and keep adding to the transcript.</summary>
    public interface IHash
    {
        int DigestSize { get; }
        int BlockSize { get; }
        void Update(byte[] b, int off, int n);

        /// <summary>Ends this hash and returns the digest. Update or Finish after this throws. Clone first to keep going.</summary>
        byte[] Finish();

        IHash Clone();
    }
}
