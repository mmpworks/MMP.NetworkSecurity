// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from src/NetSec.Core/Crypto/IHash.cs at 5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc (blob sha256 397709480b63ed7c3a1e597283254c4d41a34b7a44e0045d2af830f6511aea29). Do not edit.
namespace Acceptance.Frozen.Crypto
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
