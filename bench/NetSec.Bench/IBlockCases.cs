using System;

namespace NetSec.Bench;

/// <summary>
/// The per-block cases of AO-5 and AO-6, for one copy of the code. Each method makes its key objects at once, outside the timer, and
/// returns the one operation to time as an <see cref="Action"/>, so a case pays the same delegate call on both copies and nothing more.
/// Two copies implement it: the product (<see cref="Files.ProductCode"/>) and Echo's frozen 5c5d4a4 copy (<see cref="Files.FrozenCode"/>).
/// </summary>
interface IBlockCases
{
    string Name { get; }
    Action AesEncryptBlock(byte[] key, byte[] input, byte[] output);
    Action AesDecryptBlock(byte[] key, byte[] input, byte[] output);
    Action AesKeySetup(byte[] key);
    Action Ecb(byte[] key, byte[] message);
    Action CbcEncrypt(byte[] key, byte[] iv, byte[] message);
    Action CbcDecrypt(byte[] key, byte[] iv, byte[] message);
    Action Ctr(byte[] key, byte[] counter, byte[] message);
    Action GcmSeal(byte[] key, byte[] nonce, byte[] aad, byte[] message);
    Action GcmOpen(byte[] key, byte[] nonce, byte[] aad, byte[] message);
    Action Cmac(byte[] key, byte[] message);
    Action TdesEncryptBlock(byte[] key, byte[] input, byte[] output);
    Action TdesDecryptBlock(byte[] key, byte[] input, byte[] output);
    Action TdesKeySetup(byte[] key);

    /// <summary>One whole hash of the message: new state, one Update, Finish. Names: md5, sha1, sha256, sha512, sha3-256.</summary>
    Action Hash(string name, byte[] message);

    /// <summary>Update only, on one hash state made at once: each call adds <paramref name="blocks"/> blocks of the hash's block size.</summary>
    Action HashUpdate(string name, int blocks);
    int HashBlockSize(string name);
    Action Shake128(byte[] message, int outputBytes);
    Action HmacSha256(byte[] key, byte[] message);
    Action DukptDeriveWorkingKey(byte[] bdk, byte[] ksn);
}
