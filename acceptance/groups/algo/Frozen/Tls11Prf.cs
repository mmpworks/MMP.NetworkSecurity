// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from src/NetSec.Core/Tls11/Tls11Prf.cs at 5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc (blob sha256 a2394d99ca45fe7e3ba7a6aaed7661b06a18a10da84aa25a64f40ba989764422). Do not edit.
using System;
using System.Text;
using Acceptance.Frozen.Bytes;
using Acceptance.Frozen.Crypto;

namespace Acceptance.Frozen.Tls11
{
    /// <summary>The four keys of one connection, cut from the key block in RFC 4346 section 6.3 order. TLS 1.1 sends each IV on the wire, so the block holds no IV.</summary>
    public sealed class Tls11KeyBlock
    {
        public const int MacSize = 20, KeySize = 16;
        public byte[] ClientMac, ServerMac, ClientKey, ServerKey;
    }

    /// <summary>
    /// The PRF of RFC 4346 section 5. It runs P_MD5 over the first half of the secret and P_SHA-1 over the second half, then xors them.
    /// When the secret has an odd length, the two halves share the middle byte. Pure: no state and no side effect.
    /// </summary>
    public static class Tls11Prf
    {
        public const int MasterSize = 48, FinishedSize = 12;
        public const string ClientFinished = "client finished", ServerFinished = "server finished";

        public static byte[] Derive(byte[] secret, string label, byte[] seed, int count)
        {
            if (secret == null) throw new ArgumentNullException("secret");
            int half = (secret.Length + 1) / 2;
            byte[] first = new byte[half], second = new byte[half];
            Buffer.BlockCopy(secret, 0, first, 0, half);
            Buffer.BlockCopy(secret, secret.Length - half, second, 0, half);
            byte[] labelled = new ByteWriter().Put(Encoding.UTF8.GetBytes(label)).Put(seed).ToArray();
            byte[] md5 = PHash(Hashes.Md5, first, labelled, count);
            byte[] sha1 = PHash(Hashes.Sha1, second, labelled, count);
            for (int i = 0; i < count; i++) md5[i] ^= sha1[i];
            return md5;
        }

        /// <summary>A(0) is the seed and A(i) is HMAC(secret, A(i-1)). The output joins HMAC(secret, A(i) + seed) for i from 1.</summary>
        static byte[] PHash(Func<IHash> hash, byte[] secret, byte[] seed, int count)
        {
            byte[] output = new byte[count];
            byte[] a = seed;
            for (int filled = 0; filled < count; )
            {
                a = Hmac.Compute(hash, secret, a);
                byte[] block = Hmac.Compute(hash, secret, new ByteWriter().Put(a).Put(seed).ToArray());
                int take = Math.Min(block.Length, count - filled);
                Buffer.BlockCopy(block, 0, output, filled, take);
                filled += take;
            }
            return output;
        }

        public static byte[] MasterSecret(byte[] premaster, byte[] clientRandom, byte[] serverRandom)
        {
            return Derive(premaster, "master secret", new ByteWriter().Put(clientRandom).Put(serverRandom).ToArray(), MasterSize);
        }

        /// <summary>The seed takes the server random first here, the reverse of the master secret.</summary>
        public static Tls11KeyBlock KeyBlock(byte[] master, byte[] clientRandom, byte[] serverRandom)
        {
            int size = 2 * (Tls11KeyBlock.MacSize + Tls11KeyBlock.KeySize);
            byte[] block = Derive(master, "key expansion", new ByteWriter().Put(serverRandom).Put(clientRandom).ToArray(), size);
            Tls11KeyBlock keys = new Tls11KeyBlock();
            keys.ClientMac = Slice(block, 0, Tls11KeyBlock.MacSize);
            keys.ServerMac = Slice(block, Tls11KeyBlock.MacSize, Tls11KeyBlock.MacSize);
            keys.ClientKey = Slice(block, 2 * Tls11KeyBlock.MacSize, Tls11KeyBlock.KeySize);
            keys.ServerKey = Slice(block, 2 * Tls11KeyBlock.MacSize + Tls11KeyBlock.KeySize, Tls11KeyBlock.KeySize);
            return keys;
        }

        /// <param name="transcriptDigest">MD5 of the transcript, then SHA-1 of the transcript (36 bytes).</param>
        public static byte[] FinishedData(byte[] master, string label, byte[] transcriptDigest)
        {
            return Derive(master, label, transcriptDigest, FinishedSize);
        }

        /// <summary>MD5 of the bytes, then SHA-1 of the bytes. RFC 4346 uses this pair for the transcript and for an RSA signature.</summary>
        public static byte[] Md5Sha1(byte[] data)
        {
            return new ByteWriter().Put(Digest(Hashes.Md5(), data)).Put(Digest(Hashes.Sha1(), data)).ToArray();
        }

        static byte[] Digest(IHash hash, byte[] data)
        {
            hash.Update(data, 0, data.Length);
            return hash.Finish();
        }

        static byte[] Slice(byte[] bytes, int offset, int count)
        {
            byte[] part = new byte[count];
            Buffer.BlockCopy(bytes, offset, part, 0, count);
            return part;
        }
    }
}
