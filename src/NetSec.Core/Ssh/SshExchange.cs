using System;
using System.Text;
using NetSec.Bytes;
using NetSec.Crypto;

namespace NetSec.Ssh
{
    /// <summary>One suite as data. A lab offers only one name per slot, so each run names what it uses.</summary>
    public sealed class SshAlgorithms
    {
        public readonly string Kex, HostKey, Cipher, Mac;
        public readonly int MacSize;
        public readonly bool IsLegacy;
        public readonly Func<IHash> ExchangeHash, MacHash;

        SshAlgorithms(string kex, string hostKey, string cipher, string mac, int macSize, bool isLegacy, Func<IHash> exchangeHash, Func<IHash> macHash)
        {
            Kex = kex; HostKey = hostKey; Cipher = cipher; Mac = mac; MacSize = macSize; IsLegacy = isLegacy; ExchangeHash = exchangeHash; MacHash = macHash;
        }

        public const string CipherCbc = "aes128-cbc";

        public static readonly SshAlgorithms Modern = new SshAlgorithms(
            "curve25519-sha256", "ssh-ed25519", "aes128-ctr", "hmac-sha2-256", 32, false, Hashes.Sha256, Hashes.Sha256);

        /// <summary>
        /// The suite for the old device. It stays here because a CE build may offer nothing newer. What is weak: SHA-1 has known collision
        /// attacks, ssh-rsa signs with SHA-1, and CBC with a MAC over the plain text has a published plaintext recovery attack
        /// (Albrecht, Paterson and Watson, 2009). HMAC-SHA-1 has no known practical break, and it is old.
        /// </summary>
        public static readonly SshAlgorithms Legacy = new SshAlgorithms(
            "diffie-hellman-group14-sha1", "ssh-rsa", CipherCbc, "hmac-sha1", 20, true, Hashes.Sha1, Hashes.Sha1);

        public string CipherAndMac { get { return Cipher + "," + Mac; } }
    }

    /// <summary>The six values of RFC 4253 section 7.2.</summary>
    public sealed class SshKeyBlock
    {
        public byte[] IvC2S, IvS2C, KeyC2S, KeyS2C, MacC2S, MacS2C;
    }

    /// <summary>Pure computation of the exchange hash and the keys. A test runs these with no engine.</summary>
    public static class SshExchange
    {
        const int CipherKeySize = 16, IvSize = 16;

        /// <summary>RFC 8731 section 3.1 and RFC 5656 section 4: each share is a string, and K is an mpint.</summary>
        public static byte[] Curve25519Hash(Func<IHash> hash, byte[] vc, byte[] vs, byte[] ic, byte[] isv, byte[] ks, byte[] qc, byte[] qs, byte[] k)
        {
            return Finish(hash, Prefix(vc, vs, ic, isv, ks).Prefixed(qc).Prefixed(qs).Mpint(k));
        }

        /// <summary>RFC 4253 section 8: e, f and K are all mpints. DhGroup14 returns 256 fixed bytes, and Mpint fixes the form.</summary>
        public static byte[] Group14Hash(Func<IHash> hash, byte[] vc, byte[] vs, byte[] ic, byte[] isv, byte[] ks, byte[] e, byte[] f, byte[] k)
        {
            return Finish(hash, Prefix(vc, vs, ic, isv, ks).Mpint(e).Mpint(f).Mpint(k));
        }

        static ByteWriter Prefix(byte[] vc, byte[] vs, byte[] ic, byte[] isv, byte[] ks)
        {
            return new ByteWriter().Prefixed(vc).Prefixed(vs).Prefixed(ic).Prefixed(isv).Prefixed(ks);
        }

        static byte[] Finish(Func<IHash> hash, ByteWriter input)
        {
            byte[] bytes = input.ToArray();
            IHash h = hash();
            h.Update(bytes, 0, bytes.Length);
            return h.Finish();
        }

        public static SshKeyBlock DeriveKeys(Func<IHash> hash, byte[] k, byte[] h, byte[] sessionId, int macSize)
        {
            SshKeyBlock block = new SshKeyBlock();
            block.IvC2S = Derive(hash, k, h, 'A', sessionId, IvSize);
            block.IvS2C = Derive(hash, k, h, 'B', sessionId, IvSize);
            block.KeyC2S = Derive(hash, k, h, 'C', sessionId, CipherKeySize);
            block.KeyS2C = Derive(hash, k, h, 'D', sessionId, CipherKeySize);
            block.MacC2S = Derive(hash, k, h, 'E', sessionId, macSize);
            block.MacS2C = Derive(hash, k, h, 'F', sessionId, macSize);
            return block;
        }

        /// <summary>HASH(K, H, letter, session id), then HASH(K, H, all so far) until there are enough bytes.</summary>
        static byte[] Derive(Func<IHash> hash, byte[] k, byte[] h, char letter, byte[] sessionId, int size)
        {
            byte[] kAsMpint = new ByteWriter().Mpint(k).ToArray();
            ByteWriter have = new ByteWriter().Put(Finish(hash, new ByteWriter().Put(kAsMpint).Put(h).U8(letter).Put(sessionId)));
            while (have.Count < size)
                have.Put(Finish(hash, new ByteWriter().Put(kAsMpint).Put(h).Put(have.ToArray())));
            byte[] output = new byte[size];
            Buffer.BlockCopy(have.ToArray(), 0, output, 0, size);
            return output;
        }

        /// <summary>RFC 8731 section 3: the all-zero result means a low-order peer share, and X25519.Mult leaves this check to the protocol.</summary>
        public static bool IsAllZero(byte[] value)
        {
            int any = 0;
            for (int i = 0; i < value.Length; i++) any |= value[i];
            return any == 0;
        }

        /// <summary>A name-list holds comma-separated names. A lab offers one name in each list, so a match means the peer lists that name.</summary>
        public static bool ListHas(byte[] nameList, string name)
        {
            string[] names = Encoding.UTF8.GetString(nameList, 0, nameList.Length).Split(',');
            for (int i = 0; i < names.Length; i++)
                if (names[i] == name) return true;
            return false;
        }
    }
}
