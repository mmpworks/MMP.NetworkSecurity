using System;
using NetSec.Crypto;

namespace NetSec.Tls13
{
    public enum Tls13Group { X25519, X25519MlKem768 }

    /// <summary>One row per cipher suite this engine offers. A suite names its hash and its AES key size.</summary>
    public sealed class Tls13Suite
    {
        public readonly int Code;
        public readonly string Name;
        public readonly Func<IHash> Hash;
        public readonly int KeyLength;

        Tls13Suite(int code, string name, Func<IHash> hash, int keyLength)
        {
            Code = code; Name = name; Hash = hash; KeyLength = keyLength;
        }

        public static readonly Tls13Suite Aes128 = new Tls13Suite(0x1301, "TLS_AES_128_GCM_SHA256", Hashes.Sha256, 16);
        public static readonly Tls13Suite Aes256 = new Tls13Suite(0x1302, "TLS_AES_256_GCM_SHA384", Hashes.Sha384, 32);
        public static readonly Tls13Suite[] All = { Aes128, Aes256 };

        public static Tls13Suite Find(int code)
        {
            for (int i = 0; i < All.Length; i++)
                if (All[i].Code == code) return All[i];
            return null;
        }
    }

    public static class Tls13GroupInfo
    {
        public const int X25519Code = 0x001D;
        public const int HybridCode = 0x11EC;

        public static int Code(Tls13Group group) { return group == Tls13Group.X25519 ? X25519Code : HybridCode; }
        public static string Name(Tls13Group group) { return group == Tls13Group.X25519 ? "X25519" : "X25519MLKEM768"; }
    }
}
