using System;
using NetSec.Bytes;
using NetSec.Keys;

namespace NetSec.Pki
{
    /// <summary>The SSH public key blob of RFC 4253 section 6.6 and RFC 8709. OpenSshFile writes the key files.</summary>
    public static class SshKeyBlob
    {
        public const string Ed25519Name = "ssh-ed25519";
        public const string RsaName = "ssh-rsa";

        public static byte[] Ed25519(byte[] publicKey)
        {
            return new ByteWriter().Prefixed(Ed25519Name).Prefixed(publicKey).ToArray();
        }

        public static byte[] Rsa(byte[] n, byte[] e)
        {
            return new ByteWriter().Prefixed(RsaName).Mpint(e).Mpint(n).ToArray();
        }

        /// <summary>The blob of an Ed25519 or RSA training key, and its type name.</summary>
        public static byte[] Of(ITrainingKey key, out string typeName)
        {
            if (key == null) throw new ArgumentNullException("key");
            if (key.Algorithm == KeyAlgorithm.Ed25519)
            {
                typeName = Ed25519Name;
                return Ed25519(key.CopyPublic());
            }
            RsaPkcs8 parts = RsaPkcs8.Parse(key.CopyMaterial());
            typeName = RsaName;
            return Rsa(parts.N, parts.E);
        }
    }
}
