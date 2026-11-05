using System;
using System.Text;
using NetSec.Bytes;
using NetSec.Keys;

namespace NetSec.Pki
{
    /// <summary>
    /// The SSH public key blob (RFC 4253 section 6.6, RFC 8709) and the OpenSSH key file forms. The private file has no passphrase on
    /// purpose: these are made-up training keys that anyone can read in this source.
    /// </summary>
    public static class OpenSshKeyFile
    {
        public const string Ed25519Name = "ssh-ed25519";
        public const string RsaName = "ssh-rsa";

        const int LineWidth = 70;
        const int PaddingBlock = 8;
        const uint CheckValue = 0x4e657453;   // A private section repeats one number twice. A reader compares them to detect a wrong passphrase.

        public static byte[] Ed25519Blob(byte[] publicKey)
        {
            return new ByteWriter().Prefixed(Ed25519Name).Prefixed(publicKey).ToArray();
        }

        public static byte[] RsaBlob(byte[] n, byte[] e)
        {
            return new ByteWriter().Prefixed(RsaName).Mpint(e).Mpint(n).ToArray();
        }

        /// <summary>One authorized_keys line: type, base64 blob, comment.</summary>
        public static string AuthorizedLine(byte[] blob, string typeName, string comment)
        {
            return typeName + " " + Convert.ToBase64String(blob) + " " + comment + "\n";
        }

        public static string PublicBlobOf(ITrainingKey key, out string typeName, out byte[] blob)
        {
            if (key == null) throw new ArgumentNullException("key");
            if (key.Algorithm == KeyAlgorithm.Ed25519)
            {
                typeName = Ed25519Name;
                blob = Ed25519Blob(key.CopyPublic());
                return typeName;
            }
            RsaPkcs8 parts = RsaPkcs8.Parse(key.CopyMaterial());
            typeName = RsaName;
            blob = RsaBlob(parts.N, parts.E);
            return typeName;
        }

        /// <summary>The whole text of an unencrypted OpenSSH private key file for an Ed25519 or RSA training key.</summary>
        public static string PrivateFile(ITrainingKey key, string comment)
        {
            string typeName;
            byte[] blob;
            PublicBlobOf(key, out typeName, out blob);
            ByteWriter section = new ByteWriter().U32(CheckValue).U32(CheckValue).Prefixed(typeName);
            if (key.Algorithm == KeyAlgorithm.Ed25519) AddEd25519(section, key);
            else AddRsa(section, key);
            section.Prefixed(comment);
            for (int pad = 1; section.Count % PaddingBlock != 0; pad++) section.U8(pad);

            ByteWriter file = new ByteWriter();
            file.Put(Encoding.UTF8.GetBytes("openssh-key-v1")).U8(0);
            file.Prefixed("none").Prefixed("none").Prefixed(new byte[0]).U32(1).Prefixed(blob).Prefixed(section.ToArray());
            return Armor(file.ToArray());
        }

        static void AddEd25519(ByteWriter section, ITrainingKey key)
        {
            byte[] publicKey = key.CopyPublic();
            section.Prefixed(publicKey).Prefixed(new ByteWriter().Put(key.CopyMaterial()).Put(publicKey).ToArray());
        }

        static void AddRsa(ByteWriter section, ITrainingKey key)
        {
            RsaPkcs8 parts = RsaPkcs8.Parse(key.CopyMaterial());
            section.Mpint(parts.N).Mpint(parts.E).Mpint(parts.D).Mpint(parts.Iqmp).Mpint(parts.P).Mpint(parts.Q);
        }

        static string Armor(byte[] bytes)
        {
            string base64 = Convert.ToBase64String(bytes);
            StringBuilder text = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
            for (int at = 0; at < base64.Length; at += LineWidth)
                text.Append(base64.Substring(at, Math.Min(LineWidth, base64.Length - at))).Append('\n');
            return text.Append("-----END OPENSSH PRIVATE KEY-----\n").ToString();
        }
    }
}
