using System;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// Writes Ed25519 keys in the formats OpenSSH reads: the "openssh-key-v1" private key file (ssh.exe rejects PKCS#8 for Ed25519)
    /// and the one-line public key for authorized_keys. Written by hand so the suite does not depend on ssh-keygen.
    /// The self-test checks both against `ssh-keygen -y` (SELF.openssh-key-format).
    /// </summary>
    public static class OpenSshKey
    {
        static void Str(MemoryStream ms, byte[] data)
        {
            ms.WriteByte((byte)(data.Length >> 24)); ms.WriteByte((byte)(data.Length >> 16)); ms.WriteByte((byte)(data.Length >> 8)); ms.WriteByte((byte)data.Length);
            ms.Write(data, 0, data.Length);
        }

        static void U32(MemoryStream ms, uint v)
        {
            ms.WriteByte((byte)(v >> 24)); ms.WriteByte((byte)(v >> 16)); ms.WriteByte((byte)(v >> 8)); ms.WriteByte((byte)v);
        }

        static byte[] Ascii(string s) { return Encoding.ASCII.GetBytes(s); }

        public static byte[] PublicBlob(byte[] pub32)
        {
            if (pub32.Length != 32) throw new FailException("an Ed25519 public key is 32 bytes, got " + pub32.Length);
            MemoryStream ms = new MemoryStream();
            Str(ms, Ascii("ssh-ed25519"));
            Str(ms, pub32);
            return ms.ToArray();
        }

        /// <summary>The authorized_keys line: "ssh-ed25519 AAAA... comment".</summary>
        public static string AuthorizedLine(byte[] pub32, string comment)
        {
            return "ssh-ed25519 " + Convert.ToBase64String(PublicBlob(pub32)) + " " + comment + "\n";
        }

        /// <summary>An unencrypted OpenSSH private key file for an Ed25519 key.</summary>
        public static string PrivatePem(byte[] seed32, byte[] pub32, string comment)
        {
            if (seed32.Length != 32) throw new FailException("an Ed25519 seed is 32 bytes, got " + seed32.Length);
            MemoryStream priv = new MemoryStream();
            U32(priv, 0x4d4d5054); U32(priv, 0x4d4d5054);                  // two equal check words
            Str(priv, Ascii("ssh-ed25519"));
            Str(priv, pub32);
            byte[] both = new byte[64];
            Array.Copy(seed32, 0, both, 0, 32); Array.Copy(pub32, 0, both, 32, 32);
            Str(priv, both);
            Str(priv, Ascii(comment));
            int pad = 1;
            while (priv.Length % 8 != 0) priv.WriteByte((byte)pad++);

            MemoryStream all = new MemoryStream();
            byte[] magic = Ascii("openssh-key-v1");
            all.Write(magic, 0, magic.Length); all.WriteByte(0);
            Str(all, Ascii("none")); Str(all, Ascii("none")); Str(all, new byte[0]);
            U32(all, 1);
            Str(all, PublicBlob(pub32));
            Str(all, priv.ToArray());

            string b64 = Convert.ToBase64String(all.ToArray());
            StringBuilder sb = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
            for (int i = 0; i < b64.Length; i += 70) sb.Append(b64, i, Math.Min(70, b64.Length - i)).Append('\n');
            sb.Append("-----END OPENSSH PRIVATE KEY-----\n");
            return sb.ToString();
        }

        /// <summary>Limits a private key file to the current user, as OpenSSH for Windows requires.</summary>
        public static void RestrictToCurrentUser(string path)
        {
            string output;
            int code = Proc.Run("icacls", "\"" + path + "\" /inheritance:r /grant:r \"" + Environment.UserName + ":R\"", null, 30000, out output);
            if (code != 0) throw new NotRunException("ICACLS_FAILED", "icacls on " + path + " exited " + code + ": " + output);
        }
    }
}
