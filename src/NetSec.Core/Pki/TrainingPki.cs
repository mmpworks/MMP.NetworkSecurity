using System;
using System.IO;
using System.Text;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Keys;

namespace NetSec.Pki
{
    /// <summary>Writes the training keys and certificates as the files OpenSSL, Go, and ssh.exe read. Every key is made up and public in this source.</summary>
    public static class TrainingPki
    {
        public const string ServerName = "localhost";
        const string UserComment = "training";

        public static void Export(string directory)
        {
            if (directory == null) throw new ArgumentNullException("directory");
            Directory.CreateDirectory(directory);
            ITrainingKeySource keys = new TrainingKeySource();
            TrainingCa ca = new TrainingCa(keys);

            ITrainingKey tls = keys.Find(KeyIds.ServerTlsEd25519);
            Write(directory, "root.pem", Pem("CERTIFICATE", ca.RootCertificateDer));
            Write(directory, "srv.pem", Pem("CERTIFICATE", ServerCertificate(ca, tls)));
            Write(directory, "srv.key", Pem("PRIVATE KEY", TrainingCa.Ed25519Pkcs8(tls.CopyMaterial())));

            ITrainingKey rsa = keys.Find(KeyIds.ServerTls11Rsa);
            byte[] rsaCert = ca.IssueServerCertificate(ServerName, rsa.CopyPublic(), TrainingCa.DefaultNotBefore, TrainingCa.DefaultNotAfter);
            Write(directory, "rsa.pem", Pem("CERTIFICATE", rsaCert));
            Write(directory, "rsa.key", Pem("PRIVATE KEY", rsa.CopyMaterial()));

            ITrainingKey user = keys.Find(KeyIds.SshClient);
            Write(directory, "host.key", OpenSshFile.Ed25519Private(keys.Find(KeyIds.SshHostEd25519), "host"));
            Write(directory, "rsa-host.key", OpenSshFile.RsaPrivate(keys.Find(KeyIds.SshHostRsa), "rsa-host"));
            Write(directory, "user.key", OpenSshFile.Ed25519Private(user, UserComment));
            Write(directory, "user.pub", OpenSshFile.Ed25519PublicLine(user, UserComment));
            Write(directory, "issuer.pub", Pem("PUBLIC KEY", TrainingCa.Ed25519Spki(keys.Find(KeyIds.TokenIssuer).CopyPublic())));
        }

        /// <summary>The leaf the glass server and the referees present.</summary>
        public static byte[] ServerCertificate(TrainingCa ca, ITrainingKey key)
        {
            return ca.IssueServerCertificate(ServerName, TrainingCa.Ed25519Spki(key.CopyPublic()), TrainingCa.DefaultNotBefore, TrainingCa.DefaultNotAfter);
        }

        public static string Pem(string label, byte[] der)
        {
            StringBuilder text = new StringBuilder();
            text.Append("-----BEGIN ").Append(label).Append("-----\n");
            AppendWrapped(text, Convert.ToBase64String(der), 64);
            text.Append("-----END ").Append(label).Append("-----\n");
            return text.ToString();
        }

        internal static void AppendWrapped(StringBuilder text, string base64, int width)
        {
            for (int i = 0; i < base64.Length; i += width)
                text.Append(base64.Substring(i, Math.Min(width, base64.Length - i))).Append('\n');
        }

        static void Write(string directory, string name, string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            using (FileStream file = File.Create(Path.Combine(directory, name)))
                file.Write(bytes, 0, bytes.Length);
        }
    }

    /// <summary>The OpenSSH private key file (PROTOCOL.key in the OpenSSH source) with no cipher, and the one-line public key form.</summary>
    public static class OpenSshFile
    {
        const string Ed25519Type = "ssh-ed25519";
        const string RsaType = "ssh-rsa";
        const int BlockSize = 8;

        public static string Ed25519PublicLine(ITrainingKey key, string comment)
        {
            return Ed25519Type + " " + Convert.ToBase64String(Ed25519Blob(key.CopyPublic())) + " " + comment + "\n";
        }

        public static string Ed25519Private(ITrainingKey key, string comment)
        {
            byte[] pub = key.CopyPublic();
            byte[] seedAndPublic = new ByteWriter().Put(key.CopyMaterial()).Put(pub).ToArray();
            ByteWriter body = new ByteWriter();
            PutText(body, Ed25519Type);
            PutBytes(body, pub);
            PutBytes(body, seedAndPublic);
            return Armor(Ed25519Blob(pub), body, key.KeyId, comment);
        }

        /// <summary>PKCS#8 holds n, e, d, p, q, dp, dq, iqmp. A DER integer and an SSH mpint have the same bytes, because both carry a sign.</summary>
        public static string RsaPrivate(ITrainingKey key, string comment)
        {
            byte[] material = key.CopyMaterial();
            DerReader outer = new DerReader(material, 0, material.Length).Read(Der.TagSequence).Inner;
            outer.Read(Der.TagInteger);
            outer.Read(Der.TagSequence);
            byte[] inner = outer.Read(Der.TagOctetString).Value;
            DerReader rsa = new DerReader(inner, 0, inner.Length).Read(Der.TagSequence).Inner;
            rsa.Read(Der.TagInteger);
            byte[] n = rsa.Read(Der.TagInteger).Value, e = rsa.Read(Der.TagInteger).Value, d = rsa.Read(Der.TagInteger).Value;
            byte[] p = rsa.Read(Der.TagInteger).Value, q = rsa.Read(Der.TagInteger).Value;
            rsa.Read(Der.TagInteger);
            rsa.Read(Der.TagInteger);
            byte[] iqmp = rsa.Read(Der.TagInteger).Value;

            ByteWriter blob = new ByteWriter();
            PutText(blob, RsaType);
            PutBytes(blob, e);
            PutBytes(blob, n);

            ByteWriter body = new ByteWriter();
            PutText(body, RsaType);
            PutBytes(body, n);
            PutBytes(body, e);
            PutBytes(body, d);
            PutBytes(body, iqmp);
            PutBytes(body, p);
            PutBytes(body, q);
            return Armor(blob.ToArray(), body, key.KeyId, comment);
        }

        static byte[] Ed25519Blob(byte[] publicKey)
        {
            ByteWriter blob = new ByteWriter();
            PutText(blob, Ed25519Type);
            PutBytes(blob, publicKey);
            return blob.ToArray();
        }

        static string Armor(byte[] publicBlob, ByteWriter keyFields, string keyId, string comment)
        {
            long check = CheckValue(keyId);
            ByteWriter inner = new ByteWriter().U32(check).U32(check).Put(keyFields.ToArray());
            PutText(inner, comment);
            for (int pad = 1; inner.Count % BlockSize != 0; pad++) inner.U8(pad);

            ByteWriter file = new ByteWriter().Put(Encoding.UTF8.GetBytes("openssh-key-v1")).U8(0);
            PutText(file, "none");
            PutText(file, "none");
            PutBytes(file, new byte[0]);
            file.U32(1);
            PutBytes(file, publicBlob);
            PutBytes(file, inner.ToArray());

            StringBuilder text = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
            TrainingPki.AppendWrapped(text, Convert.ToBase64String(file.ToArray()), 70);
            return text.Append("-----END OPENSSH PRIVATE KEY-----\n").ToString();
        }

        /// <summary>OpenSSH writes one random value twice, to spot a wrong passphrase. Here it comes from the key id, so a rerun writes the same file.</summary>
        static long CheckValue(string keyId)
        {
            byte[] text = Encoding.UTF8.GetBytes(keyId);
            IHash sha256 = Hashes.Sha256();
            sha256.Update(text, 0, text.Length);
            byte[] digest = sha256.Finish();
            return ((long)digest[0] << 24) | ((long)digest[1] << 16) | ((long)digest[2] << 8) | digest[3];
        }

        static void PutText(ByteWriter w, string text) { PutBytes(w, Encoding.UTF8.GetBytes(text)); }
        static void PutBytes(ByteWriter w, byte[] bytes) { w.U32(bytes.Length).Put(bytes); }
    }
}
