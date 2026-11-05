using System;
using System.IO;
using System.Text;
using NetSec.Keys;

namespace NetSec.Pki
{
    /// <summary>
    /// Writes the made-up training keys in the file forms the referees read (design section 9). This part writes the SSH files.
    /// The certificates arrive through WriteCertificates, in the part of this class that the certificate code owns.
    /// </summary>
    public static partial class TrainingPki
    {
        public const string HostKeyFile = "host.key", RsaHostKeyFile = "rsa-host.key", UserKeyFile = "user.key", UserPublicFile = "user.pub";

        public static void Export(string directory)
        {
            if (directory == null) throw new ArgumentNullException("directory");
            Directory.CreateDirectory(directory);
            WriteSshFiles(directory);
            WriteCertificates(directory);
        }

        static partial void WriteCertificates(string directory);

        static void WriteSshFiles(string directory)
        {
            TrainingKeySource keys = new TrainingKeySource();
            WriteText(directory, HostKeyFile, OpenSshKeyFile.PrivateFile(keys.Find(KeyIds.SshHostEd25519), "training host"));
            WriteText(directory, RsaHostKeyFile, OpenSshKeyFile.PrivateFile(keys.Find(KeyIds.SshHostRsa), "training host, old RSA"));
            ITrainingKey user = keys.Find(KeyIds.SshClient);
            WriteText(directory, UserKeyFile, OpenSshKeyFile.PrivateFile(user, "training user"));
            WriteText(directory, UserPublicFile, OpenSshKeyFile.AuthorizedLine(OpenSshKeyFile.Ed25519Blob(user.CopyPublic()), OpenSshKeyFile.Ed25519Name, "training user"));
        }

        /// <summary>
        /// LF endings and no byte order mark: ssh-keygen and the Go parser both refuse less. An older copy goes first, because ssh.exe needs a
        /// key file locked to one reader, and a locked file refuses a write and still allows a delete from its folder.
        /// </summary>
        static void WriteText(string directory, string name, string text)
        {
            string path = Path.Combine(directory, name);
            if (File.Exists(path)) File.Delete(path);
            using (StreamWriter writer = new StreamWriter(path, false, new UTF8Encoding(false)))
                writer.Write(text);
        }
    }
}
