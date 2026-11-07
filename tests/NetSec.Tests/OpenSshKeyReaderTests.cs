using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Pki;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// The OpenSSH key reader takes files a learner hands it, so most of these tests feed it a broken file and expect one named refusal. The files
    /// come from Raw below, a writer separate from the product's own, so a fault both share cannot hide.
    /// </summary>
    public class OpenSshKeyReaderTests
    {
        const string Ed = OpenSshKeyReader.Ed25519Type, Rsa = OpenSshKeyReader.RsaType;
        static readonly ITrainingKey TrainingUser = new TrainingKeySource().Find(KeyIds.SshClient);
        static readonly ITrainingKey TrainingRsaHost = new TrainingKeySource().Find(KeyIds.SshHostRsa);

        // ------------------------------------------------------------- a separate writer for whole and broken files

        sealed class Raw
        {
            readonly List<byte> _b = new List<byte>();
            public Raw U32(long v) { _b.Add((byte)(v >> 24)); _b.Add((byte)(v >> 16)); _b.Add((byte)(v >> 8)); _b.Add((byte)v); return this; }
            public Raw Bytes(byte[] v) { U32(v.Length); _b.AddRange(v); return this; }
            public Raw Text(string v) { return Bytes(Encoding.ASCII.GetBytes(v)); }
            public Raw Put(byte[] v) { _b.AddRange(v); return this; }
            public Raw Pad(int block) { for (int i = 1; _b.Count % block != 0; i++) _b.Add((byte)i); return this; }
            public int Count { get { return _b.Count; } }
            public byte[] ToArray() { return _b.ToArray(); }
        }

        static byte[] EdBlob(byte[] pub) { return new Raw().Text(Ed).Bytes(pub).ToArray(); }

        static byte[] EdSection(byte[] seed, byte[] pub, uint check1 = 7, uint check2 = 7, string type = Ed, byte[] privTail = null, bool pad = true)
        {
            byte[] both = new byte[64];
            Buffer.BlockCopy(seed, 0, both, 0, 32);
            Buffer.BlockCopy(privTail ?? pub, 0, both, 32, 32);
            Raw r = new Raw().U32(check1).U32(check2).Text(type).Bytes(pub).Bytes(both).Text("learner");
            return pad ? r.Pad(8).ToArray() : r.ToArray();
        }

        static byte[] File(byte[] publicBlob, byte[] section, string cipher = "none", string kdf = "none", byte[] kdfOptions = null, long keys = 1, byte[] trailing = null)
        {
            Raw r = new Raw().Put(Encoding.ASCII.GetBytes("openssh-key-v1")).Put(new byte[] { 0 }).Text(cipher).Text(kdf).Bytes(kdfOptions ?? new byte[0]).U32(keys)
                .Bytes(publicBlob).Bytes(section);
            if (trailing != null) r.Put(trailing);
            return r.ToArray();
        }

        static string Armor(byte[] file) { return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + Convert.ToBase64String(file) + "\n-----END OPENSSH PRIVATE KEY-----\n"; }

        static byte[] Seed() { byte[] s = new byte[32]; for (int i = 0; i < 32; i++) s[i] = (byte)(i * 7 + 1); return s; }

        static byte[] GoodEdFile()
        {
            byte[] seed = Seed(), pub = Ed25519.PublicFrom(seed);
            return File(EdBlob(pub), EdSection(seed, pub));
        }

        static string Refusal(string text, string type = Ed)
        {
            NetSecException e = Assert.Throws<NetSecException>(() => OpenSshKeyReader.Parse(text, KeyIds.SshClient, type));
            return e.Error.Code;
        }

        // ------------------------------------------------------------- whole files

        [Fact]
        public void An_ed25519_file_from_the_separate_writer_gives_its_seed_and_public_key()
        {
            ITrainingKey key = OpenSshKeyReader.Parse(Armor(GoodEdFile()), KeyIds.SshClient, Ed);
            Assert.Equal(Ed25519.PublicFrom(Seed()), key.CopyPublic());
            Assert.Equal(KeyAlgorithm.Ed25519, key.Algorithm);
        }

        [Fact]
        public void The_products_own_writer_round_trips_both_key_types()
        {
            ITrainingKey ed = OpenSshKeyReader.Parse(OpenSshFile.Ed25519Private(TrainingUser, "c"), KeyIds.SshClient, Ed);
            Assert.Equal(TrainingUser.CopyPublic(), ed.CopyPublic());
            ITrainingKey rsa = OpenSshKeyReader.Parse(OpenSshFile.RsaPrivate(TrainingRsaHost, "c"), KeyIds.SshHostRsa, Rsa);
            RsaPkcs8 want = RsaPkcs8.Parse(TrainingRsaHost.CopyMaterial()), got = RsaPkcs8.Parse(rsa.CopyMaterial());
            Assert.Equal(want.N, got.N);
            Assert.Equal(want.E, got.E);
            Assert.Equal(want.D, got.D);
            Assert.Equal(TrainingRsaHost.CopyPublic(), rsa.CopyPublic());
        }

        /// <summary>ssh-keygen is the outside writer. A file it makes must read, and one it encrypts must be refused by name.</summary>
        [Fact]
        public void Files_from_ssh_keygen_read_and_an_encrypted_one_is_refused_by_name()
        {
            const string Keygen = @"C:\Windows\System32\OpenSSH\ssh-keygen.exe";
            string dir = Path.Combine(Path.GetTempPath(), "netsec-keygen-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            string ed = Path.Combine(dir, "ed"), rsa = Path.Combine(dir, "rsa"), locked = Path.Combine(dir, "locked");
            Run(Keygen, "-q -t ed25519 -N \"\" -f \"" + ed + "\"");
            Run(Keygen, "-q -t rsa -b 2048 -N \"\" -f \"" + rsa + "\"");
            Run(Keygen, "-q -t ed25519 -N \"a passphrase\" -f \"" + locked + "\"");
            ITrainingKey edKey = OpenSshKeyReader.Read(ed, KeyIds.SshClient, Ed);
            Assert.Equal(OpenSshKeyReader.PublicBlobOfLine(OpenSshKeyReader.ReadText(ed + ".pub")), OpenSshKeyReader.Ed25519BlobOf(edKey.CopyPublic()));
            Assert.Equal(KeyAlgorithm.Rsa2048, OpenSshKeyReader.Read(rsa, KeyIds.SshHostRsa, Rsa).Algorithm);
            Assert.Equal(ErrorCodes.KeyFileEncrypted, Assert.Throws<NetSecException>(() => OpenSshKeyReader.Read(locked, KeyIds.SshClient, Ed)).Error.Code);
        }

        static void Run(string exe, string args)
        {
            using (Process p = Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }))
            {
                p.StandardOutput.ReadToEnd();
                Assert.True(p.WaitForExit(30000) && p.ExitCode == 0, exe + " " + args + ": " + p.StandardError.ReadToEnd());
            }
        }

        // ------------------------------------------------------------- broken files, one named refusal each

        public static IEnumerable<object[]> BrokenFiles()
        {
            byte[] seed = Seed(), pub = Ed25519.PublicFrom(seed), good = GoodEdFile();
            byte[] otherPub = Ed25519.PublicFrom(new byte[32]);
            byte[] cut = new byte[good.Length - 9];
            Buffer.BlockCopy(good, 0, cut, 0, cut.Length);
            byte[] wrongMagic = (byte[])good.Clone();
            wrongMagic[0] = (byte)'O';

            yield return new object[] { "no armor", "ssh-ed25519 AAAA", ErrorCodes.KeyFileFormat };
            yield return new object[] { "a PEM key instead", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", ErrorCodes.KeyFileFormat };
            yield return new object[] { "body not base64", "-----BEGIN OPENSSH PRIVATE KEY-----\n!!!!\n-----END OPENSSH PRIVATE KEY-----\n", ErrorCodes.KeyFileFormat };
            yield return new object[] { "the word ENCRYPTED", "-----BEGIN OPENSSH PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n-----END OPENSSH PRIVATE KEY-----\n", ErrorCodes.KeyFileEncrypted };
            yield return new object[] { "wrong magic", Armor(wrongMagic), ErrorCodes.KeyFileFormat };
            yield return new object[] { "empty body", Armor(new byte[0]), ErrorCodes.KeyFileFormat };
            yield return new object[] { "cut at the end", Armor(cut), ErrorCodes.KeyFileFormat };
            yield return new object[] { "aes256-ctr with bcrypt", Armor(File(EdBlob(pub), EdSection(seed, pub), "aes256-ctr", "bcrypt", new byte[16])), ErrorCodes.KeyFileEncrypted };
            yield return new object[] { "cipher none with bcrypt", Armor(File(EdBlob(pub), EdSection(seed, pub), "none", "bcrypt")), ErrorCodes.KeyFileEncrypted };
            yield return new object[] { "kdf options with no kdf", Armor(File(EdBlob(pub), EdSection(seed, pub), kdfOptions: new byte[4])), ErrorCodes.KeyFileEncrypted };
            yield return new object[] { "2 keys", Armor(File(EdBlob(pub), EdSection(seed, pub), keys: 2)), ErrorCodes.KeyFileFormat };
            yield return new object[] { "0 keys", Armor(File(EdBlob(pub), EdSection(seed, pub), keys: 0)), ErrorCodes.KeyFileFormat };
            yield return new object[] { "bytes after the private section", Armor(File(EdBlob(pub), EdSection(seed, pub), trailing: new byte[] { 1 })), ErrorCodes.KeyFileFormat };
            yield return new object[] { "public blob length past the end", Armor(OversizeAt(good, "openssh-key-v1".Length + 1 + 4 + 4 + 4 + 4 + 4, 0x7fffffffL)), ErrorCodes.KeyFileFormat };
            yield return new object[] { "public blob length 0xFFFFFFFF", Armor(OversizeAt(good, "openssh-key-v1".Length + 1 + 4 + 4 + 4 + 4 + 4, 0xffffffffL)), ErrorCodes.KeyFileFormat };
            yield return new object[] { "check values differ", Armor(File(EdBlob(pub), EdSection(seed, pub, 7, 8))), ErrorCodes.KeyFileFormat };
            yield return new object[] { "private type differs from public type", Armor(File(new Raw().Text(Rsa).Bytes(pub).ToArray(), EdSection(seed, pub))), ErrorCodes.KeyFileFormat };
            yield return new object[] { "public key the seed does not give", Armor(File(EdBlob(otherPub), EdSection(seed, otherPub, privTail: otherPub))), ErrorCodes.KeyFileFormat };
            yield return new object[] { "private tail differs from the public key", Armor(File(EdBlob(pub), EdSection(seed, pub, privTail: otherPub))), ErrorCodes.KeyFileFormat };
            yield return new object[] { "blob names another key", Armor(File(EdBlob(otherPub), EdSection(seed, pub))), ErrorCodes.KeyFileFormat };
            yield return new object[] { "section not whole blocks", Armor(File(EdBlob(pub), EdSection(seed, pub, pad: false).Length % 8 == 0 ? Unpadded(seed, pub, 1) : EdSection(seed, pub, pad: false))), ErrorCodes.KeyFileFormat };
            yield return new object[] { "padding out of order", Armor(File(EdBlob(pub), BadPadding(seed, pub))), ErrorCodes.KeyFileFormat };
            yield return new object[] { "a 31-byte public key", Armor(File(EdBlob(new byte[31]), new Raw().U32(7).U32(7).Text(Ed).Bytes(new byte[31]).Bytes(new byte[64]).Text("x").Pad(8).ToArray())), ErrorCodes.KeyFileFormat };
        }

        static byte[] OversizeAt(byte[] file, int at, long value)
        {
            byte[] f = (byte[])file.Clone();
            f[at] = (byte)(value >> 24); f[at + 1] = (byte)(value >> 16); f[at + 2] = (byte)(value >> 8); f[at + 3] = (byte)value;
            return f;
        }

        static byte[] Unpadded(byte[] seed, byte[] pub, int extra)
        {
            Raw r = new Raw().U32(7).U32(7).Text(Ed).Bytes(pub).Bytes(Combine(seed, pub)).Text("learner").Pad(8);
            for (int i = 0; i < extra; i++) r.Put(new byte[] { 9 });
            return r.ToArray();
        }

        static byte[] BadPadding(byte[] seed, byte[] pub)
        {
            byte[] s = EdSection(seed, pub, pad: false);
            Raw r = new Raw().Put(s);
            int need = 8 - s.Length % 8;
            if (need < 2) need += 8;
            for (int i = 0; i < need; i++) r.Put(new byte[] { (byte)(i == 0 ? 2 : i + 1) });
            return r.ToArray();
        }

        static byte[] Combine(byte[] a, byte[] b)
        {
            byte[] c = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, c, 0, a.Length);
            Buffer.BlockCopy(b, 0, c, a.Length, b.Length);
            return c;
        }

        [Theory]
        [MemberData(nameof(BrokenFiles))]
        public void A_broken_file_is_refused_with_its_named_code(string name, string text, string code)
        {
            Assert.True(code == Refusal(text), name);
        }

        [Fact]
        public void A_key_of_the_wrong_type_for_its_role_is_refused_by_name()
        {
            Assert.Equal(ErrorCodes.KeyAlgorithmNotInEngine, Refusal(Armor(GoodEdFile()), Rsa));
            Assert.Equal(ErrorCodes.KeyAlgorithmNotInEngine, Refusal(OpenSshFile.RsaPrivate(TrainingRsaHost, "c"), Ed));
        }

        // ------------------------------------------------------------- RSA numbers

        static string RsaFile(byte[] n, byte[] e, byte[] d, byte[] iqmp, byte[] p, byte[] q)
        {
            byte[] blob = new Raw().Text(Rsa).Bytes(Mp(e)).Bytes(Mp(n)).ToArray();
            byte[] section = new Raw().U32(7).U32(7).Text(Rsa).Bytes(Mp(n)).Bytes(Mp(e)).Bytes(Mp(d)).Bytes(Mp(iqmp)).Bytes(Mp(p)).Bytes(Mp(q)).Text("c").Pad(8).ToArray();
            return Armor(File(blob, section));
        }

        static byte[] Mp(byte[] unsigned) { return unsigned.Length > 0 && (unsigned[0] & 0x80) != 0 ? Combine(new byte[] { 0 }, unsigned) : unsigned; }

        [Fact]
        public void Rsa_numbers_that_do_not_form_one_2048_bit_key_are_refused()
        {
            RsaPkcs8 k = RsaPkcs8.Parse(TrainingRsaHost.CopyMaterial());
            byte[] n = Trim(k.N), e = Trim(k.E), d = Trim(k.D), one = new byte[] { 1 };
            Assert.Equal(ErrorCodes.KeyFileFormat, Refusal(RsaFile(n, e, d, one, one, n), Rsa));                    // p = 1, q = n
            Assert.Equal(ErrorCodes.KeyFileFormat, Refusal(RsaFile(n, e, d, one, new byte[] { 3 }, new byte[] { 5 }), Rsa)); // p * q is not n
            byte[] small = new byte[128];
            small[0] = 0xC1;
            small[127] = 1;
            Assert.Equal(ErrorCodes.KeySizeNot2048, Refusal(RsaFile(small, e, one, one, one, one), Rsa));
            byte[] negativeBlob = new Raw().Text(Rsa).Bytes(e).Bytes(n).ToArray();
            byte[] negative = new Raw().U32(7).U32(7).Text(Rsa).Bytes(n).Bytes(e).Bytes(d).Bytes(one).Bytes(one).Bytes(one).Text("c").Pad(8).ToArray();
            Assert.Equal(ErrorCodes.KeyFileFormat, Refusal(Armor(File(negativeBlob, negative)), Rsa));             // n with its top bit set and no leading zero
        }

        /// <summary>Only the sign check refuses this file: every other number is the training key's, and e is 0x80 written with no leading zero.</summary>
        [Fact]
        public void A_negative_rsa_number_is_refused_even_when_the_rest_forms_a_key()
        {
            byte[][] all = RsaNumbers(TrainingRsaHost.CopyMaterial());
            byte[] n = all[0], d = all[2], p = all[3], q = all[4], iqmp = all[7], e = new byte[] { 0x80 };
            byte[] blob = new Raw().Text(Rsa).Bytes(e).Bytes(Mp(n)).ToArray();
            byte[] section = new Raw().U32(7).U32(7).Text(Rsa).Bytes(Mp(n)).Bytes(e).Bytes(Mp(d)).Bytes(Mp(iqmp)).Bytes(Mp(p)).Bytes(Mp(q)).Text("c").Pad(8).ToArray();
            Assert.Equal(ErrorCodes.KeyFileFormat, Refusal(Armor(File(blob, section)), Rsa));
        }

        /// <summary>Only the type check refuses this file: the public half names ssh-ed25519 and the private half ssh-rsa, and the role takes ssh-ed25519.</summary>
        [Fact]
        public void A_private_type_unlike_the_public_type_is_a_format_fault_not_a_wrong_role()
        {
            byte[] pub = Ed25519.PublicFrom(Seed());
            byte[] section = new Raw().U32(7).U32(7).Text(Rsa).Bytes(new byte[] { 1 }).Text("c").Pad(8).ToArray();
            Assert.Equal(ErrorCodes.KeyFileFormat, Refusal(Armor(File(EdBlob(pub), section)), Ed));
        }

        /// <summary>n, e, d, p, q, dp, dq, iqmp from a PKCS#8 RSA key, without leading zero bytes.</summary>
        static byte[][] RsaNumbers(byte[] pkcs8)
        {
            DerReader info = new DerReader(pkcs8, 0, pkcs8.Length).Read(Der.TagSequence).Inner;
            info.Read(Der.TagInteger);
            info.Read(Der.TagSequence);
            byte[] inner = info.Read(Der.TagOctetString).Value;
            DerReader rsa = new DerReader(inner, 0, inner.Length).Read(Der.TagSequence).Inner;
            rsa.Read(Der.TagInteger);
            byte[][] all = new byte[8][];
            for (int i = 0; i < 8; i++) all[i] = Trim(rsa.Read(Der.TagInteger).Value);
            return all;
        }

        static byte[] Trim(byte[] v)
        {
            int at = 0;
            while (at < v.Length - 1 && v[at] == 0) at++;
            byte[] t = new byte[v.Length - at];
            Buffer.BlockCopy(v, at, t, 0, t.Length);
            return t;
        }

        // ------------------------------------------------------------- CredentialSet.FromFiles

        static string Folder()
        {
            string dir = Path.Combine(Path.GetTempPath(), "netsec-fromfiles-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        [Fact]
        public void FromFiles_reads_the_ssh_rows_and_leaves_a_missing_one_built_in()
        {
            string dir = Folder();
            System.IO.File.WriteAllText(Path.Combine(dir, "host.key"), Armor(GoodEdFile()));
            System.IO.File.WriteAllText(Path.Combine(dir, "user.key"), OpenSshFile.Ed25519Private(TrainingUser, "c"));
            System.IO.File.WriteAllText(Path.Combine(dir, "user.pub"), OpenSshFile.Ed25519PublicLine(TrainingUser, "c"));
            CredentialSet set = CredentialSet.FromFiles(dir);
            Assert.Equal(Ed25519.PublicFrom(Seed()), set.Find(KeyIds.SshHostEd25519).CopyPublic());
            Assert.Equal(TrainingUser.CopyPublic(), set.Find(KeyIds.SshClient).CopyPublic());
            Assert.Equal(new TrainingKeySource().Find(KeyIds.SshHostRsa).CopyPublic(), set.Find(KeyIds.SshHostRsa).CopyPublic());
            Assert.Equal(2, set.Mine().Length);
            Assert.Empty(CredentialSet.FromFiles(Folder()).Mine());
        }

        [Fact]
        public void FromFiles_refuses_a_mismatched_user_pub_an_unbuilt_row_a_missing_folder_and_a_large_file()
        {
            string dir = Folder();
            System.IO.File.WriteAllText(Path.Combine(dir, "user.key"), OpenSshFile.Ed25519Private(TrainingUser, "c"));
            System.IO.File.WriteAllText(Path.Combine(dir, "user.pub"), OpenSshFile.Ed25519PublicLine(OpenSshKeyReader.Parse(Armor(GoodEdFile()), KeyIds.SshClient, Ed), "c"));
            Assert.Equal(ErrorCodes.KeyFileFormat, Assert.Throws<NetSecException>(() => CredentialSet.FromFiles(dir)).Error.Code);

            string tls = Folder();
            System.IO.File.WriteAllText(Path.Combine(tls, "root.pem"), "x");
            Assert.Equal(ErrorCodes.FileRowNotBuilt, Assert.Throws<NetSecException>(() => CredentialSet.FromFiles(tls)).Error.Code);

            Assert.Equal(ErrorCodes.KeyFileUnreadable, Assert.Throws<NetSecException>(() => CredentialSet.FromFiles(Path.Combine(Folder(), "none"))).Error.Code);

            string big = Folder();
            System.IO.File.WriteAllBytes(Path.Combine(big, "host.key"), new byte[65 * 1024]);
            Assert.Equal(ErrorCodes.KeyFileFormat, Assert.Throws<NetSecException>(() => CredentialSet.FromFiles(big)).Error.Code);
        }

        /// <summary>The key type comes from the file. A long or unprintable one must not reach the message, so the message says an unknown type.</summary>
        [Fact]
        public void A_long_or_unprintable_key_type_is_not_printed()
        {
            string bad = "ssh-x" + new string('A', 200) + "\u001b[2J";
            byte[] pub = Ed25519.PublicFrom(Seed());
            byte[] blob = new Raw().Text(bad).Bytes(pub).ToArray();
            byte[] section = new Raw().U32(7).U32(7).Text(bad).Bytes(pub).Text("c").Pad(8).ToArray();
            NetSecException e = Assert.Throws<NetSecException>(() => OpenSshKeyReader.Parse(Armor(File(blob, section)), KeyIds.SshClient, Ed));
            Assert.DoesNotContain("\u001b", e.Error.Message);
            Assert.DoesNotContain(new string('A', 40), e.Error.Message);
            Assert.Contains("an unknown type", e.Error.Message);
            byte[] otherBlob = new Raw().Text(Ed).Bytes(pub).ToArray();
            NetSecException mismatch = Assert.Throws<NetSecException>(() => OpenSshKeyReader.Parse(Armor(File(otherBlob, section)), KeyIds.SshClient, Ed));
            Assert.DoesNotContain("\u001b", mismatch.Error.Message);
            Assert.Contains("an unknown type", mismatch.Error.Message);
        }
    }
}
