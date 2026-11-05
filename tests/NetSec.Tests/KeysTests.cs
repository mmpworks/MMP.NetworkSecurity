using System;
using System.Text;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;
using Xunit;

namespace NetSec.Tests
{
    public class KeysTests
    {
        static readonly string[] Ed25519Ids = { KeyIds.CaRoot, KeyIds.ServerTlsEd25519, KeyIds.SshHostEd25519, KeyIds.SshClient, KeyIds.TokenIssuer, KeyIds.AttackerEd25519 };

        [Fact]
        public void Key_ids_are_the_contract_strings()
        {
            Assert.Equal("ca-root", KeyIds.CaRoot);
            Assert.Equal("server-tls-ed25519", KeyIds.ServerTlsEd25519);
            Assert.Equal("server-tls11-rsa", KeyIds.ServerTls11Rsa);
            Assert.Equal("ssh-host-ed25519", KeyIds.SshHostEd25519);
            Assert.Equal("ssh-host-rsa", KeyIds.SshHostRsa);
            Assert.Equal("ssh-client", KeyIds.SshClient);
            Assert.Equal("dukpt-bdk-128", KeyIds.DukptBdk128);
            Assert.Equal("dukpt-bdk-256", KeyIds.DukptBdk256);
            Assert.Equal("token-issuer", KeyIds.TokenIssuer);
            Assert.Equal("attacker-ed25519", KeyIds.AttackerEd25519);
        }

        [Fact]
        public void An_ed25519_key_is_a_32_byte_seed_and_its_public_key()
        {
            TrainingKeySource keys = new TrainingKeySource();
            foreach (string id in Ed25519Ids)
            {
                ITrainingKey key = keys.Find(id);
                Assert.Equal(id, key.KeyId);
                Assert.Equal(KeyAlgorithm.Ed25519, key.Algorithm);
                Assert.Equal(32, key.CopyMaterial().Length);
                Assert.Equal(Ed25519.PublicFrom(key.CopyMaterial()), key.CopyPublic());
            }
        }

        [Fact]
        public void A_seed_is_shake256_of_the_label_and_the_id()
        {
            byte[] input = Encoding.UTF8.GetBytes("MMP.NetworkSecurity training" + KeyIds.DukptBdk128);
            Shake shake = Shake.New256();
            shake.Absorb(input, 0, input.Length);
            byte[] expected = new byte[16];
            shake.Squeeze(expected, 0, 16);
            Assert.Equal(expected, new TrainingKeySource().Find(KeyIds.DukptBdk128).CopyMaterial());
        }

        [Fact]
        public void Each_id_gives_its_own_key()
        {
            TrainingKeySource keys = new TrainingKeySource();
            Assert.NotEqual(keys.Find(KeyIds.CaRoot).CopyMaterial(), keys.Find(KeyIds.SshClient).CopyMaterial());
            Assert.NotEqual(keys.Find(KeyIds.ServerTls11Rsa).CopyMaterial(), keys.Find(KeyIds.SshHostRsa).CopyMaterial());
        }

        [Fact]
        public void A_bdk_is_raw_bytes_with_no_public_part()
        {
            TrainingKeySource keys = new TrainingKeySource();
            ITrainingKey k128 = keys.Find(KeyIds.DukptBdk128);
            ITrainingKey k256 = keys.Find(KeyIds.DukptBdk256);
            Assert.Equal(KeyAlgorithm.Aes128, k128.Algorithm);
            Assert.Equal(16, k128.CopyMaterial().Length);
            Assert.Empty(k128.CopyPublic());
            Assert.Equal(KeyAlgorithm.Aes256, k256.Algorithm);
            Assert.Equal(32, k256.CopyMaterial().Length);
            Assert.Empty(k256.CopyPublic());
        }

        [Fact]
        public void Copies_cannot_change_the_key()
        {
            ITrainingKey key = new TrainingKeySource().Find(KeyIds.SshClient);
            byte[] first = key.CopyMaterial();
            byte[] expected = (byte[])first.Clone();
            first[0] ^= 1;
            byte[] pub = key.CopyPublic();
            byte[] expectedPub = (byte[])pub.Clone();
            pub[0] ^= 1;
            Assert.Equal(expected, key.CopyMaterial());
            Assert.Equal(expectedPub, key.CopyPublic());
        }

        [Fact]
        public void An_unknown_id_gives_a_named_error()
        {
            NetSecException error = Assert.Throws<NetSecException>(() => new TrainingKeySource().Find("no-such-key"));
            Assert.Equal(ErrorCodes.TrainingKeyUnknown, error.Error.Code);
        }

#if NET
        [Theory]
        [InlineData(KeyIds.ServerTls11Rsa)]
        [InlineData(KeyIds.SshHostRsa)]
        public void An_rsa_key_is_pkcs8_with_its_matching_spki(string id)
        {
            ITrainingKey key = new TrainingKeySource().Find(id);
            Assert.Equal(KeyAlgorithm.Rsa2048, key.Algorithm);
            using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create())
            {
                int read;
                rsa.ImportPkcs8PrivateKey(key.CopyMaterial(), out read);
                Assert.Equal(key.CopyMaterial().Length, read);
                Assert.Equal(2048, rsa.KeySize);
                Assert.Equal(rsa.ExportSubjectPublicKeyInfo(), key.CopyPublic());
            }
        }
#endif
    }
}
