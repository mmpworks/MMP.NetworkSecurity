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

        /// <summary>Runs on both builds with the product's RSA. tests/NetSec.Host.Tests holds the outside check through the BCL import.</summary>
        [Theory]
        [InlineData(KeyIds.ServerTls11Rsa, KeyIds.SshHostRsa)]
        [InlineData(KeyIds.SshHostRsa, KeyIds.ServerTls11Rsa)]
        public void An_rsa_key_is_pkcs8_with_its_matching_spki(string id, string otherId)
        {
            ITrainingKey key = new TrainingKeySource().Find(id);
            Assert.Equal(KeyAlgorithm.Rsa2048, key.Algorithm);
            RsaFields fields = RsaFields.Parse(key.CopyMaterial(), key.CopyPublic());
            Assert.Equal(2048, fields.N.BitLength);
            Assert.Equal(fields.N.ToBigEndian(), fields.P.Multiply(fields.Q).ToBigEndian());

            byte[] message = Encoding.UTF8.GetBytes("a made-up training message");
            byte[] signature = Pkcs1.SignSha256(new RsaPrivate(fields.N, fields.D), message);
            RsaPublic publicKey = new RsaPublic(fields.N, fields.E);
            Assert.True(Pkcs1.VerifySha256(publicKey, message, signature));

            byte[] changed = (byte[])signature.Clone();
            changed[20] ^= 1;
            Assert.False(Pkcs1.VerifySha256(publicKey, message, changed));

            ITrainingKey other = new TrainingKeySource().Find(otherId);
            RsaFields otherFields = RsaFields.Parse(other.CopyMaterial(), other.CopyPublic());
            Assert.False(Pkcs1.VerifySha256(new RsaPublic(otherFields.N, otherFields.E), message, signature));
        }

        /// <summary>Reads the fields of a PKCS#8 PrivateKeyInfo and an SPKI, and fails on any other shape. N and E must match in the two documents.</summary>
        sealed class RsaFields
        {
            public BigUInt N, E, D, P, Q;

            static readonly byte[] RsaAlgorithm = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };

            public static RsaFields Parse(byte[] pkcs8, byte[] spki)
            {
                Der info = new Der(new Der(pkcs8).Take(0x30));
                Assert.Equal(new byte[] { 0 }, info.Take(0x02));
                info.Expect(RsaAlgorithm);
                Der rsa = new Der(new Der(info.Take(0x04)).Take(0x30));
                Assert.True(info.AtEnd, "PrivateKeyInfo has extra fields");
                Assert.Equal(new byte[] { 0 }, rsa.Take(0x02));

                RsaFields fields = new RsaFields();
                byte[] n = rsa.Take(0x02), e = rsa.Take(0x02);
                fields.N = BigUInt.FromBytes(n);
                fields.E = BigUInt.FromBytes(e);
                fields.D = BigUInt.FromBytes(rsa.Take(0x02));
                fields.P = BigUInt.FromBytes(rsa.Take(0x02));
                fields.Q = BigUInt.FromBytes(rsa.Take(0x02));

                Der publicInfo = new Der(new Der(spki).Take(0x30));
                publicInfo.Expect(RsaAlgorithm);
                byte[] bits = publicInfo.Take(0x03);
                Assert.True(publicInfo.AtEnd, "SubjectPublicKeyInfo has extra fields");
                Assert.Equal(0, bits[0]);
                byte[] inner = new byte[bits.Length - 1];
                Array.Copy(bits, 1, inner, 0, inner.Length);
                Der publicKey = new Der(new Der(inner).Take(0x30));
                Assert.Equal(n, publicKey.Take(0x02));
                Assert.Equal(e, publicKey.Take(0x02));
                Assert.True(publicKey.AtEnd, "RSAPublicKey has extra fields");
                return fields;
            }
        }

        /// <summary>The smallest DER reader these two documents need: one tag and one definite length at a time.</summary>
        sealed class Der
        {
            readonly byte[] _bytes;
            int _at;

            public Der(byte[] bytes) { _bytes = bytes; }

            public bool AtEnd { get { return _at == _bytes.Length; } }

            public byte[] Take(int tag)
            {
                Assert.Equal(tag, (int)_bytes[_at++]);
                int length = _bytes[_at++];
                if (length >= 0x80)
                {
                    int count = length & 0x7f;
                    length = 0;
                    for (int i = 0; i < count; i++) length = (length << 8) | _bytes[_at++];
                }
                byte[] value = new byte[length];
                Array.Copy(_bytes, _at, value, 0, length);
                _at += length;
                return value;
            }

            public void Expect(byte[] raw)
            {
                byte[] actual = new byte[raw.Length];
                Array.Copy(_bytes, _at, actual, 0, raw.Length);
                Assert.Equal(raw, actual);
                _at += raw.Length;
            }
        }
    }
}
