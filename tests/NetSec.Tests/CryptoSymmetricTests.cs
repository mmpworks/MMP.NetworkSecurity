using System;
using System.Security.Cryptography;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using Xunit;

namespace NetSec.Tests
{
    public class CryptoSymmetricTests
    {
        static Func<IHash> Factory(string alg)
        {
            switch (alg)
            {
                case "md5": return Hashes.Md5;
                case "sha1": return Hashes.Sha1;
                case "sha256": return Hashes.Sha256;
                case "sha384": return Hashes.Sha384;
                case "sha512": return Hashes.Sha512;
                default: throw new ArgumentException(alg);
            }
        }

        static byte[] Fill(int n, int seed = 7)
        {
            byte[] b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = (byte)(i * 31 + seed);
            return b;
        }

        static void Same(byte[] expected, byte[] actual) { Assert.Equal(Hex.Encode(expected), Hex.Encode(actual)); }

        static byte[] Blocks(AesKey k, byte[] data, bool encrypt)
        {
            byte[] o = new byte[data.Length];
            for (int i = 0; i < data.Length; i += 16)
            {
                if (encrypt) k.EncryptBlock(data, i, o, i); else k.DecryptBlock(data, i, o, i);
            }
            return o;
        }

        // ---------------------------------------------------------------- AES

        [Theory]
        [InlineData("aes-fips197.nsv", "aes-block")]
        [InlineData("aes-modes-sp800-38a.nsv", "aes-ecb")]
        public void Published_aes_block_vectors_pass(string file, string group)
        {
            foreach (var r in VectorFile.Read(file, group))
            {
                AesKey k = new AesKey(r.Bytes("key"));
                Same(r.Bytes("ciphertext"), Modes.EcbEncrypt(k, r.Bytes("plaintext")));
                Same(r.Bytes("plaintext"), Blocks(k, r.Bytes("ciphertext"), false));
            }
        }

        [Fact]
        public void Published_cbc_and_ctr_vectors_pass()
        {
            foreach (var r in VectorFile.Read("aes-modes-sp800-38a.nsv", "aes-cbc"))
            {
                AesKey k = new AesKey(r.Bytes("key"));
                Same(r.Bytes("ciphertext"), Modes.CbcEncrypt(k, r.Bytes("iv"), r.Bytes("plaintext")));
                Same(r.Bytes("plaintext"), Modes.CbcDecrypt(k, r.Bytes("iv"), r.Bytes("ciphertext")));
            }
            foreach (var r in VectorFile.Read("aes-modes-sp800-38a.nsv", "aes-ctr"))
            {
                AesKey k = new AesKey(r.Bytes("key"));
                Same(r.Bytes("ciphertext"), Modes.Ctr(k, r.Bytes("iv"), r.Bytes("plaintext")));
                Same(r.Bytes("plaintext"), Modes.Ctr(k, r.Bytes("iv"), r.Bytes("ciphertext")));
            }
        }

        [Theory]
        [InlineData(16)]
        [InlineData(24)]
        [InlineData(32)]
        public void Aes_matches_the_bcl(int keySize)
        {
            byte[] key = Fill(keySize), iv = Fill(16, 99), data = Fill(160, 3);
            using (Aes bcl = Aes.Create())
            {
                bcl.Key = key;
                bcl.Padding = PaddingMode.None;
                bcl.Mode = CipherMode.ECB;
                using (ICryptoTransform t = bcl.CreateEncryptor()) Same(t.TransformFinalBlock(data, 0, data.Length), Modes.EcbEncrypt(new AesKey(key), data));
                using (ICryptoTransform t = bcl.CreateDecryptor()) Same(t.TransformFinalBlock(data, 0, data.Length), Blocks(new AesKey(key), data, false));
                bcl.Mode = CipherMode.CBC;
                bcl.IV = iv;
                using (ICryptoTransform t = bcl.CreateEncryptor()) Same(t.TransformFinalBlock(data, 0, data.Length), Modes.CbcEncrypt(new AesKey(key), iv, data));
                using (ICryptoTransform t = bcl.CreateDecryptor()) Same(t.TransformFinalBlock(data, 0, data.Length), Modes.CbcDecrypt(new AesKey(key), iv, data));
            }
        }

        [Fact]
        public void A_block_can_encrypt_over_itself()
        {
            AesKey k = new AesKey(Fill(16));
            byte[] block = Fill(16, 40);
            byte[] plain = (byte[])block.Clone();
            byte[] expected = new byte[16];
            k.EncryptBlock(block, 0, expected, 0);
            k.EncryptBlock(block, 0, block, 0);
            Same(expected, block);
            k.DecryptBlock(block, 0, block, 0);
            Same(plain, block);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(15)]
        [InlineData(17)]
        [InlineData(33)]
        public void Aes_refuses_other_key_sizes(int size)
        {
            Assert.Throws<ArgumentException>(() => new AesKey(new byte[size]));
        }

        [Fact]
        public void Ecb_and_cbc_refuse_a_partial_block()
        {
            AesKey k = new AesKey(new byte[16]);
            Assert.Throws<ArgumentException>(() => Modes.EcbEncrypt(k, new byte[17]));
            Assert.Throws<ArgumentException>(() => Modes.CbcEncrypt(k, new byte[16], new byte[15]));
            Assert.Throws<ArgumentException>(() => Modes.CbcDecrypt(k, new byte[16], new byte[1]));
            Assert.Throws<ArgumentException>(() => Modes.CbcEncrypt(k, new byte[8], new byte[16]));
        }

        [Fact]
        public void Ctr_carries_across_all_128_bits()
        {
            AesKey k = new AesKey(Fill(16));
            byte[] allOnes = new byte[16];
            for (int i = 0; i < 16; i++) allOnes[i] = 0xff;
            byte[] output = Modes.Ctr(k, allOnes, new byte[32]);

            byte[] secondBlock = new byte[16];
            k.EncryptBlock(new byte[16], 0, secondBlock, 0);
            Assert.Equal(Hex.Encode(secondBlock), Hex.Encode(output).Substring(32));
        }

        [Fact]
        public void Ctr_leaves_its_counter_unchanged_and_handles_a_short_tail()
        {
            byte[] counter = Fill(16);
            byte[] copy = (byte[])counter.Clone();
            byte[] data = Fill(21);
            AesKey k = new AesKey(Fill(16, 1));
            Same(data, Modes.Ctr(k, counter, Modes.Ctr(k, counter, data)));
            Same(copy, counter);
        }

        // ---------------------------------------------------------------- TDES

        [Theory]
        [InlineData("tdes-ecb-encrypt-kat", true)]
        [InlineData("tdes-ecb-encrypt-mmt", true)]
        [InlineData("tdes-ecb-decrypt-kat", false)]
        [InlineData("tdes-ecb-decrypt-mmt", false)]
        public void Published_tdes_vectors_pass(string group, bool encrypt)
        {
            foreach (var r in VectorFile.Read("tdes-cavp.nsv", group))
            {
                TdesKey k = new TdesKey(r.Bytes("key"));
                byte[] input = r.Bytes(encrypt ? "plaintext" : "ciphertext");
                byte[] output = new byte[input.Length];
                for (int i = 0; i < input.Length; i += 8)
                {
                    if (encrypt) k.EncryptBlock(input, i, output, i); else k.DecryptBlock(input, i, output, i);
                }
                Same(r.Bytes(encrypt ? "ciphertext" : "plaintext"), output);
            }
        }

        [Theory]
        [InlineData(16)]
        [InlineData(24)]
        public void Tdes_matches_the_bcl(int keySize)
        {
            byte[] key = Fill(keySize, 17);
            byte[] block = Fill(8, 5);
            using (TripleDES bcl = TripleDES.Create())
            {
                bcl.Key = key;
                bcl.Mode = CipherMode.ECB;
                bcl.Padding = PaddingMode.None;
                byte[] ours = new byte[8];
                new TdesKey(key).EncryptBlock(block, 0, ours, 0);
                using (ICryptoTransform t = bcl.CreateEncryptor()) Same(t.TransformFinalBlock(block, 0, 8), ours);
                new TdesKey(key).DecryptBlock(block, 0, ours, 0);
                using (ICryptoTransform t = bcl.CreateDecryptor()) Same(t.TransformFinalBlock(block, 0, 8), ours);
            }
        }

        [Theory]
        [InlineData(8)]
        [InlineData(15)]
        [InlineData(32)]
        public void Tdes_refuses_other_key_sizes(int size)
        {
            Assert.Throws<ArgumentException>(() => new TdesKey(new byte[size]));
        }

        // ---------------------------------------------------------------- GCM

        [Fact]
        public void Published_gcm_vectors_pass()
        {
            foreach (var r in VectorFile.Read("gcm-cavp.nsv", "gcm-seal"))
            {
                AesKey k = new AesKey(r.Bytes("key"));
                byte[] sealedBytes = Join(r.Bytes("ciphertext"), r.Bytes("tag"));
                Same(sealedBytes, Gcm.Seal(k, r.Bytes("iv"), r.Bytes("aad"), r.Bytes("plaintext")));
                Assert.True(Gcm.TryOpen(k, r.Bytes("iv"), r.Bytes("aad"), sealedBytes, out byte[] plain));
                Same(r.Bytes("plaintext"), plain);
            }
            foreach (var r in VectorFile.Read("gcm-cavp.nsv", "gcm-open-fail"))
            {
                bool opened = Gcm.TryOpen(new AesKey(r.Bytes("key")), r.Bytes("iv"), r.Bytes("aad"), Join(r.Bytes("ciphertext"), r.Bytes("tag")), out byte[] plain);
                Assert.False(opened);
                Assert.Null(plain);
            }
        }

        [Fact]
        public void A_change_to_any_byte_or_the_aad_or_the_nonce_is_refused()
        {
            AesKey k = new AesKey(Fill(16));
            byte[] nonce = Fill(12, 2), aad = Fill(5, 3), plain = Fill(20, 4);
            byte[] good = Gcm.Seal(k, nonce, aad, plain);
            Assert.True(Gcm.TryOpen(k, nonce, aad, good, out byte[] opened));
            Same(plain, opened);

            for (int i = 0; i < good.Length; i++)
            {
                byte[] bad = (byte[])good.Clone();
                bad[i] ^= 0x01;
                Assert.False(Gcm.TryOpen(k, nonce, aad, bad, out byte[] none));
                Assert.Null(none);
            }
            Assert.False(Gcm.TryOpen(k, nonce, Fill(5, 30), good, out _));
            Assert.False(Gcm.TryOpen(k, Fill(12, 20), aad, good, out _));
            Assert.False(Gcm.TryOpen(new AesKey(Fill(16, 8)), nonce, aad, good, out _));
        }

        [Fact]
        public void Bytes_too_short_to_hold_a_tag_are_refused_without_a_throw()
        {
            AesKey k = new AesKey(new byte[16]);
            Assert.False(Gcm.TryOpen(k, new byte[12], new byte[0], new byte[15], out byte[] plain));
            Assert.Null(plain);
        }

        [Fact]
        public void Gcm_takes_only_a_12_byte_nonce()
        {
            AesKey k = new AesKey(new byte[16]);
            Assert.Throws<ArgumentException>(() => Gcm.Seal(k, new byte[16], new byte[0], new byte[0]));
            Assert.Throws<ArgumentException>(() => Gcm.TryOpen(k, new byte[8], new byte[0], new byte[16], out _));
        }

        // ---------------------------------------------------------------- HMAC, CMAC, HKDF

        [Theory]
        [InlineData("md5", "hmac-rfc2202.nsv", "hmac-md5")]
        [InlineData("sha1", "hmac-rfc2202.nsv", "hmac-sha1")]
        [InlineData("sha256", "hmac-rfc4231.nsv", "hmac-sha256")]
        [InlineData("sha384", "hmac-rfc4231.nsv", "hmac-sha384")]
        [InlineData("sha512", "hmac-rfc4231.nsv", "hmac-sha512")]
        public void Published_hmac_vectors_pass(string alg, string file, string group)
        {
            foreach (var r in VectorFile.Read(file, group))
            {
                byte[] expected = r.Bytes("mac");
                byte[] actual = Hmac.Compute(Factory(alg), r.Bytes("key"), r.Bytes("data"));
                Assert.Equal(Hex.Encode(expected), Hex.Encode(actual).Substring(0, expected.Length * 2));
            }
        }

        [Fact]
        public void Hmac_matches_the_bcl_below_at_and_above_the_block_size()
        {
            foreach (int keySize in new[] { 0, 1, 63, 64, 65, 127, 128, 129, 300 })
            {
                byte[] key = Fill(keySize), data = Fill(77, 2);
                using (HMACSHA1 h = new HMACSHA1(key)) Same(h.ComputeHash(data), Hmac.Compute(Hashes.Sha1, key, data));
                using (HMACSHA256 h = new HMACSHA256(key)) Same(h.ComputeHash(data), Hmac.Compute(Hashes.Sha256, key, data));
                using (HMACSHA384 h = new HMACSHA384(key)) Same(h.ComputeHash(data), Hmac.Compute(Hashes.Sha384, key, data));
                using (HMACSHA512 h = new HMACSHA512(key)) Same(h.ComputeHash(data), Hmac.Compute(Hashes.Sha512, key, data));
                using (HMACMD5 h = new HMACMD5(key)) Same(h.ComputeHash(data), Hmac.Compute(Hashes.Md5, key, data));
            }
        }

        [Fact]
        public void Published_cmac_vectors_pass()
        {
            foreach (var r in VectorFile.Read("cmac-rfc4493.nsv", "cmac-aes128"))
                Same(r.Bytes("mac"), Cmac.Compute(new AesKey(r.Bytes("key")), r.Bytes("msg")));
        }

        [Theory]
        [InlineData("sha256", "hkdf-sha256")]
        [InlineData("sha1", "hkdf-sha1")]
        public void Published_hkdf_vectors_pass(string alg, string group)
        {
            foreach (var r in VectorFile.Read("hkdf-rfc5869.nsv", group))
            {
                Same(r.Bytes("prk"), Hkdf.Extract(Factory(alg), r.Bytes("salt"), r.Bytes("ikm")));
                Same(r.Bytes("okm"), Hkdf.Expand(Factory(alg), r.Bytes("prk"), r.Bytes("info"), int.Parse(r["length"])));
            }
        }

        [Fact]
        public void Hkdf_null_salt_equals_a_salt_of_zeros()
        {
            Same(Hkdf.Extract(Hashes.Sha256, new byte[32], Fill(22)), Hkdf.Extract(Hashes.Sha256, null, Fill(22)));
        }

        [Fact]
        public void Hkdf_expand_stops_at_255_hash_lengths()
        {
            byte[] prk = Fill(32);
            Assert.Equal(255 * 32, Hkdf.Expand(Hashes.Sha256, prk, new byte[0], 255 * 32).Length);
            Assert.Empty(Hkdf.Expand(Hashes.Sha256, prk, new byte[0], 0));
            Assert.Throws<ArgumentOutOfRangeException>(() => Hkdf.Expand(Hashes.Sha256, prk, new byte[0], 255 * 32 + 1));
            Assert.Throws<ArgumentOutOfRangeException>(() => Hkdf.Expand(Hashes.Sha256, prk, new byte[0], -1));
        }

        [Theory]
        [InlineData("sha1", 20)]
        [InlineData("sha256", 32)]
        [InlineData("sha512", 64)]
        public void Hkdf_expand_refuses_a_prk_shorter_than_the_hash(string alg, int hashLength)
        {
            Assert.Equal(10, Hkdf.Expand(Factory(alg), Fill(hashLength), new byte[0], 10).Length);
            NetSecException refused = Assert.Throws<NetSecException>(() => Hkdf.Expand(Factory(alg), Fill(hashLength - 1), new byte[0], 10));
            Assert.Equal(ErrorCodes.HkdfPrkTooShort, refused.Error.Code);
        }

        [Fact]
        public void Hmac_verify_takes_the_right_tag_and_refuses_the_rest()
        {
            byte[] key = Fill(32), data = Fill(40, 2);
            byte[] tag = Hmac.Compute(Hashes.Sha256, key, data);
            Assert.True(Hmac.Verify(Hashes.Sha256, key, data, tag));

            for (int i = 0; i < tag.Length; i++)
            {
                byte[] bad = (byte[])tag.Clone();
                bad[i] ^= 0x01;
                Assert.False(Hmac.Verify(Hashes.Sha256, key, data, bad));
            }
            Assert.False(Hmac.Verify(Hashes.Sha256, key, Fill(40, 3), tag));
            Assert.False(Hmac.Verify(Hashes.Sha256, Fill(32, 9), data, tag));
            Assert.False(Hmac.Verify(Hashes.Sha256, key, data, Slice(tag, 16)));
            Assert.False(Hmac.Verify(Hashes.Sha256, key, data, new byte[0]));
            Assert.False(Hmac.Verify(Hashes.Sha256, key, data, Join(tag, new byte[1])));
            Assert.Throws<ArgumentNullException>(() => Hmac.Verify(Hashes.Sha256, key, data, null));
        }

        [Fact]
        public void Cmac_verify_takes_the_right_tag_and_refuses_the_rest()
        {
            AesKey k = new AesKey(Fill(16));
            byte[] message = Fill(40, 2);
            byte[] tag = Cmac.Compute(k, message);
            Assert.True(Cmac.Verify(k, message, tag));

            for (int i = 0; i < tag.Length; i++)
            {
                byte[] bad = (byte[])tag.Clone();
                bad[i] ^= 0x01;
                Assert.False(Cmac.Verify(k, message, bad));
            }
            Assert.False(Cmac.Verify(k, Fill(40, 3), tag));
            Assert.False(Cmac.Verify(new AesKey(Fill(16, 9)), message, tag));
            Assert.False(Cmac.Verify(k, message, Slice(tag, 8)));
            Assert.False(Cmac.Verify(k, message, new byte[0]));
            Assert.False(Cmac.Verify(k, message, Join(tag, new byte[1])));
            Assert.Throws<ArgumentNullException>(() => Cmac.Verify(k, message, null));
        }

        static byte[] Slice(byte[] a, int n)
        {
            byte[] r = new byte[n];
            Buffer.BlockCopy(a, 0, r, 0, n);
            return r;
        }

        static byte[] Join(byte[] a, byte[] b)
        {
            byte[] r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }
    }
}
