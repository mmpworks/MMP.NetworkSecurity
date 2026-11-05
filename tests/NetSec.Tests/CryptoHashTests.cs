using System;
using System.Security.Cryptography;
using NetSec.Bytes;
using NetSec.Crypto;
using Xunit;

namespace NetSec.Tests
{
    public class CryptoHashTests
    {
        static IHash New(string alg)
        {
            switch (alg)
            {
                case "md5": return Hashes.Md5();
                case "sha1": return Hashes.Sha1();
                case "sha256": return Hashes.Sha256();
                case "sha384": return Hashes.Sha384();
                case "sha512": return Hashes.Sha512();
                case "sha3-256": return Hashes.Sha3_256();
                case "sha3-512": return Hashes.Sha3_512();
                default: throw new ArgumentException(alg);
            }
        }

        static byte[] Bcl(string alg, byte[] data)
        {
            switch (alg)
            {
                case "md5": using (MD5 h = MD5.Create()) return h.ComputeHash(data);
                case "sha1": using (SHA1 h = SHA1.Create()) return h.ComputeHash(data);
                case "sha256": using (SHA256 h = SHA256.Create()) return h.ComputeHash(data);
                case "sha384": using (SHA384 h = SHA384.Create()) return h.ComputeHash(data);
                case "sha512": using (SHA512 h = SHA512.Create()) return h.ComputeHash(data);
                default: throw new ArgumentException(alg);
            }
        }

        static byte[] Fill(int n)
        {
            byte[] b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = (byte)(i * 31 + 7);
            return b;
        }

        static byte[] Run(string alg, byte[] data)
        {
            IHash h = New(alg);
            h.Update(data, 0, data.Length);
            return h.Finish();
        }

        [Theory]
        [InlineData("sha1", "sha-cavp.nsv", "sha1")]
        [InlineData("sha256", "sha-cavp.nsv", "sha256")]
        [InlineData("sha384", "sha-cavp.nsv", "sha384")]
        [InlineData("sha512", "sha-cavp.nsv", "sha512")]
        [InlineData("sha3-256", "sha3-cavp.nsv", "sha3-256")]
        [InlineData("sha3-512", "sha3-cavp.nsv", "sha3-512")]
        [InlineData("md5", "md5-rfc1321.nsv", "md5")]
        public void Published_vectors_pass_whole_and_in_pieces(string alg, string file, string group)
        {
            foreach (var r in VectorFile.Read(file, group))
            {
                byte[] msg = r.ContainsKey("msg") ? r.Bytes("msg") : Hex.Decode(r["msg_ascii_hex"]);
                byte[] digest = r.Bytes("digest");
                foreach (int piece in new[] { 1, 7, 64, 65, 200 })
                {
                    IHash h = New(alg);
                    for (int off = 0; off < msg.Length; off += piece) h.Update(msg, off, Math.Min(piece, msg.Length - off));
                    Assert.Equal(Hex.Encode(digest), Hex.Encode(h.Finish()));
                }
            }
        }

        [Theory]
        [InlineData("shake128")]
        [InlineData("shake256")]
        public void Published_shake_vectors_pass(string alg)
        {
            foreach (var r in VectorFile.Read("sha3-cavp.nsv", alg))
            {
                byte[] msg = r.Bytes("msg"), expected = r.Bytes("output");
                Shake s = alg == "shake128" ? Shake.New128() : Shake.New256();
                s.Absorb(msg, 0, msg.Length);
                byte[] output = new byte[expected.Length];
                s.Squeeze(output, 0, output.Length);
                Assert.Equal(Hex.Encode(expected), Hex.Encode(output));
            }
        }

        // Every length across two blocks walks the padding branch: the length field fits in this block, or it needs one more.
        [Theory]
        [InlineData("md5")]
        [InlineData("sha1")]
        [InlineData("sha256")]
        [InlineData("sha384")]
        [InlineData("sha512")]
        public void Every_length_across_two_blocks_matches_the_bcl(string alg)
        {
            for (int n = 0; n <= 2 * New(alg).BlockSize + 1; n++)
            {
                byte[] data = Fill(n);
                Assert.Equal(Hex.Encode(Bcl(alg, data)), Hex.Encode(Run(alg, data)));
            }
        }

        [Theory]
        [InlineData("md5", 16, 64)]
        [InlineData("sha1", 20, 64)]
        [InlineData("sha256", 32, 64)]
        [InlineData("sha384", 48, 128)]
        [InlineData("sha512", 64, 128)]
        [InlineData("sha3-256", 32, 136)]
        [InlineData("sha3-512", 64, 72)]
        public void Sizes_are_the_standard_sizes(string alg, int digest, int block)
        {
            IHash h = New(alg);
            Assert.Equal(digest, h.DigestSize);
            Assert.Equal(block, h.BlockSize);
            Assert.Equal(digest, h.Finish().Length);
        }

        [Theory]
        [InlineData("md5")]
        [InlineData("sha1")]
        [InlineData("sha256")]
        [InlineData("sha384")]
        [InlineData("sha512")]
        [InlineData("sha3-256")]
        [InlineData("sha3-512")]
        public void A_clone_and_its_source_go_their_own_ways(string alg)
        {
            byte[] head = Fill(100), tailA = Fill(80), tailB = Fill(13);
            IHash source = New(alg);
            source.Update(head, 0, head.Length);

            IHash clone = source.Clone();
            clone.Update(tailB, 0, tailB.Length);
            byte[] cloneDigest = clone.Finish();

            source.Update(tailA, 0, tailA.Length);
            byte[] sourceDigest = source.Finish();

            Assert.Equal(Hex.Encode(Run(alg, Concat(head, tailB))), Hex.Encode(cloneDigest));
            Assert.Equal(Hex.Encode(Run(alg, Concat(head, tailA))), Hex.Encode(sourceDigest));
        }

        [Theory]
        [InlineData("md5")]
        [InlineData("sha256")]
        [InlineData("sha3-256")]
        public void Finish_ends_the_hash(string alg)
        {
            IHash h = New(alg);
            h.Finish();
            Assert.Throws<InvalidOperationException>(() => h.Finish());
            Assert.Throws<InvalidOperationException>(() => h.Update(new byte[1], 0, 1));
        }

        [Theory]
        [InlineData("sha256")]
        [InlineData("sha3-256")]
        public void Update_refuses_a_range_outside_the_array(string alg)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => New(alg).Update(new byte[4], 2, 3));
            Assert.Throws<ArgumentNullException>(() => New(alg).Update(null, 0, 0));
        }

        [Fact]
        public void Squeeze_in_pieces_continues_one_output_stream()
        {
            byte[] msg = Fill(50);
            Shake whole = Shake.New128();
            whole.Absorb(msg, 0, msg.Length);
            byte[] expected = new byte[500];
            whole.Squeeze(expected, 0, 500);

            Shake pieces = Shake.New128();
            pieces.Absorb(msg, 0, 20);
            pieces.Absorb(msg, 20, 30);
            byte[] output = new byte[500];
            for (int off = 0; off < 500; off += 37) pieces.Squeeze(output, off, Math.Min(37, 500 - off));
            Assert.Equal(Hex.Encode(expected), Hex.Encode(output));
        }

        [Fact]
        public void Absorb_after_squeeze_is_refused()
        {
            Shake s = Shake.New256();
            s.Squeeze(new byte[1], 0, 1);
            Assert.Throws<InvalidOperationException>(() => s.Absorb(new byte[1], 0, 1));
        }

        static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }
    }
}
