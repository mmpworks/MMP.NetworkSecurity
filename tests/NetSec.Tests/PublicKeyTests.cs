using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Platform;
using Xunit;

namespace NetSec.Tests
{
    public class BigUIntTests
    {
        // Values with long runs of 0 and ff limbs reach the rare branches of Knuth D: the lowered guess and the add-back.
        static byte[] Shaped(Random rng, int maxBytes)
        {
            byte[] bytes = new byte[1 + rng.Next(maxBytes)];
            rng.NextBytes(bytes);
            if (rng.Next(3) == 0)
            {
                int run = rng.Next(bytes.Length + 1);
                byte fill = rng.Next(2) == 0 ? (byte)0xff : (byte)0x00;
                for (int i = 0; i < run; i++) bytes[i] = fill;
            }
            return bytes;
        }

        static BigInteger Bcl(byte[] bigEndian)
        {
            byte[] littleEndian = new byte[bigEndian.Length + 1];   // The extra zero byte keeps the value positive.
            for (int i = 0; i < bigEndian.Length; i++) littleEndian[i] = bigEndian[bigEndian.Length - 1 - i];
            return new BigInteger(littleEndian);
        }

        static BigInteger Bcl(BigUInt value) { return Bcl(value.ToBigEndian()); }

        [Fact]
        public void Add_multiply_and_divide_match_System_Numerics_on_2000_shaped_pairs()
        {
            Random rng = new Random(1401);
            for (int i = 0; i < 2000; i++)
            {
                byte[] a = Shaped(rng, 80), b = Shaped(rng, 40);
                BigUInt x = BigUInt.FromBytes(a), y = BigUInt.FromBytes(b);
                BigInteger bx = Bcl(a), by = Bcl(b);
                Assert.Equal(bx + by, Bcl(x.Add(y)));
                Assert.Equal(bx * by, Bcl(x.Multiply(y)));
                if (by.IsZero) continue;
                BigUInt rest;
                BigUInt quotient = x.DivRem(y, out rest);
                Assert.Equal(BigInteger.Divide(bx, by), Bcl(quotient));
                Assert.Equal(BigInteger.Remainder(bx, by), Bcl(rest));
            }
        }

        [Fact]
        public void Division_runs_the_add_back_branch_on_the_known_input()
        {
            // This input runs the add-back once: a port of the control flow to Python counted it. The first guess stays 1 too high.
            BigUInt dividend = BigUInt.FromBytes(Hex.Decode("7fffffff800000000000000000000000"));
            BigUInt divisor = BigUInt.FromBytes(Hex.Decode("800000000000000000000001"));
            BigUInt rest;
            BigUInt quotient = dividend.DivRem(divisor, out rest);
            Assert.Equal(BigInteger.Divide(Bcl(dividend), Bcl(divisor)), Bcl(quotient));
            Assert.Equal(BigInteger.Remainder(Bcl(dividend), Bcl(divisor)), Bcl(rest));
        }

        [Fact]
        public void ModPow_matches_System_Numerics_for_odd_moduli()
        {
            Random rng = new Random(1402);
            for (int i = 0; i < 300; i++)
            {
                byte[] b = Shaped(rng, 64), e = Shaped(rng, 16), m = Shaped(rng, 64);
                m[m.Length - 1] |= 1;
                BigInteger expected = BigInteger.ModPow(Bcl(b), Bcl(e), Bcl(m));
                Assert.Equal(expected, Bcl(BigUInt.FromBytes(b).ModPow(BigUInt.FromBytes(e), BigUInt.FromBytes(m))));
            }
        }

        [Fact]
        public void ModPow_handles_exponent_zero_and_modulus_one_and_refuses_an_even_modulus()
        {
            BigUInt seven = BigUInt.FromUInt32(7), eleven = BigUInt.FromUInt32(11);
            Assert.Equal(0, seven.ModPow(BigUInt.Zero, eleven).CompareTo(BigUInt.One));
            Assert.True(seven.ModPow(eleven, BigUInt.One).IsZero);
            Assert.Throws<ArgumentException>(() => seven.ModPow(eleven, BigUInt.FromUInt32(10)));
        }

        [Fact]
        public void Bytes_round_trip_with_leading_zeros_and_fixed_width()
        {
            BigUInt value = BigUInt.FromBytes(Hex.Decode("000000012345"));
            Assert.Equal("012345", Hex.Encode(value.ToBigEndian()));
            Assert.Equal("00012345", Hex.Encode(value.ToBigEndian(4)));
            Assert.Equal(17, value.BitLength);
            Assert.Empty(BigUInt.Zero.ToBigEndian());
            Assert.Throws<ArgumentException>(() => value.ToBigEndian(2));
        }

        [Fact]
        public void Subtract_refuses_a_negative_result_and_borrows_across_limbs()
        {
            BigUInt big = BigUInt.FromBytes(Hex.Decode("0100000000"));
            Assert.Equal("ffffffff", Hex.Encode(big.Subtract(BigUInt.One).ToBigEndian()));
            Assert.Throws<ArgumentException>(() => BigUInt.One.Subtract(big));
        }
    }

    public class X25519Tests
    {
        [Fact]
        public void Rfc7748_section_5_2_first_vector()
        {
            byte[] scalar = Hex.Decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
            byte[] u = Hex.Decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
            Assert.Equal("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", Hex.Encode(X25519.Mult(scalar, u)));
        }

        [Fact]
        public void The_top_bit_of_the_point_is_ignored()
        {
            byte[] scalar = new byte[32];
            scalar[0] = 77;
            byte[] point = X25519.MultBase(new byte[32]);
            byte[] withTopBit = (byte[])point.Clone();
            withTopBit[31] |= 0x80;
            Assert.Equal(X25519.Mult(scalar, point), X25519.Mult(scalar, withTopBit));
        }

        [Fact]
        public void A_wrong_length_is_refused()
        {
            Assert.Throws<ArgumentException>(() => X25519.Mult(new byte[31], new byte[32]));
            Assert.Throws<ArgumentException>(() => X25519.Mult(new byte[32], new byte[33]));
        }
    }

    public class Ed25519Tests
    {
        // RFC 8032 section 7.1, TEST 1.
        static readonly byte[] Seed = Hex.Decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        static readonly byte[] Public = Hex.Decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        static readonly byte[] Signature = Hex.Decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

        [Fact]
        public void Rfc8032_test_1_signs_and_verifies()
        {
            Assert.Equal(Public, Ed25519.PublicFrom(Seed));
            Assert.Equal(Signature, Ed25519.Sign(Seed, new byte[0]));
            Assert.True(Ed25519.Verify(Public, new byte[0], Signature));
        }

        [Fact]
        public void Verify_refuses_S_plus_L_so_a_signature_has_one_form()
        {
            byte[] l = Hex.Decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");   // Little-endian.
            byte[] forged = (byte[])Signature.Clone();
            int carry = 0;
            for (int i = 0; i < 32; i++)
            {
                int total = forged[32 + i] + l[i] + carry;
                forged[32 + i] = (byte)total;
                carry = total >> 8;
            }
            Assert.False(Ed25519.Verify(Public, new byte[0], forged));
        }

        [Fact]
        public void Verify_refuses_a_public_key_with_y_at_or_above_p()
        {
            // With A at y = 1 (the neutral point), h*A adds nothing, so R = B and S = 1 verifies for any message. That is the control.
            byte[] r = Hex.Decode("5866666666666666666666666666666666666666666666666666666666666666");
            byte[] s = Hex.Decode("0100000000000000000000000000000000000000000000000000000000000000");
            byte[] signature = r.Concat(s).ToArray();
            byte[] canonical = Hex.Decode("0100000000000000000000000000000000000000000000000000000000000000");
            byte[] sameValueAboveP = Hex.Decode("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");   // p + 1
            Assert.True(Ed25519.Verify(canonical, new byte[] { 1 }, signature));
            Assert.False(Ed25519.Verify(sameValueAboveP, new byte[] { 1 }, signature));
        }

        [Fact]
        public void Verify_refuses_the_sign_bit_on_the_neutral_point_because_x_is_zero()
        {
            // RFC 8032 section 5.1.3 step 4. At y = 1, x = 0, so a set sign bit is a second encoding of one point.
            byte[] signature = Hex.Decode("5866666666666666666666666666666666666666666666666666666666666666" + "0100000000000000000000000000000000000000000000000000000000000000");
            byte[] control = Hex.Decode("0100000000000000000000000000000000000000000000000000000000000000");
            byte[] signSet = Hex.Decode("0100000000000000000000000000000000000000000000000000000000000080");
            Assert.True(Ed25519.Verify(control, new byte[] { 1 }, signature));
            Assert.False(Ed25519.Verify(signSet, new byte[] { 1 }, signature));
        }

        [Fact]
        public void Verify_refuses_the_sign_bit_on_the_order_2_point_because_x_is_zero()
        {
            // y = -1 is the only other point with x = 0. It has order 2, so h*A adds nothing when h is even, and h changes with the message.
            byte[] signature = Hex.Decode("5866666666666666666666666666666666666666666666666666666666666666" + "0100000000000000000000000000000000000000000000000000000000000000");
            byte[] control = Hex.Decode("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
            byte[] signSet = Hex.Decode("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            int controlAccepted = 0;
            for (byte m = 0; m < 16; m++)
            {
                if (Ed25519.Verify(control, new[] { m }, signature)) controlAccepted++;
                Assert.False(Ed25519.Verify(signSet, new[] { m }, signature));
            }
            Assert.InRange(controlAccepted, 1, 15);
        }

        [Fact]
        public void Verify_returns_false_for_wrong_lengths()
        {
            Assert.False(Ed25519.Verify(new byte[31], new byte[0], Signature));
            Assert.False(Ed25519.Verify(Public, new byte[0], new byte[63]));
        }
    }

    public class RsaTests
    {
        sealed class Scripted : IRandomSource
        {
            readonly byte[] _bytes;
            int _next;
            public Scripted(params byte[] bytes) { _bytes = bytes; }
            public int Draws { get { return _next; } }
            public void Fill(byte[] b, int off, int n)
            {
                for (int i = 0; i < n; i++) b[off + i] = _bytes[_next++ % _bytes.Length];
            }
        }

        static Dictionary<string, string> Key() { return VectorFile.Read("rsa-openssl.nsv", "rsa-sign")[0]; }
        static RsaPublic Public() { Dictionary<string, string> k = Key(); return new RsaPublic(BigUInt.FromBytes(k.Bytes("n")), BigUInt.FromBytes(k.Bytes("e"))); }
        static RsaPrivate Private() { Dictionary<string, string> k = Key(); return new RsaPrivate(BigUInt.FromBytes(k.Bytes("n")), BigUInt.FromBytes(k.Bytes("d"))); }

        [Fact]
        public void Sign_and_verify_round_trip_with_both_hashes()
        {
            byte[] message = { 1, 2, 3 };
            Assert.True(Pkcs1.VerifySha1(Public(), message, Pkcs1.SignSha1(Private(), message)));
            Assert.True(Pkcs1.VerifySha256(Public(), message, Pkcs1.SignSha256(Private(), message)));
            Assert.False(Pkcs1.VerifySha256(Public(), message, Pkcs1.SignSha1(Private(), message)));
        }

        [Fact]
        public void Verify_refuses_a_block_with_junk_after_the_digest()
        {
            // The 2006 forgery shape: short padding, a valid digest, then junk at the end. A parsing verifier accepts it.
            byte[] message = { 1, 2, 3 };
            IHash hash = Hashes.Sha256();
            hash.Update(message, 0, message.Length);
            byte[] digestInfo = Hex.Decode("3031300d060960864801650304020105000420").Concat(hash.Finish()).ToArray();
            int k = Public().ModulusLength;
            byte[] block = new byte[k];
            block[1] = 1;
            for (int i = 2; i < 10; i++) block[i] = 0xff;
            Array.Copy(digestInfo, 0, block, 11, digestInfo.Length);
            for (int i = 11 + digestInfo.Length; i < k; i++) block[i] = 0x5a;
            Assert.False(Pkcs1.VerifySha256(Public(), message, Private().Raw(block)));
        }

        [Fact]
        public void Verify_refuses_a_wrong_length_and_a_value_at_the_modulus()
        {
            byte[] message = { 1 };
            byte[] signature = Pkcs1.SignSha1(Private(), message);
            Assert.False(Pkcs1.VerifySha1(Public(), message, signature.Concat(new byte[] { 0 }).ToArray()));
            Assert.False(Pkcs1.VerifySha1(Public(), message, Key().Bytes("n")));
        }

        [Fact]
        public void Raw_refuses_a_value_at_or_above_the_modulus_by_code()
        {
            NetSecException e = Assert.Throws<NetSecException>(() => Public().Raw(Key().Bytes("n")));
            Assert.Equal(ErrorCodes.RsaValueOutOfRange, e.Error.Code);
        }

        [Fact]
        public void Encrypt_draws_again_on_a_zero_padding_byte()
        {
            byte[] plain = { 9, 8, 7 };
            Scripted random = new Scripted(0, 0x11, 0, 0x22);
            byte[] cipher = Pkcs1.EncryptV15(Public(), random, plain);
            byte[] back;
            Assert.True(Pkcs1.TryDecryptV15(Private(), cipher, out back));
            Assert.Equal(plain, back);
            int paddingLength = Public().ModulusLength - plain.Length - 3;
            Assert.Equal(2 * paddingLength, random.Draws);
        }

        [Fact]
        public void Encrypt_refuses_a_message_that_leaves_under_8_padding_bytes()
        {
            int k = Public().ModulusLength;
            Pkcs1.EncryptV15(Public(), new Scripted(0x33), new byte[k - 11]);
            NetSecException e = Assert.Throws<NetSecException>(() => Pkcs1.EncryptV15(Public(), new Scripted(0x33), new byte[k - 10]));
            Assert.Equal(ErrorCodes.RsaMessageTooLong, e.Error.Code);
        }

        [Fact]
        public void Decrypt_returns_false_for_each_bad_block_shape()
        {
            int k = Public().ModulusLength;
            byte[] wrongType = new byte[k];
            wrongType[1] = 1;
            for (int i = 2; i < k; i++) wrongType[i] = 0x44;
            wrongType[k - 2] = 0;

            byte[] noSeparator = new byte[k];
            noSeparator[1] = 2;
            for (int i = 2; i < k; i++) noSeparator[i] = 0x44;

            byte[] shortPadding = (byte[])noSeparator.Clone();
            shortPadding[9] = 0;    // Seven padding bytes.

            byte[] good = (byte[])noSeparator.Clone();
            good[10] = 0;           // Eight padding bytes: the control.

            byte[] plain;
            Assert.True(Pkcs1.TryDecryptV15(Private(), Public().Raw(good), out plain));
            Assert.False(Pkcs1.TryDecryptV15(Private(), Public().Raw(wrongType), out plain));
            Assert.False(Pkcs1.TryDecryptV15(Private(), Public().Raw(noSeparator), out plain));
            Assert.False(Pkcs1.TryDecryptV15(Private(), Public().Raw(shortPadding), out plain));
            Assert.False(Pkcs1.TryDecryptV15(Private(), new byte[k - 1], out plain));
            Assert.False(Pkcs1.TryDecryptV15(Private(), Key().Bytes("n"), out plain));
        }
    }

    public class DhGroup14Tests
    {
        [Fact]
        public void Two_sides_reach_one_secret_with_short_exponents()
        {
            byte[] a = new byte[64], b = new byte[64];
            new SeededRandom(1).Fill(a, 0, 64);
            new SeededRandom(2).Fill(b, 0, 64);
            byte[] sharedA = DhGroup14.Shared(a, DhGroup14.Public(b));
            Assert.Equal(256, sharedA.Length);
            Assert.Equal(sharedA, DhGroup14.Shared(b, DhGroup14.Public(a)));
        }

        [Fact]
        public void The_peer_range_is_2_to_p_minus_2()
        {
            byte[] p = Hex.Decode(VectorFile.Read("dh-group14-rfc3526.nsv", "dh-group14-params")[0]["p"]);
            byte[] x = { 3 };
            byte[] pMinus2 = (byte[])p.Clone();
            pMinus2[255] -= 2;
            byte[] pMinus1 = (byte[])p.Clone();
            pMinus1[255] -= 1;
            DhGroup14.Shared(x, new byte[] { 2 });
            DhGroup14.Shared(x, pMinus2);
            foreach (byte[] bad in new[] { new byte[] { 0 }, new byte[] { 1 }, pMinus1, p })
            {
                NetSecException e = Assert.Throws<NetSecException>(() => DhGroup14.Shared(x, bad));
                Assert.Equal(ErrorCodes.DhPeerOutOfRange, e.Error.Code);
            }
        }
    }

    public class MlKem768Tests
    {
        static IEnumerable<string[]> Vectors(string kind)
        {
            string directory = AppContext.BaseDirectory;
            while (!File.Exists(Path.Combine(directory, "tests", "NetSec.Tests", "vectors", "mlkem768-acvp.txt")))
            {
                directory = Path.GetDirectoryName(directory);
                Assert.NotNull(directory);
            }
            string file = Path.Combine(directory, "tests", "NetSec.Tests", "vectors", "mlkem768-acvp.txt");
            return File.ReadAllLines(file).Where(l => l.StartsWith(kind + " ")).Select(l => l.Split(' '));
        }

        [Fact]
        public void Nist_keygen_vectors_match()
        {
            int count = 0;
            foreach (string[] v in Vectors("keygen"))
            {
                MlKemPair pair = MlKem768.KeyGen(Hex.Decode(v[1]), Hex.Decode(v[2]));
                Assert.Equal(v[3], Hex.Encode(pair.Ek), ignoreCase: true);
                Assert.Equal(v[4], Hex.Encode(pair.Dk), ignoreCase: true);
                count++;
            }
            Assert.Equal(3, count);
        }

        [Fact]
        public void Nist_encapsulation_vectors_match()
        {
            int count = 0;
            foreach (string[] v in Vectors("encaps"))
            {
                MlKemSealed sealedKey = MlKem768.Encaps(Hex.Decode(v[1]), Hex.Decode(v[2]));
                Assert.Equal(v[3], Hex.Encode(sealedKey.Ciphertext), ignoreCase: true);
                Assert.Equal(v[4], Hex.Encode(sealedKey.SharedSecret), ignoreCase: true);
                count++;
            }
            Assert.Equal(3, count);
        }

        [Fact]
        public void Nist_decapsulation_vectors_match_including_modified_ciphertext()
        {
            int count = 0;
            foreach (string[] v in Vectors("decaps"))
            {
                Assert.Equal(v[3], Hex.Encode(MlKem768.Decaps(Hex.Decode(v[1]), Hex.Decode(v[2]))), ignoreCase: true);
                count++;
            }
            Assert.Equal(10, count);
        }

        [Fact]
        public void Nist_encapsulation_key_checks_match()
        {
            int passed = 0, failed = 0;
            foreach (string[] v in Vectors("ekcheck"))
            {
                if (v[2] == "pass")
                {
                    MlKem768.Encaps(Hex.Decode(v[1]), new byte[32]);
                    passed++;
                }
                else
                {
                    NetSecException e = Assert.Throws<NetSecException>(() => MlKem768.Encaps(Hex.Decode(v[1]), new byte[32]));
                    Assert.Equal(ErrorCodes.MlKemKeyInvalid, e.Error.Code);
                    failed++;
                }
            }
            Assert.Equal(5, passed);
            Assert.Equal(5, failed);
        }

        [Fact]
        public void Nist_decapsulation_key_checks_match()
        {
            int passed = 0, failed = 0;
            foreach (string[] v in Vectors("dkcheck"))
            {
                if (v[2] == "pass")
                {
                    MlKem768.Decaps(Hex.Decode(v[1]), new byte[1088]);
                    passed++;
                }
                else
                {
                    NetSecException e = Assert.Throws<NetSecException>(() => MlKem768.Decaps(Hex.Decode(v[1]), new byte[1088]));
                    Assert.Equal(ErrorCodes.MlKemKeyInvalid, e.Error.Code);
                    failed++;
                }
            }
            Assert.Equal(5, passed);
            Assert.Equal(5, failed);
        }

        [Fact]
        public void A_round_trip_agrees_and_a_flipped_ciphertext_bit_gives_a_different_secret_and_no_error()
        {
            byte[] d = new byte[32], z = new byte[32], m = new byte[32];
            SeededRandom random = new SeededRandom(7);
            random.Fill(d, 0, 32);
            random.Fill(z, 0, 32);
            random.Fill(m, 0, 32);
            MlKemPair pair = MlKem768.KeyGen(d, z);
            Assert.Equal(1184, pair.Ek.Length);
            Assert.Equal(2400, pair.Dk.Length);
            MlKemSealed sealedKey = MlKem768.Encaps(pair.Ek, m);
            Assert.Equal(1088, sealedKey.Ciphertext.Length);
            Assert.Equal(sealedKey.SharedSecret, MlKem768.Decaps(pair.Dk, sealedKey.Ciphertext));

            byte[] tampered = sealedKey.Ciphertext;
            tampered[100] ^= 1;
            Assert.NotEqual(sealedKey.SharedSecret, MlKem768.Decaps(pair.Dk, tampered));
        }

        [Fact]
        public void A_wrong_ciphertext_length_is_refused_by_code()
        {
            MlKemPair pair = MlKem768.KeyGen(new byte[32], new byte[32]);
            NetSecException e = Assert.Throws<NetSecException>(() => MlKem768.Decaps(pair.Dk, new byte[1087]));
            Assert.Equal(ErrorCodes.MlKemCiphertextInvalid, e.Error.Code);
        }

        [Fact]
        public void Key_and_sealed_properties_hand_out_copies()
        {
            MlKemPair pair = MlKem768.KeyGen(new byte[32], new byte[32]);
            pair.Ek[0] ^= 1;
            Assert.Equal(pair.Ek, MlKem768.KeyGen(new byte[32], new byte[32]).Ek);
        }
    }

    public class SeededRandomTests
    {
        [Fact]
        public void One_seed_gives_the_pinned_bytes_on_both_builds()
        {
            // python: hashlib.shake_256(b"NetSec.Seed" + (42).to_bytes(4, "big")).hexdigest(16)
            byte[] drawn = new byte[16];
            new SeededRandom(42).Fill(drawn, 0, 16);
            Assert.Equal(PinnedSeed42, Hex.Encode(drawn));
        }

        const string PinnedSeed42 = "920758d9bb8a5b45bbfcfc17def9a21a";

        [Fact]
        public void Pieces_join_to_the_one_shot_stream_and_seeds_differ()
        {
            byte[] whole = new byte[300], pieces = new byte[300];
            new SeededRandom(5).Fill(whole, 0, 300);
            SeededRandom random = new SeededRandom(5);
            random.Fill(pieces, 0, 1);
            random.Fill(pieces, 1, 136);
            random.Fill(pieces, 137, 163);
            Assert.Equal(whole, pieces);

            byte[] other = new byte[300];
            new SeededRandom(6).Fill(other, 0, 300);
            Assert.NotEqual(whole, other);
        }
    }
}
