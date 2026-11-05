using System;
using NetSec.Bytes;
using NetSec.Errors;

namespace NetSec.Crypto
{
    public sealed class RsaPublic
    {
        readonly BigUInt _n, _e;

        public RsaPublic(BigUInt n, BigUInt e)
        {
            if (n == null) throw new ArgumentNullException("n");
            if (e == null) throw new ArgumentNullException("e");
            _n = n;
            _e = e;
        }

        public BigUInt N { get { return _n; } }
        public BigUInt E { get { return _e; } }
        public int ModulusLength { get { return RsaMath.LengthOf(_n); } }

        /// <summary>m^e mod n, at the width of the modulus. A value at or above n throws RSA_VALUE_OUT_OF_RANGE.</summary>
        public byte[] Raw(byte[] m) { return RsaMath.Apply(m, _e, _n); }
    }

    public sealed class RsaPrivate
    {
        readonly BigUInt _n, _d;

        public RsaPrivate(BigUInt n, BigUInt d)
        {
            if (n == null) throw new ArgumentNullException("n");
            if (d == null) throw new ArgumentNullException("d");
            _n = n;
            _d = d;
        }

        internal BigUInt N { get { return _n; } }
        public int ModulusLength { get { return RsaMath.LengthOf(_n); } }

        /// <summary>c^d mod n, at the width of the modulus. This code holds only n and d, so it does not use the CRT shortcut.</summary>
        public byte[] Raw(byte[] c) { return RsaMath.Apply(c, _d, _n); }
    }

    internal static class RsaMath
    {
        public static int LengthOf(BigUInt n) { return (n.BitLength + 7) / 8; }

        public static byte[] Apply(byte[] value, BigUInt exponent, BigUInt n)
        {
            if (value == null) throw new ArgumentNullException("value");
            BigUInt v = BigUInt.FromBigEndian(value);
            if (v.CompareTo(n) >= 0) throw new NetSecException(NetSecError.Of(ErrorCodes.RsaValueOutOfRange, "the RSA input is not below the modulus"));
            return v.ModPow(exponent, n).ToBigEndian(LengthOf(n));
        }
    }

    /// <summary>
    /// PKCS#1 v1.5 (RFC 8017 sections 7.2 and 8.2). Built to show the parts. Do not copy: a real TLS server must not reveal
    /// whether padding was valid, because Bleichenbacher's attack reads that answer. This class returns false on bad padding.
    /// </summary>
    public static class Pkcs1
    {
        const int MinimumPadding = 8;

        // DER of DigestInfo up to the digest itself (RFC 8017 section 9.2, note 1).
        static readonly byte[] Sha1Prefix = Hex.Decode("3021300906052b0e03021a05000414");
        static readonly byte[] Sha256Prefix = Hex.Decode("3031300d060960864801650304020105000420");

        /// <summary>The block is 00 02, at least 8 random bytes that are not zero, 00, then the message.</summary>
        public static byte[] EncryptV15(RsaPublic key, IRandomSource random, byte[] plain)
        {
            if (key == null) throw new ArgumentNullException("key");
            if (random == null) throw new ArgumentNullException("random");
            if (plain == null) throw new ArgumentNullException("plain");
            int k = key.ModulusLength;
            int paddingLength = k - plain.Length - 3;
            if (paddingLength < MinimumPadding) throw new NetSecException(NetSecError.Of(ErrorCodes.RsaMessageTooLong, "the message does not fit under this modulus"));
            byte[] block = new byte[k];
            block[1] = 2;
            FillNonZero(block, 2, paddingLength, random);
            Array.Copy(plain, 0, block, k - plain.Length, plain.Length);
            return key.Raw(block);
        }

        /// <summary>A padding byte cannot be zero, because a zero ends the padding. Each zero draw is drawn again.</summary>
        static void FillNonZero(byte[] block, int offset, int count, IRandomSource random)
        {
            byte[] one = new byte[1];
            for (int i = 0; i < count; i++)
            {
                do { random.Fill(one, 0, 1); } while (one[0] == 0);
                block[offset + i] = one[0];
            }
        }

        public static bool TryDecryptV15(RsaPrivate key, byte[] cipher, out byte[] plain)
        {
            if (key == null) throw new ArgumentNullException("key");
            if (cipher == null) throw new ArgumentNullException("cipher");
            plain = null;
            if (cipher.Length != key.ModulusLength) return false;
            if (BigUInt.FromBigEndian(cipher).CompareTo(key.N) >= 0) return false;
            byte[] block = key.Raw(cipher);
            if (block[0] != 0 || block[1] != 2) return false;
            int separator = 2;
            while (separator < block.Length && block[separator] != 0) separator++;
            if (separator == block.Length || separator - 2 < MinimumPadding) return false;
            plain = new byte[block.Length - separator - 1];
            Array.Copy(block, separator + 1, plain, 0, plain.Length);
            return true;
        }

        public static byte[] SignSha1(RsaPrivate key, byte[] message) { return Sign(key, Sha1Prefix, Hashes.Sha1(), message); }

        public static byte[] SignSha256(RsaPrivate key, byte[] message) { return Sign(key, Sha256Prefix, Hashes.Sha256(), message); }

        public static bool VerifySha1(RsaPublic key, byte[] message, byte[] signature) { return Verify(key, Sha1Prefix, Hashes.Sha1(), message, signature); }

        public static bool VerifySha256(RsaPublic key, byte[] message, byte[] signature) { return Verify(key, Sha256Prefix, Hashes.Sha256(), message, signature); }

        static byte[] Sign(RsaPrivate key, byte[] prefix, IHash hash, byte[] message)
        {
            if (key == null) throw new ArgumentNullException("key");
            return key.Raw(EncodeSignatureBlock(key.ModulusLength, prefix, hash, message));
        }

        /// <summary>
        /// Builds the block this message must give, then compares whole blocks. Parsing the signature's block instead lets a
        /// forged block with junk after the digest pass (Bleichenbacher 2006).
        /// </summary>
        static bool Verify(RsaPublic key, byte[] prefix, IHash hash, byte[] message, byte[] signature)
        {
            if (key == null) throw new ArgumentNullException("key");
            if (signature == null) throw new ArgumentNullException("signature");
            if (signature.Length != key.ModulusLength) return false;
            if (BigUInt.FromBigEndian(signature).CompareTo(key.N) >= 0) return false;
            byte[] actual = key.Raw(signature);
            byte[] expected = EncodeSignatureBlock(key.ModulusLength, prefix, hash, message);
            int difference = 0;
            for (int i = 0; i < expected.Length; i++) difference |= actual[i] ^ expected[i];
            return difference == 0;
        }

        /// <summary>The block is 00 01, ff bytes, 00, the DigestInfo prefix, then the digest (RFC 8017 section 9.2).</summary>
        static byte[] EncodeSignatureBlock(int k, byte[] prefix, IHash hash, byte[] message)
        {
            if (message == null) throw new ArgumentNullException("message");
            hash.Update(message, 0, message.Length);
            byte[] digest = hash.Finish();
            int paddingLength = k - prefix.Length - digest.Length - 3;
            if (paddingLength < MinimumPadding) throw new NetSecException(NetSecError.Of(ErrorCodes.RsaMessageTooLong, "the digest does not fit under this modulus"));
            byte[] block = new byte[k];
            block[1] = 1;
            for (int i = 0; i < paddingLength; i++) block[2 + i] = 0xff;
            Array.Copy(prefix, 0, block, 3 + paddingLength, prefix.Length);
            Array.Copy(digest, 0, block, 3 + paddingLength + prefix.Length, digest.Length);
            return block;
        }
    }
}
