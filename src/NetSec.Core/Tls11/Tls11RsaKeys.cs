using NetSec.Crypto;
using NetSec.Pki;

namespace NetSec.Tls11
{
    /// <summary>RSA keys in the DER forms that X.509 and PKCS#8 use. A public key comes from the wire, so its shape gets a check before any arithmetic runs.</summary>
    public static class Tls11RsaKeys
    {
        /// <summary>On RSA key transport this key guards the whole session, so a small key the CA signed is still refused. The training key has this size.</summary>
        public const int MinModulusBits = 2048;

        /// <summary>Reads RSAPublicKey (RFC 8017 appendix A.1.1). Null means the key is unusable, and problem says why.</summary>
        public static RsaPublic TryReadPublic(byte[] der, out string problem)
        {
            DerReader sequence = new DerReader(der, 0, der.Length).Read(Der.TagSequence).Inner;
            BigUInt n = BigUInt.FromBytes(sequence.Read(Der.TagInteger).Value);
            BigUInt e = BigUInt.FromBytes(sequence.Read(Der.TagInteger).Value);
            problem = Shape(n, e);
            return problem == null ? new RsaPublic(n, e) : null;
        }

        /// <summary>An even modulus makes BigUInt throw, and an even or tiny exponent gives no usable key.</summary>
        static string Shape(BigUInt n, BigUInt e)
        {
            if (!n.IsOdd) return "the RSA modulus is even";
            if (n.BitLength < MinModulusBits) return "the RSA modulus has " + n.BitLength + " bits, below the limit of " + MinModulusBits;
            if (!e.IsOdd || e.BitLength < 2) return "the RSA exponent is even or below 3";
            return null;
        }

        /// <summary>Reads the n and d of a PKCS#8 PrivateKeyInfo that holds an RSAPrivateKey (RFC 5958, RFC 8017 appendix A.1.2).</summary>
        public static RsaPrivate ReadPrivate(byte[] pkcs8)
        {
            DerReader info = new DerReader(pkcs8, 0, pkcs8.Length).Read(Der.TagSequence).Inner;
            info.Read(Der.TagInteger);
            info.Read(Der.TagSequence);
            DerItem wrapped = info.Read(Der.TagOctetString);
            DerReader key = wrapped.Inner.Read(Der.TagSequence).Inner;
            key.Read(Der.TagInteger);
            BigUInt n = BigUInt.FromBytes(key.Read(Der.TagInteger).Value);
            key.Read(Der.TagInteger);
            return new RsaPrivate(n, BigUInt.FromBytes(key.Read(Der.TagInteger).Value));
        }
    }
}
