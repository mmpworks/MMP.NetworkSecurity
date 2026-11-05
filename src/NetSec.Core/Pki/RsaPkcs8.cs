using System;

namespace NetSec.Pki
{
    /// <summary>The numbers of an RSA key, read from a PKCS#8 PrivateKeyInfo (RFC 5208) that holds an RSAPrivateKey (RFC 8017 appendix A.1.2).</summary>
    public sealed class RsaPkcs8
    {
        public byte[] N, E, D;

        public static RsaPkcs8 Parse(byte[] der)
        {
            if (der == null) throw new ArgumentNullException("der");
            DerReader info = new DerReader(der, 0, der.Length).Read(Der.TagSequence).Inner;
            info.Read(Der.TagInteger);
            info.Read(Der.TagSequence);
            byte[] inner = info.Read(Der.TagOctetString).Value;
            DerReader rsa = new DerReader(inner, 0, inner.Length).Read(Der.TagSequence).Inner;
            rsa.Read(Der.TagInteger);
            RsaPkcs8 parts = new RsaPkcs8();
            parts.N = rsa.Read(Der.TagInteger).Value;
            parts.E = rsa.Read(Der.TagInteger).Value;
            parts.D = rsa.Read(Der.TagInteger).Value;
            return parts;
        }
    }
}
