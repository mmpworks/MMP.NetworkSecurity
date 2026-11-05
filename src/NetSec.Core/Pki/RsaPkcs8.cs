using System;
using NetSec.Bytes;

namespace NetSec.Pki
{
    /// <summary>The numbers of an RSA key, read from a PKCS#8 PrivateKeyInfo (RFC 5208) that holds an RSAPrivateKey (RFC 8017 appendix A.1.2).</summary>
    public sealed class RsaPkcs8
    {
        public byte[] N, E, D, P, Q, Iqmp;

        const int TagInteger = 0x02, TagOctetString = 0x04, TagSequence = 0x30;

        /// <summary>A malformed key throws ParseFailure. The training keys are literal hex, so this code reads only known-good bytes in practice.</summary>
        public static RsaPkcs8 Parse(byte[] der)
        {
            if (der == null) throw new ArgumentNullException("der");
            Cursor info = new Cursor(der, 0, der.Length).Enter(TagSequence);
            info.Skip(TagInteger);
            info.Skip(TagSequence);
            Cursor key = info.Enter(TagOctetString);
            Cursor rsa = key.Enter(TagSequence);
            rsa.Skip(TagInteger);
            RsaPkcs8 parts = new RsaPkcs8();
            parts.N = rsa.Integer();
            parts.E = rsa.Integer();
            parts.D = rsa.Integer();
            parts.P = rsa.Integer();
            parts.Q = rsa.Integer();
            rsa.Skip(TagInteger);
            rsa.Skip(TagInteger);
            parts.Iqmp = rsa.Integer();
            return parts;
        }

        /// <summary>Reads one tag and one definite length at a time. It handles only what this one structure holds.</summary>
        sealed class Cursor
        {
            readonly byte[] _der;
            readonly int _end;
            int _at;

            public Cursor(byte[] der, int at, int count) { _der = der; _at = at; _end = at + count; }

            public Cursor Enter(int tag)
            {
                int length = Header(tag);
                Cursor inner = new Cursor(_der, _at, length);
                _at += length;
                return inner;
            }

            public void Skip(int tag)
            {
                int length = Header(tag);
                _at += length;
            }

            /// <summary>The value bytes with DER's leading sign zero removed.</summary>
            public byte[] Integer()
            {
                int length = Header(TagInteger);
                int start = _at;
                _at += length;
                int skip = length > 1 && _der[start] == 0 ? 1 : 0;
                byte[] value = new byte[length - skip];
                Buffer.BlockCopy(_der, start + skip, value, 0, value.Length);
                return value;
            }

            int Header(int tag)
            {
                if (_at + 2 > _end || _der[_at] != tag) throw new ParseFailure("PARSE_TRUNCATED", "the RSA key has no DER tag " + tag + " at offset " + _at);
                _at++;
                int first = _der[_at++];
                int length = first;
                if (first >= 0x80)
                {
                    int count = first & 0x7f;
                    if (count > 3 || _at + count > _end) throw new ParseFailure("PARSE_TRUNCATED", "the RSA key has a DER length this reader does not take");
                    length = 0;
                    for (int i = 0; i < count; i++) length = (length << 8) | _der[_at++];
                }
                if (_at + length > _end) throw new ParseFailure("PARSE_TRUNCATED", "a DER value runs past its parent");
                return length;
            }
        }
    }
}
