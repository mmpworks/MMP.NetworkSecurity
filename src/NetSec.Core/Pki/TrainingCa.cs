using System;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Keys;

namespace NetSec.Pki
{
    /// <summary>
    /// A made-up certificate authority. Its key is a training key anyone can read, so its certificates prove nothing outside these labs.
    /// All signatures are Ed25519. Same input, same bytes, because Ed25519 signing has no random part.
    /// </summary>
    public sealed class TrainingCa
    {
        public const string RootName = "MMP.NetworkSecurity training root";
        public static readonly DateTime DefaultNotBefore = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        public static readonly DateTime DefaultNotAfter = new DateTime(2049, 12, 31, 0, 0, 0, DateTimeKind.Utc);

        const string Ed25519Oid = "2b6570";
        const string CommonNameOid = "550403";
        const string BasicConstraintsOid = "551d13";
        const string KeyUsageOid = "551d0f";
        const string SubjectAltNameOid = "551d11";
        const string ExtendedKeyUsageOid = "551d25";
        const string SubjectKeyIdOid = "551d0e";
        const string AuthorityKeyIdOid = "551d23";
        const string ServerAuthOid = "2b06010505070301";
        const string ClientAuthOid = "2b06010505070302";
        const int DnsNameTag = 0x82;
        const int KeyIdTag = 0x80;

        readonly byte[] _seed, _public;
        readonly string _name;
        readonly byte[] _root;

        public TrainingCa(ITrainingKeySource keys) : this(keys.Find(KeyIds.CaRoot), RootName) { }

        /// <summary>A CA under any Ed25519 key and name. The unknown-CA attack uses the attacker key here.</summary>
        public TrainingCa(ITrainingKey key, string name)
        {
            if (key == null) throw new ArgumentNullException("key");
            _seed = key.CopyMaterial();
            _public = key.CopyPublic();
            _name = name;
            _root = BuildRoot();
        }

        public byte[] RootCertificateDer { get { return (byte[])_root.Clone(); } }

        /// <summary>The leaf carries dnsName as its CN and as a dNSName SAN. The caller gives the subject key as a SubjectPublicKeyInfo, so an RSA key fits too.</summary>
        public byte[] IssueServerCertificate(string dnsName, byte[] subjectPublicKeyInfoDer, DateTime notBefore, DateTime notAfter)
        {
            byte[] san = Der.Sequence(Der.Tlv(DnsNameTag, System.Text.Encoding.UTF8.GetBytes(dnsName)));
            byte[] extensions = Der.Sequence(
                Extension(BasicConstraintsOid, true, Der.Sequence()),
                Extension(ExtendedKeyUsageOid, false, Der.Sequence(Der.Oid(ServerAuthOid))),
                Extension(SubjectAltNameOid, false, san),
                Extension(AuthorityKeyIdOid, false, Der.Sequence(Der.Tlv(KeyIdTag, KeyId(_public)))));
            return Sign(Serial(dnsName), _name, dnsName, notBefore, notAfter, subjectPublicKeyInfoDer, extensions);
        }

        /// <summary>The leaf carries the subject name as its CN and allows client authentication only. It has no SAN, because nobody dials a client.</summary>
        public byte[] IssueClientCertificate(string subjectName, byte[] subjectPublicKeyInfoDer, DateTime notBefore, DateTime notAfter)
        {
            byte[] extensions = Der.Sequence(
                Extension(BasicConstraintsOid, true, Der.Sequence()),
                Extension(ExtendedKeyUsageOid, false, Der.Sequence(Der.Oid(ClientAuthOid))),
                Extension(AuthorityKeyIdOid, false, Der.Sequence(Der.Tlv(KeyIdTag, KeyId(_public)))));
            return Sign(Serial(subjectName), _name, subjectName, notBefore, notAfter, subjectPublicKeyInfoDer, extensions);
        }

        public static byte[] Ed25519Spki(byte[] publicKey)
        {
            return Der.Sequence(Der.Sequence(Der.Oid(Ed25519Oid)), Der.BitString(publicKey));
        }

        /// <summary>RFC 8410: a version-0 PrivateKeyInfo whose key is an octet string inside an octet string.</summary>
        public static byte[] Ed25519Pkcs8(byte[] seed)
        {
            return Der.Sequence(Der.Integer(new byte[] { 0 }), Der.Sequence(Der.Oid(Ed25519Oid)), Der.OctetString(Der.OctetString(seed)));
        }

        byte[] BuildRoot()
        {
            byte[] keyUsageCertSignAndCrlSign = Der.Tlv(Der.TagBitString, new byte[] { 1, 0x06 });
            byte[] extensions = Der.Sequence(
                Extension(BasicConstraintsOid, true, Der.Sequence(Der.Boolean(true))),
                Extension(KeyUsageOid, true, keyUsageCertSignAndCrlSign),
                Extension(SubjectKeyIdOid, false, Der.OctetString(KeyId(_public))));
            return Sign(Serial(_name), _name, _name, DefaultNotBefore, DefaultNotAfter, Ed25519Spki(_public), extensions);
        }

        byte[] Sign(byte[] serial, string issuer, string subject, DateTime notBefore, DateTime notAfter, byte[] spki, byte[] extensions)
        {
            byte[] algorithm = Der.Sequence(Der.Oid(Ed25519Oid));
            byte[] tbs = Der.Sequence(
                Der.Tlv(0xA0, Der.Integer(new byte[] { 2 })),
                Der.Integer(serial),
                algorithm,
                Name(issuer),
                Der.Sequence(Der.Time(notBefore), Der.Time(notAfter)),
                Name(subject),
                spki,
                Der.Tlv(0xA3, extensions));
            return Der.Sequence(tbs, algorithm, Der.BitString(Ed25519.Sign(_seed, tbs)));
        }

        /// <summary>The DER of a subject that holds one common name, as these certificates carry it.</summary>
        public static byte[] Name(string commonName)
        {
            return Der.Sequence(Der.Set(Der.Sequence(Der.Oid(CommonNameOid), Der.Utf8(commonName))));
        }

        static byte[] Extension(string oid, bool critical, byte[] value)
        {
            byte[] wrapped = Der.OctetString(value);
            return critical ? Der.Sequence(Der.Oid(oid), Der.Boolean(true), wrapped) : Der.Sequence(Der.Oid(oid), wrapped);
        }

        static byte[] KeyId(byte[] publicKey)
        {
            IHash sha1 = Hashes.Sha1();
            sha1.Update(publicKey, 0, publicKey.Length);
            return sha1.Finish();
        }

        /// <summary>8 bytes from the name, with the top bit clear so the number stays positive. The same name gets the same serial, so a rerun gives the same bytes.</summary>
        static byte[] Serial(string name)
        {
            byte[] text = System.Text.Encoding.UTF8.GetBytes(name);
            IHash sha256 = Hashes.Sha256();
            sha256.Update(text, 0, text.Length);
            byte[] serial = new byte[8];
            Buffer.BlockCopy(sha256.Finish(), 0, serial, 0, 8);
            serial[0] = (byte)((serial[0] & 0x7F) | 0x40);
            return serial;
        }
    }
}
