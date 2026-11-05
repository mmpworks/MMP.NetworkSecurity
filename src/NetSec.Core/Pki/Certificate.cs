using System;
using System.Collections.Generic;
using System.Text;
using NetSec.Bytes;
using NetSec.Crypto;

namespace NetSec.Pki
{
    /// <summary>The fields of an X.509 certificate that this course checks. Immutable after Parse.</summary>
    public sealed class Certificate
    {
        const string Ed25519Oid = "2b6570";
        const string SanOid = "551d11";
        const string BasicConstraintsOid = "551d13";
        const string ExtendedKeyUsageOid = "551d25";
        const string ClientAuthOid = "2b06010505070302";
        const int DnsNameTag = 0x82;
        const int ExplicitVersionTag = 0xA0;
        const int ExplicitExtensionsTag = 0xA3;

        public byte[] Der { get; private set; }
        public byte[] Tbs { get; private set; }
        public byte[] Issuer { get; private set; }
        public byte[] Subject { get; private set; }
        public byte[] PublicKey { get; private set; }
        public byte[] Signature { get; private set; }
        public DateTime NotBefore { get; private set; }
        public DateTime NotAfter { get; private set; }
        public bool KeyIsEd25519 { get; private set; }
        public bool SignedWithEd25519 { get; private set; }
        public bool IsCa { get; private set; }
        public bool AllowsClientAuth { get; private set; }
        public string[] DnsNames { get; private set; }

        readonly List<FieldMark> _marks = new List<FieldMark>();

        Certificate() { }

        public static Certificate Parse(byte[] der)
        {
            if (der == null) throw new ArgumentNullException("der");
            Certificate c = new Certificate();
            c.Der = (byte[])der.Clone();
            DerReader outer = new DerReader(der, 0, der.Length).Read(NetSec.Pki.Der.TagSequence).Inner;
            DerItem tbs = outer.Read(NetSec.Pki.Der.TagSequence);
            DerItem algorithm = outer.Read(NetSec.Pki.Der.TagSequence);
            DerItem signature = outer.Read(NetSec.Pki.Der.TagBitString);
            c.Tbs = tbs.Whole;
            c.SignedWithEd25519 = HasOid(algorithm, Ed25519Oid);
            c.Signature = AfterUnusedBits(signature);
            c.ReadTbs(tbs.Inner);
            c.Mark("cert.signature", signature, "mac");
            return c;
        }

        void ReadTbs(DerReader tbs)
        {
            if (tbs.PeekTag == ExplicitVersionTag) tbs.Read();
            Mark("cert.serial", tbs.Read(NetSec.Pki.Der.TagInteger), "id");
            tbs.Read(NetSec.Pki.Der.TagSequence);
            DerItem issuer = tbs.Read(NetSec.Pki.Der.TagSequence);
            Issuer = issuer.Whole;
            Mark("cert.issuer", issuer, "id");
            ReadValidity(tbs.Read(NetSec.Pki.Der.TagSequence));
            DerItem subject = tbs.Read(NetSec.Pki.Der.TagSequence);
            Subject = subject.Whole;
            Mark("cert.subject", subject, "id");
            ReadPublicKey(tbs.Read(NetSec.Pki.Der.TagSequence));
            DnsNames = new string[0];
            while (tbs.HasMore)
            {
                DerItem item = tbs.Read();
                if (item.Tag == ExplicitExtensionsTag) ReadExtensions(item.Inner.Read(NetSec.Pki.Der.TagSequence).Inner);
            }
        }

        void ReadValidity(DerItem validity)
        {
            DerReader r = validity.Inner;
            DerItem before = r.Read();
            DerItem after = r.Read();
            NotBefore = ParseTime(before);
            NotAfter = ParseTime(after);
            Mark("cert.not_before", before, "data");
            Mark("cert.not_after", after, "data");
        }

        void ReadPublicKey(DerItem spki)
        {
            DerReader r = spki.Inner;
            KeyIsEd25519 = HasOid(r.Read(NetSec.Pki.Der.TagSequence), Ed25519Oid);
            DerItem key = r.Read(NetSec.Pki.Der.TagBitString);
            PublicKey = AfterUnusedBits(key);
            Mark("cert.public_key", key, "key");
        }

        void ReadExtensions(DerReader extensions)
        {
            while (extensions.HasMore)
            {
                DerReader extension = extensions.Read(NetSec.Pki.Der.TagSequence).Inner;
                string oid = Hex.Encode(extension.Read(NetSec.Pki.Der.TagOid).Value);
                if (extension.PeekTag == NetSec.Pki.Der.TagBoolean) extension.Read();
                DerItem value = extension.Read(NetSec.Pki.Der.TagOctetString);
                if (oid == SanOid) ReadNames(value);
                else if (oid == BasicConstraintsOid) ReadBasicConstraints(value);
                else if (oid == ExtendedKeyUsageOid) ReadKeyUsages(value);
            }
        }

        void ReadNames(DerItem value)
        {
            DerReader names = value.Inner.Read(NetSec.Pki.Der.TagSequence).Inner;
            List<string> found = new List<string>();
            while (names.HasMore)
            {
                DerItem name = names.Read();
                if (name.Tag == DnsNameTag) found.Add(Encoding.UTF8.GetString(name.Value, 0, name.ValueLength));
            }
            DnsNames = found.ToArray();
            Mark("cert.subject_alt_name", value, "id");
        }

        void ReadKeyUsages(DerItem value)
        {
            DerReader usages = value.Inner.Read(NetSec.Pki.Der.TagSequence).Inner;
            while (usages.HasMore)
                if (Hex.Encode(usages.Read(NetSec.Pki.Der.TagOid).Value) == ClientAuthOid) AllowsClientAuth = true;
        }

        void ReadBasicConstraints(DerItem value)
        {
            DerReader constraints = value.Inner.Read(NetSec.Pki.Der.TagSequence).Inner;
            if (constraints.PeekTag != NetSec.Pki.Der.TagBoolean) return;
            byte[] flag = constraints.Read().Value;
            IsCa = flag.Length == 1 && flag[0] != 0;
        }

        /// <summary>The fields as FieldMarks, shifted to where this certificate sits inside a message.</summary>
        public FieldMark[] Marks(int offset, bool visible)
        {
            FieldMark[] shifted = new FieldMark[_marks.Count];
            for (int i = 0; i < shifted.Length; i++)
                shifted[i] = new FieldMark(_marks[i].Name, _marks[i].Offset + offset, _marks[i].Length, _marks[i].Kind, visible, _marks[i].Gloss);
            return shifted;
        }

        void Mark(string name, DerItem item, string kind)
        {
            _marks.Add(new FieldMark(name, item.Start, item.TotalLength, kind, true, name));
        }

        static bool HasOid(DerItem algorithm, string oidHex)
        {
            DerReader r = algorithm.Inner;
            return r.PeekTag == NetSec.Pki.Der.TagOid && Hex.Encode(r.Read().Value) == oidHex;
        }

        static byte[] AfterUnusedBits(DerItem bitString)
        {
            byte[] value = bitString.Value;
            if (value.Length < 1 || value[0] != 0) throw new NetSec.Bytes.ParseFailure(DerReader.ParseCode, "a bit string has unused bits");
            byte[] bytes = new byte[value.Length - 1];
            Buffer.BlockCopy(value, 1, bytes, 0, bytes.Length);
            return bytes;
        }

        static DateTime ParseTime(DerItem item)
        {
            string text = Encoding.UTF8.GetString(item.Value, 0, item.ValueLength);
            bool utc = item.Tag == NetSec.Pki.Der.TagUtcTime;
            if (!utc && item.Tag != NetSec.Pki.Der.TagGeneralizedTime) throw new ParseFailure(DerReader.ParseCode, "a validity date has the wrong tag");
            if (text.Length != (utc ? 13 : 15) || text[text.Length - 1] != 'Z') throw new ParseFailure(DerReader.ParseCode, "a validity date has the wrong shape");
            int at = utc ? 2 : 4;
            int year = utc ? TwoDigitYear(Number(text, 0, 2)) : Number(text, 0, 4);
            return new DateTime(year, Number(text, at, 2), Number(text, at + 2, 2), Number(text, at + 4, 2), Number(text, at + 6, 2), Number(text, at + 8, 2), DateTimeKind.Utc);
        }

        /// <summary>RFC 5280: a two-digit year from 50 means 19xx, below 50 means 20xx.</summary>
        static int TwoDigitYear(int yy) { return yy >= 50 ? 1900 + yy : 2000 + yy; }

        static int Number(string text, int off, int n)
        {
            int value = 0;
            for (int i = 0; i < n; i++)
            {
                char c = text[off + i];
                if (c < '0' || c > '9') throw new ParseFailure(DerReader.ParseCode, "a validity date holds a non-digit");
                value = value * 10 + (c - '0');
            }
            return value;
        }

        public bool VerifySignedBy(byte[] issuerPublicKey)
        {
            return SignedWithEd25519 && issuerPublicKey.Length == 32 && Signature.Length == 64 && Ed25519.Verify(issuerPublicKey, Tbs, Signature);
        }

        /// <summary>Compares the whole subject in bytes, so a second name part or another spelling of the name does not pass.</summary>
        public bool SubjectIs(string commonName)
        {
            byte[] expected = TrainingCa.Name(commonName);
            if (Subject.Length != expected.Length) return false;
            for (int i = 0; i < expected.Length; i++)
                if (Subject[i] != expected[i]) return false;
            return true;
        }

        public bool Matches(string dnsName)
        {
            for (int i = 0; i < DnsNames.Length; i++)
                if (string.Compare(DnsNames[i], dnsName, StringComparison.OrdinalIgnoreCase) == 0) return true;
            return false;
        }
    }

    /// <summary>A decision value. The caller turns a failure into a trace event.</summary>
    public sealed class ChainVerdict
    {
        public readonly string Code, Detail;
        public ChainVerdict(string code, string detail) { Code = code; Detail = detail; }
        public bool Passed { get { return Code == null; } }
        public static readonly ChainVerdict Ok = new ChainVerdict(null, null);
    }

    /// <summary>
    /// Walks from the leaf up to a trust anchor. It checks in the order a learner meets the attacks: can the chain reach an anchor at all,
    /// is each signature good, is each certificate in date, and does the leaf carry the name the client asked for.
    /// </summary>
    public static class ChainCheck
    {
        public const string NoAnchor = "CHAIN_NO_ANCHOR";
        public const string Validity = "CERT_VALIDITY";
        public const string Name = "CERT_NAME";
        public const string BadSignature = "CERT_SIGNATURE";
        public const string NotForClients = "CERT_NOT_FOR_CLIENTS";

        public static ChainVerdict Run(Certificate[] chain, Certificate[] anchors, string dnsName, DateTime now)
        {
            ChainVerdict trusted = Trusted(chain, anchors, now);
            if (!trusted.Passed) return trusted;
            if (!chain[0].Matches(dnsName)) return new ChainVerdict(Name, "the leaf does not carry the name " + dnsName);
            return ChainVerdict.Ok;
        }

        /// <summary>A server asks the same chain questions of a client, but no client has a name to match. The leaf must list client authentication. A leaf with no key usage list is refused, which is stricter than RFC 5280.</summary>
        public static ChainVerdict RunForClient(Certificate[] chain, Certificate[] anchors, DateTime now)
        {
            ChainVerdict trusted = Trusted(chain, anchors, now);
            if (!trusted.Passed) return trusted;
            if (!chain[0].AllowsClientAuth) return new ChainVerdict(NotForClients, "the leaf does not allow client authentication");
            return ChainVerdict.Ok;
        }

        static ChainVerdict Trusted(Certificate[] chain, Certificate[] anchors, DateTime now)
        {
            if (chain == null || chain.Length == 0) return new ChainVerdict(NoAnchor, "the peer sent no certificate");
            Certificate[] issuers = new Certificate[chain.Length];
            for (int i = 0; i < chain.Length; i++)
            {
                issuers[i] = i + 1 < chain.Length && SameName(chain[i].Issuer, chain[i + 1].Subject) ? chain[i + 1] : FindAnchor(chain[i], anchors);
                if (issuers[i] == null) return new ChainVerdict(NoAnchor, "no trusted certificate issued certificate " + i);
                if (!issuers[i].IsCa) return new ChainVerdict(NoAnchor, "the issuer of certificate " + i + " is not a CA");
            }
            for (int i = 0; i < chain.Length; i++)
                if (!chain[i].VerifySignedBy(issuers[i].PublicKey)) return new ChainVerdict(BadSignature, "the signature on certificate " + i + " does not verify");
            for (int i = 0; i < chain.Length; i++)
                if (now < chain[i].NotBefore || now > chain[i].NotAfter) return new ChainVerdict(Validity, "certificate " + i + " is outside its validity window");
            return ChainVerdict.Ok;
        }

        static Certificate FindAnchor(Certificate certificate, Certificate[] anchors)
        {
            for (int i = 0; i < anchors.Length; i++)
                if (SameName(certificate.Issuer, anchors[i].Subject)) return anchors[i];
            return null;
        }

        static bool SameName(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }
    }
}
