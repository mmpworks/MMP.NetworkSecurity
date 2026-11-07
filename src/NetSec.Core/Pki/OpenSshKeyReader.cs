using System;
using System.Text;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;

namespace NetSec.Pki
{
    /// <summary>
    /// Reads an unencrypted OpenSSH private key file, the form ssh-keygen writes (PROTOCOL.key in the OpenSSH source). The file comes from a learner,
    /// so every length is checked against the bytes left before it is used, each refusal names its fault, and the decoded bytes are cleared on every
    /// path. A key the engines cannot use is refused here, so no part of a bad file reaches a lab.
    /// </summary>
    public static class OpenSshKeyReader
    {
        public const string Ed25519Type = "ssh-ed25519", RsaType = "ssh-rsa";
        const string Begin = "-----BEGIN OPENSSH PRIVATE KEY-----", End = "-----END OPENSSH PRIVATE KEY-----";
        const string Magic = "openssh-key-v1", NoCipher = "none";
        const int BlockSize = 8, Ed25519Bytes = 32, RsaModulusBytes = 256, LargestExponentBytes = 4;
        const string RsaOid = "2a864886f70d010101";

        /// <summary>Reads the one key in text. expectedType is the key type the file's role takes, such as ssh-ed25519 for host.key.</summary>
        public static ITrainingKey Parse(string text, string keyId, string expectedType)
        {
            if (text == null) throw new ArgumentNullException("text");
            byte[] file = Decode(text);
            try { return ParseFile(file, keyId, expectedType); }
            finally { Array.Clear(file, 0, file.Length); }
        }

        /// <summary>Reads the key file at path. A file larger than any key file is refused before it is read.</summary>
        public static ITrainingKey Read(string path, string keyId, string expectedType)
        {
            byte[] raw = ReadAll(path);
            try { return Parse(Encoding.UTF8.GetString(raw, 0, raw.Length), keyId, expectedType); }
            finally { Array.Clear(raw, 0, raw.Length); }
        }

        /// <summary>The text of a small file, such as user.pub or known_hosts, with the same size limit and the same refusal names.</summary>
        public static string ReadText(string path)
        {
            byte[] raw = ReadAll(path);
            return Encoding.UTF8.GetString(raw, 0, raw.Length);
        }

        static byte[] ReadAll(string path)
        {
            const int LargestKeyFile = 64 * 1024;
            try
            {
                using (System.IO.FileStream file = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read))
                {
                    if (file.Length > LargestKeyFile) throw Refuse(ErrorCodes.KeyFileFormat, "This file is too large to be a key file.");
                    byte[] all = new byte[(int)file.Length];
                    int got = 0;
                    while (got < all.Length)
                    {
                        int n = file.Read(all, got, all.Length - got);
                        if (n == 0) throw Refuse(ErrorCodes.KeyFileUnreadable, path + " ended while it was read.");
                        got += n;
                    }
                    return all;
                }
            }
            catch (System.IO.IOException e) { throw Refuse(ErrorCodes.KeyFileUnreadable, path + " cannot be read: " + e.Message); }
            catch (UnauthorizedAccessException e) { throw Refuse(ErrorCodes.KeyFileUnreadable, path + " cannot be read: " + e.Message); }
        }

        /// <summary>The public key of an OpenSSH public key line, such as user.pub: the type, then the base64 blob, then a comment.</summary>
        public static byte[] PublicBlobOfLine(string line)
        {
            // The CE framework has no StringSplitOptions, so empty pieces are dropped here.
            System.Collections.Generic.List<string> parts = new System.Collections.Generic.List<string>();
            foreach (string piece in (line ?? "").Trim().Split(new char[] { ' ', '\t' }))
                if (piece.Length > 0) parts.Add(piece);
            if (parts.Count < 2) throw Refuse(ErrorCodes.KeyFileFormat, "A public key line holds a key type and a base64 key.");
            try { return Convert.FromBase64String(parts[1]); }
            catch (FormatException) { throw Refuse(ErrorCodes.KeyFileFormat, "The key in this public key line is not base64."); }
        }

        static byte[] Decode(string text)
        {
            if (text.IndexOf("ENCRYPTED", StringComparison.Ordinal) >= 0) throw Encrypted();
            int start = text.IndexOf(Begin, StringComparison.Ordinal), stop = text.IndexOf(End, StringComparison.Ordinal);
            if (start < 0 || stop < start) throw Refuse(ErrorCodes.KeyFileFormat, "This file is not an OpenSSH private key.");
            string body = text.Substring(start + Begin.Length, stop - start - Begin.Length).Replace("\r", "").Replace("\n", "").Trim();
            try { return Convert.FromBase64String(body); }
            catch (FormatException) { throw Refuse(ErrorCodes.KeyFileFormat, "The body of this OpenSSH key is not base64."); }
        }

        static ITrainingKey ParseFile(byte[] file, string keyId, string expectedType)
        {
            Cursor outer = new Cursor(file, 0, file.Length);
            byte[] magic = Encoding.ASCII.GetBytes(Magic);
            if (file.Length < magic.Length + 1 || !Same(file, 0, magic) || file[magic.Length] != 0)
                throw Refuse(ErrorCodes.KeyFileFormat, "This file does not start with the OpenSSH key marker.");
            outer.Skip(magic.Length + 1);
            string cipher = outer.Text("cipher name"), kdf = outer.Text("key derivation name");
            byte[] kdfOptions = outer.Bytes("key derivation options");
            if (cipher != NoCipher || kdf != NoCipher || kdfOptions.Length != 0) throw Encrypted();
            if (outer.U32("key count") != 1) throw Refuse(ErrorCodes.KeyFileFormat, "This file holds more than one key, or none. A key file holds one.");
            byte[] publicBlob = outer.Bytes("public key");
            byte[] privateSection = outer.Bytes("private section");
            try
            {
                if (!outer.AtEnd) throw Refuse(ErrorCodes.KeyFileFormat, "This file has bytes after its private section.");
                return ParsePrivate(privateSection, publicBlob, keyId, expectedType);
            }
            finally { Array.Clear(privateSection, 0, privateSection.Length); }
        }

        static ITrainingKey ParsePrivate(byte[] section, byte[] publicBlob, string keyId, string expectedType)
        {
            if (section.Length % BlockSize != 0) throw Refuse(ErrorCodes.KeyFileFormat, "The private section is not a whole number of blocks.");
            Cursor c = new Cursor(section, 0, section.Length);
            if (c.U32("check value") != c.U32("check value")) throw Refuse(ErrorCodes.KeyFileFormat, "The 2 check values differ. The file is damaged, or it is encrypted.");
            string type = c.Text("key type");
            string publicType = new Cursor(publicBlob, 0, publicBlob.Length).Text("public key type");
            if (type != publicType) throw Refuse(ErrorCodes.KeyFileFormat, "The private key type " + Shown(type) + " differs from the public key type " + Shown(publicType) + ".");
            if (type != expectedType) throw Refuse(ErrorCodes.KeyAlgorithmNotInEngine, "This file holds " + Shown(type) + ", and this role takes " + expectedType + ".");
            ITrainingKey key = type == Ed25519Type ? ReadEd25519(c, publicBlob, keyId) : ReadRsa(c, publicBlob, keyId);
            c.Bytes("comment");
            for (int pad = 1; !c.AtEnd; pad++)
                if (c.U8("padding") != pad) throw Refuse(ErrorCodes.KeyFileFormat, "The padding after the key is not 1, 2, 3 and so on.");
            return key;
        }

        static ITrainingKey ReadEd25519(Cursor c, byte[] publicBlob, string keyId)
        {
            byte[] pub = c.Bytes("Ed25519 public key"), both = c.Bytes("Ed25519 private key");
            byte[] seed = new byte[Ed25519Bytes], der = null;
            try
            {
                if (pub.Length != Ed25519Bytes || both.Length != 2 * Ed25519Bytes)
                    throw Refuse(ErrorCodes.KeyFileFormat, "An Ed25519 key holds a 32-byte public key and a 64-byte private key.");
                Buffer.BlockCopy(both, 0, seed, 0, Ed25519Bytes);
                if (!Same(both, Ed25519Bytes, pub) || !Equal(Ed25519.PublicFrom(seed), pub) || !Equal(Ed25519Blob(pub), publicBlob))
                    throw Refuse(ErrorCodes.KeyFileFormat, "The Ed25519 private key does not give the public key the file names.");
                der = TrainingCa.Ed25519Pkcs8(seed);
                return KeyFileReader.Parse(TrainingPki.Pem("PRIVATE KEY", der), keyId);
            }
            finally
            {
                Array.Clear(both, 0, both.Length);
                Array.Clear(seed, 0, seed.Length);
                if (der != null) Array.Clear(der, 0, der.Length);
            }
        }

        static ITrainingKey ReadRsa(Cursor c, byte[] publicBlob, string keyId)
        {
            byte[] n = c.Mpint("n"), e = c.Mpint("e"), d = c.Mpint("d"), iqmp = c.Mpint("iqmp"), p = c.Mpint("p"), q = c.Mpint("q");
            byte[] der = null;
            try
            {
                if (n.Length != RsaModulusBytes) throw Refuse(ErrorCodes.KeySizeNot2048, "The lessons take an RSA key of 2048 bits. This one has " + (n.Length * 8) + ".");
                // A huge public exponent would make every verify slow. Real keys use 65537, which is 3 bytes.
                if (e.Length > LargestExponentBytes) throw Refuse(ErrorCodes.KeyFileFormat, "The RSA public exponent in this file is longer than " + LargestExponentBytes + " bytes.");
                BigUInt bn = BigUInt.FromBytes(n), bd = BigUInt.FromBytes(d), bp = BigUInt.FromBytes(p), bq = BigUInt.FromBytes(q);
                // p and q above 1 keep p - 1 and q - 1 nonzero for the 2 remainders below. A zero number has no DER form.
                if (bp.CompareTo(BigUInt.One) <= 0 || bq.CompareTo(BigUInt.One) <= 0 || bp.Multiply(bq).CompareTo(bn) != 0
                    || bd.IsZero || bd.CompareTo(bn) >= 0 || BigUInt.FromBytes(e).IsZero)
                    throw Refuse(ErrorCodes.KeyFileFormat, "The RSA numbers in this file do not form one key.");
                // q x iqmp mod p = 1 is what iqmp means. A wrong one would make bad signatures later, so it is refused here.
                if (BigUInt.FromBytes(iqmp).Multiply(bq).Mod(bp).CompareTo(BigUInt.One) != 0)
                    throw Refuse(ErrorCodes.KeyFileFormat, "The RSA number iqmp in this file is not the inverse of q mod p.");
                // One block through the key: (m^e)^d mod n must give m back. p x q = n holds for a wrong d, and this does not.
                BigUInt m = BigUInt.FromUInt32(2);
                if (m.ModPow(BigUInt.FromBytes(e), bn).ModPow(bd, bn).CompareTo(m) != 0)
                    throw Refuse(ErrorCodes.KeyFileFormat, "The RSA exponents in this file do not undo each other, so d does not match e.");
                Cursor blob = new Cursor(publicBlob, 0, publicBlob.Length);
                blob.Text("public key type");
                if (!Equal(blob.Mpint("public e"), e) || !Equal(blob.Mpint("public n"), n) || !blob.AtEnd)
                    throw Refuse(ErrorCodes.KeyFileFormat, "The RSA private key does not give the public key the file names.");
                byte[] dp = bd.Mod(bp.Subtract(BigUInt.One)).ToBigEndian(), dq = bd.Mod(bq.Subtract(BigUInt.One)).ToBigEndian();
                byte[] rsa = Der.Sequence(Der.Integer(new byte[] { 0 }), Der.Integer(n), Der.Integer(e), Der.Integer(d), Der.Integer(p), Der.Integer(q),
                    Der.Integer(NonEmpty(dp)), Der.Integer(NonEmpty(dq)), Der.Integer(iqmp));
                der = Der.Sequence(Der.Integer(new byte[] { 0 }), Der.Sequence(Der.Oid(RsaOid), Der.Tlv(5, new byte[0])), Der.OctetString(rsa));
                Array.Clear(rsa, 0, rsa.Length);
                return KeyFileReader.Parse(TrainingPki.Pem("PRIVATE KEY", der), keyId);
            }
            finally
            {
                Array.Clear(d, 0, d.Length);
                Array.Clear(p, 0, p.Length);
                Array.Clear(q, 0, q.Length);
                Array.Clear(iqmp, 0, iqmp.Length);
                if (der != null) Array.Clear(der, 0, der.Length);
            }
        }

        static byte[] NonEmpty(byte[] value) { return value.Length == 0 ? new byte[] { 0 } : value; }

        public static byte[] Ed25519BlobOf(byte[] pub) { return Ed25519Blob(pub); }

        static byte[] Ed25519Blob(byte[] pub)
        {
            byte[] type = Encoding.ASCII.GetBytes(Ed25519Type);
            byte[] blob = new byte[4 + type.Length + 4 + pub.Length];
            PutU32(blob, 0, type.Length);
            Buffer.BlockCopy(type, 0, blob, 4, type.Length);
            PutU32(blob, 4 + type.Length, pub.Length);
            Buffer.BlockCopy(pub, 0, blob, 8 + type.Length, pub.Length);
            return blob;
        }

        static void PutU32(byte[] b, int at, int v)
        {
            b[at] = (byte)(v >> 24); b[at + 1] = (byte)(v >> 16); b[at + 2] = (byte)(v >> 8); b[at + 3] = (byte)v;
        }

        static bool Same(byte[] b, int at, byte[] want)
        {
            if (b.Length - at < want.Length) return false;
            for (int i = 0; i < want.Length; i++) if (b[at + i] != want[i]) return false;
            return true;
        }

        static bool Equal(byte[] a, byte[] b) { return a.Length == b.Length && Same(a, 0, b); }

        /// <summary>A key type from the file, quoted, when it is short and printable ASCII. Else "an unknown type": the file chose those bytes.</summary>
        static string Shown(string type)
        {
            const int Longest = 32;
            if (type.Length == 0 || type.Length > Longest) return "an unknown type";
            foreach (char ch in type) if (ch < 0x21 || ch > 0x7E) return "an unknown type";
            return "an " + type + " key";
        }

        static NetSecException Encrypted() { return Refuse(ErrorCodes.KeyFileEncrypted, "This key has a passphrase. A test key needs none."); }

        static NetSecException Refuse(string code, string message) { return new NetSecException(NetSecError.Of(code, message)); }

        /// <summary>Reads big-endian fields from a byte range. Each length is checked against the bytes left, so a damaged file cannot read past its end.</summary>
        sealed class Cursor
        {
            readonly byte[] _b;
            readonly int _end;
            int _at;

            public Cursor(byte[] b, int at, int end) { _b = b; _at = at; _end = end; }

            public bool AtEnd { get { return _at == _end; } }

            public void Skip(int count) { Need(count, "marker"); _at += count; }

            public int U8(string field)
            {
                Need(1, field);
                return _b[_at++];
            }

            public long U32(string field)
            {
                Need(4, field);
                long v = ((long)_b[_at] << 24) | ((long)_b[_at + 1] << 16) | ((long)_b[_at + 2] << 8) | _b[_at + 3];
                _at += 4;
                return v;
            }

            public byte[] Bytes(string field)
            {
                long length = U32(field + " length");
                if (length > _end - _at) throw Refuse(ErrorCodes.KeyFileFormat, "The " + field + " is longer than the bytes left in the file. The file is cut or damaged.");
                byte[] value = new byte[(int)length];
                Buffer.BlockCopy(_b, _at, value, 0, value.Length);
                _at += value.Length;
                return value;
            }

            public string Text(string field)
            {
                byte[] value = Bytes(field);
                return Encoding.ASCII.GetString(value, 0, value.Length);
            }

            /// <summary>An SSH mpint (RFC 4251 section 5). A key's numbers are positive, so a sign bit set is a fault. The leading zero byte is dropped.</summary>
            public byte[] Mpint(string field)
            {
                byte[] raw = Bytes(field);
                if (raw.Length > 0 && (raw[0] & 0x80) != 0) throw Refuse(ErrorCodes.KeyFileFormat, "The RSA number " + field + " is negative.");
                int at = 0;
                while (at < raw.Length && raw[at] == 0) at++;
                byte[] value = new byte[raw.Length - at];
                Buffer.BlockCopy(raw, at, value, 0, value.Length);
                Array.Clear(raw, 0, raw.Length);
                return value;
            }

            void Need(int count, string field)
            {
                if (_end - _at < count) throw Refuse(ErrorCodes.KeyFileFormat, "The file ends inside the " + field + ". The file is cut or damaged.");
            }
        }
    }
}
