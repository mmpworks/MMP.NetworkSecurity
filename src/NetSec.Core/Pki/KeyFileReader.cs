using System;
using System.IO;
using System.Text;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;

namespace NetSec.Pki
{
    /// <summary>Reads a learner's test key from a file as an ITrainingKey. It takes a PEM PKCS#8 key: Ed25519, or RSA of 2048 bits. A refusal has a code from ErrorCodes.</summary>
    public static class KeyFileReader
    {
        const string RsaOid = "2a864886f70d010101", Ed25519Oid = "2b6570";
        const int RsaModulusBytes = 256;
        const int NullTag = 5;

        public static ITrainingKey ReadPrivateKey(string path, string keyId)
        {
            byte[] raw;
            try { raw = ReadAll(path); }
            catch (IOException e) { throw Refuse(ErrorCodes.KeyFileUnreadable, path + " cannot be read: " + e.Message); }
            catch (UnauthorizedAccessException e) { throw Refuse(ErrorCodes.KeyFileUnreadable, path + " cannot be read: " + e.Message); }
            return Parse(Encoding.UTF8.GetString(raw, 0, raw.Length), keyId);
        }

        public static ITrainingKey Parse(string pem, string keyId)
        {
            if (pem.IndexOf("ENCRYPTED") >= 0) throw Refuse(ErrorCodes.KeyFileEncrypted, "This key has a passphrase. A test key needs none.");
            byte[] der = DerOf(pem);
            try { return FromPkcs8(der, keyId); }
            catch (ParseFailure e) { throw Refuse(ErrorCodes.KeyFileFormat, "This file is not a PKCS#8 private key: " + e.Message); }
        }

        /// <summary>The SubjectPublicKeyInfo of an RSA key, from the numbers in its PKCS#8 form.</summary>
        public static byte[] RsaSpki(byte[] pkcs8)
        {
            RsaPkcs8 parts = RsaPkcs8.Parse(pkcs8);
            byte[] rsaPublic = Der.Sequence(Der.Integer(Unsigned(parts.N)), Der.Integer(Unsigned(parts.E)));
            return Der.Sequence(Der.Sequence(Der.Oid(RsaOid), Der.Tlv(NullTag, new byte[0])), Der.BitString(rsaPublic));
        }

        static ITrainingKey FromPkcs8(byte[] der, string keyId)
        {
            DerReader info = new DerReader(der, 0, der.Length).Read(Der.TagSequence).Inner;
            info.Read(Der.TagInteger);
            DerReader algorithm = info.Read(Der.TagSequence).Inner;
            string oid = Hex.Encode(algorithm.Read(Der.TagOid).Value);
            byte[] inner = info.Read(Der.TagOctetString).Value;
            if (oid == Ed25519Oid)
            {
                byte[] seed = new DerReader(inner, 0, inner.Length).Read(Der.TagOctetString).Value;
                if (seed.Length != 32) throw Refuse(ErrorCodes.KeyFileFormat, "An Ed25519 key holds 32 bytes, and this one holds " + seed.Length + ".");
                return new LoadedKey(keyId, KeyAlgorithm.Ed25519, seed, Ed25519.PublicFrom(seed));
            }
            if (oid == RsaOid)
            {
                if (Unsigned(RsaPkcs8.Parse(der).N).Length != RsaModulusBytes) throw Refuse(ErrorCodes.KeySizeNot2048, "The lessons take an RSA key of 2048 bits.");
                return new LoadedKey(keyId, KeyAlgorithm.Rsa2048, der, RsaSpki(der));
            }
            throw Refuse(ErrorCodes.KeyAlgorithmNotInEngine, "The engines take Ed25519 or RSA 2048. This key is neither.");
        }

        static byte[] DerOf(string pem)
        {
            const string Begin = "-----BEGIN PRIVATE KEY-----", End = "-----END PRIVATE KEY-----";
            int start = pem.IndexOf(Begin), stop = pem.IndexOf(End);
            if (start < 0 || stop < start) throw Refuse(ErrorCodes.KeyFileFormat, "This file is not a PEM private key in PKCS#8 form.");
            string body = pem.Substring(start + Begin.Length, stop - start - Begin.Length);
            try { return Convert.FromBase64String(body.Replace("\r", "").Replace("\n", "").Trim()); }
            catch (FormatException) { throw Refuse(ErrorCodes.KeyFileFormat, "The body of this PEM file is not base64."); }
        }

        static byte[] Unsigned(byte[] value)
        {
            int at = 0;
            while (at < value.Length - 1 && value[at] == 0) at++;
            byte[] trimmed = new byte[value.Length - at];
            Buffer.BlockCopy(value, at, trimmed, 0, trimmed.Length);
            return trimmed;
        }

        static byte[] ReadAll(string path)
        {
            using (FileStream file = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                byte[] all = new byte[(int)file.Length];
                int got = 0;
                while (got < all.Length)
                {
                    int n = file.Read(all, got, all.Length - got);
                    if (n == 0) break;
                    got += n;
                }
                return all;
            }
        }

        static NetSecException Refuse(string code, string message) { return new NetSecException(NetSecError.Of(code, message)); }

        sealed class LoadedKey : ITrainingKey
        {
            readonly string _keyId;
            readonly KeyAlgorithm _algorithm;
            readonly byte[] _material, _public;

            public LoadedKey(string keyId, KeyAlgorithm algorithm, byte[] material, byte[] publicPart)
            {
                _keyId = keyId;
                _algorithm = algorithm;
                _material = material;
                _public = publicPart;
            }

            public string KeyId { get { return _keyId; } }
            public KeyAlgorithm Algorithm { get { return _algorithm; } }
            public byte[] CopyMaterial() { return (byte[])_material.Clone(); }
            public byte[] CopyPublic() { return (byte[])_public.Clone(); }
        }
    }
}
