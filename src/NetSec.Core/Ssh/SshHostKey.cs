using System;
using System.Text;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Pki;

namespace NetSec.Ssh
{
    /// <summary>A host key as it came from the wire. Every value here is the peer's word until the checks pass.</summary>
    public sealed class SshHostKey
    {
        const int Ed25519Size = 32;

        public readonly string Algorithm;
        public readonly byte[] Blob;
        readonly byte[] _ed25519;
        readonly RsaPublic _rsa;

        SshHostKey(string algorithm, byte[] blob, byte[] ed25519, RsaPublic rsa)
        {
            Algorithm = algorithm; Blob = blob; _ed25519 = ed25519; _rsa = rsa;
        }

        /// <summary>
        /// A bad blob throws ParseFailure SSH_HOST_KEY_BAD. An even modulus gets its name here, because BigUInt.ModPow would throw a plain
        /// ArgumentException for it. No RSA modulus is even, so an even one is no RSA key at all.
        /// </summary>
        public static SshHostKey Parse(byte[] blob)
        {
            ByteReader r = new ByteReader(blob, 0, blob.Length, true);
            try
            {
                string algorithm = SshFields.Text(r.Prefixed("type", "id"));
                if (algorithm == OpenSshKeyFile.Ed25519Name) return ParseEd25519(blob, r);
                if (algorithm == OpenSshKeyFile.RsaName) return ParseRsa(blob, r);
                throw new ParseFailure(SshCodes.HostKeyBad, "the host key type '" + algorithm + "' is not one this lab reads");
            }
            catch (ParseFailure failure)
            {
                if (failure.Code == SshCodes.HostKeyBad) throw;
                throw new ParseFailure(SshCodes.HostKeyBad, "the host key blob is cut short: " + failure.Message);
            }
        }

        static SshHostKey ParseEd25519(byte[] blob, ByteReader r)
        {
            byte[] publicKey = r.Prefixed("key", "key");
            if (publicKey.Length != Ed25519Size) throw new ParseFailure(SshCodes.HostKeyBad, "an Ed25519 host key holds " + publicKey.Length + " bytes, not 32");
            return new SshHostKey(OpenSshKeyFile.Ed25519Name, blob, publicKey, null);
        }

        static SshHostKey ParseRsa(byte[] blob, ByteReader r)
        {
            BigUInt e = BigUInt.FromBytes(r.Prefixed("e", "key"));
            BigUInt n = BigUInt.FromBytes(r.Prefixed("n", "key"));
            if (!n.IsOdd) throw new ParseFailure(SshCodes.HostKeyBad, "the RSA modulus is even, so this is no RSA key");
            if (!e.IsOdd) throw new ParseFailure(SshCodes.HostKeyBad, "the RSA exponent is even, so this is no RSA key");
            return new SshHostKey(OpenSshKeyFile.RsaName, blob, null, new RsaPublic(n, e));
        }

        /// <summary>
        /// True when the signature blob signs this message under this key. Bad input gives false. A modulus too short to hold the
        /// digest makes Pkcs1 throw RSA_MESSAGE_TOO_LONG, and that is one more bad signature.
        /// </summary>
        public bool Verify(byte[] message, byte[] signatureBlob)
        {
            ByteReader r = new ByteReader(signatureBlob, 0, signatureBlob.Length, true);
            string algorithm;
            byte[] signature;
            try
            {
                algorithm = SshFields.Text(r.Prefixed("type", "id"));
                signature = r.Prefixed("signature", "mac");
            }
            catch (ParseFailure) { return false; }
            if (algorithm != Algorithm) return false;
            if (_ed25519 != null) return Ed25519.Verify(_ed25519, message, signature);
            try { return Pkcs1.VerifySha1(_rsa, message, signature); }
            catch (NetSecException refused)
            {
                if (refused.Error.Code == ErrorCodes.RsaMessageTooLong) return false;
                throw;
            }
        }

        /// <summary>The OpenSSH form: SHA256, a colon, then base64 of the digest with its padding removed.</summary>
        public string Fingerprint()
        {
            IHash hash = Hashes.Sha256();
            hash.Update(Blob, 0, Blob.Length);
            return "SHA256:" + Convert.ToBase64String(hash.Finish()).TrimEnd('=');
        }
    }

    /// <summary>The private half of a host key. Each round holds one, chosen by suite.</summary>
    public sealed class SshHostSigner
    {
        readonly byte[] _seed;
        readonly RsaPrivate _rsa;
        public readonly string Algorithm;
        public readonly byte[] Blob;

        public SshHostSigner(ITrainingKey key)
        {
            if (key == null) throw new ArgumentNullException("key");
            if (key.Algorithm == KeyAlgorithm.Ed25519)
            {
                _seed = key.CopyMaterial();
                Algorithm = OpenSshKeyFile.Ed25519Name;
                Blob = OpenSshKeyFile.Ed25519Blob(key.CopyPublic());
                return;
            }
            RsaPkcs8 parts = RsaPkcs8.Parse(key.CopyMaterial());
            _rsa = new RsaPrivate(BigUInt.FromBytes(parts.N), BigUInt.FromBytes(parts.D));
            Algorithm = OpenSshKeyFile.RsaName;
            Blob = OpenSshKeyFile.RsaBlob(parts.N, parts.E);
        }

        public byte[] Sign(byte[] message)
        {
            byte[] signature = _seed != null ? Ed25519.Sign(_seed, message) : Pkcs1.SignSha1(_rsa, message);
            return new ByteWriter().Prefixed(Algorithm).Prefixed(signature).ToArray();
        }
    }

    public enum HostKeyMatch { Match, Changed, Unknown }

    /// <summary>
    /// Reads known_hosts text (the sshd(8) form: host, type, base64 key). It reads plain host names only. A hashed line is a line for no host.
    /// The rule: a line for this host with this key matches. A line for this host with any other key means the key changed.
    /// </summary>
    public static class SshKnownHosts
    {
        const int DefaultPort = 22;

        public static HostKeyMatch Check(string text, string host, int port, byte[] blob)
        {
            if (string.IsNullOrEmpty(text)) return HostKeyMatch.Unknown;
            string want = port == DefaultPort ? host : "[" + host + "]:" + port;
            string expected = Convert.ToBase64String(blob);
            bool sawHost = false;
            string[] lines = text.Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                string[] parts = lines[i].Trim().Split(' ');
                if (parts.Length < 3 || parts[0].StartsWith("#") || !NamesHost(parts[0], want)) continue;
                sawHost = true;
                if (parts[2] == expected) return HostKeyMatch.Match;
            }
            return sawHost ? HostKeyMatch.Changed : HostKeyMatch.Unknown;
        }

        static bool NamesHost(string patterns, string want)
        {
            string[] names = patterns.Split(',');
            for (int i = 0; i < names.Length; i++)
                if (names[i] == want) return true;
            return false;
        }

        public static string Line(string host, int port, string typeName, byte[] blob)
        {
            string name = port == DefaultPort ? host : "[" + host + "]:" + port;
            return name + " " + typeName + " " + Convert.ToBase64String(blob) + "\n";
        }
    }
}
