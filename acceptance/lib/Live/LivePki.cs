using System;
using System.IO;
using System.Text;
using NetSec.Keys;
using NetSec.Pki;

namespace Acceptance
{
    /// <summary>
    /// Server keys and certificates for the live clauses. The keys come from OpenSSL. The certificates come from the product's
    /// TrainingCa, which signs with the training CA key. OpenSSL then checks each certificate with `openssl verify`, which is
    /// the independent anchor for the product's certificate code (clause A5.pki.leaf-verifies-under-openssl).
    /// </summary>
    public static class LivePki
    {
        public static string Pem(string label, byte[] der)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("-----BEGIN ").Append(label).Append("-----\n");
            string b64 = Convert.ToBase64String(der);
            for (int i = 0; i < b64.Length; i += 64) sb.Append(b64, i, Math.Min(64, b64.Length - i)).Append('\n');
            sb.Append("-----END ").Append(label).Append("-----\n");
            return sb.ToString();
        }

        public static string Dir(Ctx c, string name)
        {
            string d = Path.Combine(c.WorkDir, name);
            Directory.CreateDirectory(d);
            return d;
        }

        public static string Run(string exe, string args, string workDir, string what)
        {
            string output;
            int code = Proc.Run(exe, args, workDir, 60000, out output);
            if (code != 0) throw new FailException(what + " exited " + code + ": " + output);
            return output;
        }

        /// <summary>The training CA root as PEM. Written to dir/root.pem.</summary>
        public static string WriteRoot(string dir, TrainingCa ca)
        {
            string path = Path.Combine(dir, "root.pem");
            File.WriteAllText(path, Pem("CERTIFICATE", ca.RootCertificateDer));
            return path;
        }

        /// <summary>Makes an Ed25519 server key with OpenSSL and a certificate for it from the training CA. Returns the cert and key paths.</summary>
        public static void Ed25519Server(Ctx c, string dir, TrainingCa ca, string dnsName, DateTime notBefore, DateTime notAfter, out string certPath, out string keyPath)
        {
            string openssl = Referees.OpenSsl(c);
            keyPath = Path.Combine(dir, "srv-ed25519.key");
            Run(openssl, "genpkey -algorithm ed25519 -out \"" + keyPath + "\"", dir, "openssl genpkey ed25519");
            certPath = IssueFor(openssl, dir, ca, keyPath, "srv-ed25519", dnsName, notBefore, notAfter);
        }

        public static void RsaServer(Ctx c, string dir, TrainingCa ca, string dnsName, DateTime notBefore, DateTime notAfter, out string certPath, out string keyPath)
        {
            string openssl = Referees.OpenSsl(c);
            keyPath = Path.Combine(dir, "srv-rsa.key");
            Run(openssl, "genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out \"" + keyPath + "\"", dir, "openssl genpkey rsa");
            certPath = IssueFor(openssl, dir, ca, keyPath, "srv-rsa", dnsName, notBefore, notAfter);
        }

        static string IssueFor(string openssl, string dir, TrainingCa ca, string keyPath, string stem, string dnsName, DateTime nb, DateTime na)
        {
            string spkiPath = Path.Combine(dir, stem + ".spki");
            Run(openssl, "pkey -in \"" + keyPath + "\" -pubout -outform DER -out \"" + spkiPath + "\"", dir, "openssl pkey -pubout");
            byte[] cert = ca.IssueServerCertificate(dnsName, File.ReadAllBytes(spkiPath), nb, na);
            string certPath = Path.Combine(dir, stem + ".pem");
            File.WriteAllText(certPath, Pem("CERTIFICATE", cert));
            return certPath;
        }

        /// <summary>`openssl verify` of a certificate against the root. Returns true when OpenSSL accepts the chain.</summary>
        public static bool OpenSslVerifies(Ctx c, string dir, string rootPem, string certPem, string dnsName, out string output)
        {
            string openssl = Referees.OpenSsl(c);
            int code = Proc.Run(openssl, "verify -CAfile \"" + rootPem + "\" -verify_hostname " + dnsName + " \"" + certPem + "\"", dir, 60000, out output);
            return code == 0 && output.Contains("OK");
        }

        /// <summary>A self-signed certificate that the training CA never signed. For the untrusted-chain attack.</summary>
        public static void SelfSignedServer(Ctx c, string dir, string dnsName, out string certPath, out string keyPath)
        {
            string openssl = Referees.OpenSsl(c);
            keyPath = Path.Combine(dir, "rogue.key");
            certPath = Path.Combine(dir, "rogue.pem");
            Run(openssl, "genpkey -algorithm ed25519 -out \"" + keyPath + "\"", dir, "openssl genpkey rogue");
            Run(openssl, "req -new -x509 -key \"" + keyPath + "\" -subj \"/CN=" + dnsName + "\" -days 2 -addext \"subjectAltName=DNS:" + dnsName + "\" -out \"" + certPath + "\"", dir, "openssl req rogue");
        }

        /// <summary>Training key bytes from the product's key source. Ed25519 material is the 32-byte seed; RSA material is PKCS#8 DER.</summary>
        public static byte[] TrainingMaterial(string keyId)
        {
            ITrainingKey k = new TrainingKeySource().Find(keyId);
            return k.CopyMaterial();
        }

        public static string Pkcs8Ed25519Pem(byte[] seed)
        {
            if (seed.Length != 32) throw new FailException("ITrainingKey.CopyMaterial for an Ed25519 key must be the 32-byte seed, got " + seed.Length + " bytes");
            byte[] prefix = Hex.Decode("302e020100300506032b657004220420");
            return Pem("PRIVATE KEY", Hex.Concat(prefix, seed));
        }
    }
}
