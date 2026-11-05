using System;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// Helpers for the live clauses. The product writes its keys and certificates with TrainingPki.Export (see PkiDir).
    /// OpenSSL checks each certificate with `openssl verify`, which is the independent anchor for the product's certificate code
    /// (clause A5.pki.leaf-verifies-under-openssl). The self-signed rogue certificate is made with OpenSSL alone.
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
    }
}
