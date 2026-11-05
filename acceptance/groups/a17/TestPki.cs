using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// A small certificate chain made by OpenSSL, so the suite knows which chains are sound and which are not before the Host says anything.
    /// Names follow modes-design.md section 2.5: the root is "MMP.NetworkSecurity training root", the server "localhost", the client "pump-reader-4".
    /// </summary>
    public sealed class TestPki
    {
        public string Dir, RootPem, RootKey, ServerPem, ServerKey, ClientPem, ClientKey, Tls11Pem, Tls11Key;

        public sealed class Options
        {
            public string RootAlg = "ed25519";        // ed25519 or rsa
            public int Days = 30;
            public string NotBefore, NotAfter;         // YYMMDDHHMMSSZ, override Days for the leaves
            public bool Client = true;
        }

        static string Q(string path) { return "\"" + path + "\""; }

        static void Run(string openssl, string dir, string args)
        {
            string o;
            if (Proc.Run(openssl, args, dir, 60000, out o) != 0) throw new FailException("openssl " + args + " failed: " + o.Trim());
        }

        static void Key(string openssl, string dir, string alg, string file)
        {
            if (alg == "rsa") Run(openssl, dir, "genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out " + Q(file));
            else Run(openssl, dir, "genpkey -algorithm ed25519 -out " + Q(file));
        }

        public static TestPki Make(Ctx c, string name, Options opt)
        {
            string openssl = Referees.OpenSsl(c);
            TestPki p = new TestPki();
            p.Dir = A17.TempDir(c, "pki-" + name);
            string d = p.Dir;
            p.RootKey = Path.Combine(d, "root.key"); p.RootPem = Path.Combine(d, "root.pem");
            Key(openssl, d, opt.RootAlg, p.RootKey);
            string digest = opt.RootAlg == "rsa" ? " -sha256" : "";
            Run(openssl, d, "req -new -x509 -key " + Q(p.RootKey) + digest + " -subj \"/CN=MMP.NetworkSecurity training root\" -days " + Math.Max(opt.Days, 1) +
                " -addext \"basicConstraints=critical,CA:TRUE\" -addext \"keyUsage=critical,keyCertSign,cRLSign\" -out " + Q(p.RootPem));
            p.ServerKey = Path.Combine(d, "srv.key"); p.ServerPem = Path.Combine(d, "srv.pem");
            Leaf(openssl, p, "srv", "localhost", "serverAuth", p.ServerKey, p.ServerPem, 2, opt, "ed25519");
            if (opt.Client)
            {
                p.ClientKey = Path.Combine(d, "client.key"); p.ClientPem = Path.Combine(d, "client.pem");
                Leaf(openssl, p, "client", "pump-reader-4", "clientAuth", p.ClientKey, p.ClientPem, 3, opt, "ed25519");
            }
            // The TLS 1.1 server holds an RSA key under the Ed25519 root, as the lab does today (modes-design.md section 1.8).
            p.Tls11Key = Path.Combine(d, "tls11.key"); p.Tls11Pem = Path.Combine(d, "tls11.pem");
            Leaf(openssl, p, "tls11", "localhost", "serverAuth", p.Tls11Key, p.Tls11Pem, 4, opt, "rsa");
            return p;
        }

        static void Leaf(string openssl, TestPki p, string stem, string cn, string eku, string keyFile, string pemFile, int serial, Options opt, string alg)
        {
            string d = p.Dir, csr = Path.Combine(d, stem + ".csr"), ext = Path.Combine(d, stem + ".cnf");
            Key(openssl, d, alg, keyFile);
            Run(openssl, d, "req -new -key " + Q(keyFile) + " -subj \"/CN=" + cn + "\" -out " + Q(csr));
            File.WriteAllText(ext, "subjectAltName=DNS:" + cn + "\nextendedKeyUsage=" + eku + "\nbasicConstraints=CA:FALSE\n");
            string validity = opt.NotBefore != null ? " -not_before " + opt.NotBefore + " -not_after " + opt.NotAfter : " -days " + Math.Max(opt.Days, 1);
            Run(openssl, d, "x509 -req -in " + Q(csr) + " -CA " + Q(p.RootPem) + " -CAkey " + Q(p.RootKey) + validity + " -set_serial " + serial + " -extfile " + Q(ext) + " -out " + Q(pemFile));
        }

        /// <summary>True when OpenSSL itself says leaf is signed by root (the suite's ground truth, before the Host is asked).</summary>
        public static bool OpensslVerifies(Ctx c, string rootPem, string leafPem, out string output)
        {
            return Proc.Run(Referees.OpenSsl(c), "verify -CAfile " + Q(rootPem) + " " + Q(leafPem), Path.GetDirectoryName(leafPem), 30000, out output) == 0;
        }

        /// <summary>The paths map of a "Use my files" run for my-certificates, in the key layout of acceptance/CONTRACT.md section 5 (ASSUMED).</summary>
        public Dictionary<string, string> Paths(bool rootKey)
        {
            Dictionary<string, string> m = new Dictionary<string, string>();
            m["pki.root-ca"] = RootPem;
            if (rootKey) m["pki.root-ca.key"] = RootKey;
            m["tls13.server"] = ServerPem; m["tls13.server.key"] = ServerKey;
            if (ClientPem != null) { m["tls13.client"] = ClientPem; m["tls13.client.key"] = ClientKey; }
            m["tls11.server"] = Tls11Pem; m["tls11.server.key"] = Tls11Key;
            m["tls.trust"] = RootPem;
            return m;
        }
    }
}
