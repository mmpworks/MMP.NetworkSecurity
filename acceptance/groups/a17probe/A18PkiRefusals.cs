using System.IO;
using System.Text;
using NetSec.Io;
using NetSec.Keys;

namespace Acceptance
{
    /// <summary>
    /// A18: what the certificate check leaves out, against an OpenSSL server with certificates the suite made (docs/conformance-matrix.md row 12). Each clause pairs with the on-screen line A18.screen.l4-pki-leaves-out.
    /// The glass client trusts the training root. The suite reads that root's seed from TrainingKeySource and signs its own leaves with OpenSSL, and a plain leaf connects first, as the control.
    /// </summary>
    public static class A18PkiRefusals
    {
        static string Q(string s) { return "\"" + s + "\""; }

        sealed class Root { public string Dir, Pem, Key; }

        /// <summary>The training root, as OpenSSL can use it: its certificate from TrainingPki.Export, and its 32-byte Ed25519 seed in a PKCS#8 wrapper.</summary>
        static Root TrainingRoot(Ctx c, string stem)
        {
            PkiDir p = PkiDir.Export(c, stem);
            byte[] seed = new TrainingKeySource().Find(KeyIds.CaRoot).CopyMaterial();
            Check.True(seed.Length == 32, "the ca-root material is " + seed.Length + " bytes, expected a 32-byte seed");
            byte[] der = Hex.Decode("302e020100300506032b657004220420" + Hex.Encode(seed));
            Root r = new Root();
            r.Dir = p.Dir; r.Pem = p.Root; r.Key = Path.Combine(p.Dir, "root-for-suite.key");
            File.WriteAllText(r.Key, LivePki.Pem("PRIVATE KEY", der));
            return r;
        }

        /// <summary>A server leaf for localhost under the root, with extra extension lines.</summary>
        static void Leaf(Ctx c, Root pki, string name, string extraExt, int serial, out string pem, out string key)
        {
            Leaf(c, pki, name, extraExt, serial, "-algorithm ed25519", out pem, out key);
        }

        static void Leaf(Ctx c, Root pki, string name, string extraExt, int serial, string keyArgs, out string pem, out string key)
        {
            string openssl = Referees.OpenSsl(c), d = pki.Dir;
            key = Path.Combine(d, name + ".key"); pem = Path.Combine(d, name + ".pem");
            string csr = Path.Combine(d, name + ".csr"), ext = Path.Combine(d, name + ".cnf");
            LivePki.Run(openssl, "genpkey " + keyArgs + " -out " + Q(key), d, "leaf key");
            LivePki.Run(openssl, "req -new -key " + Q(key) + " -subj \"/CN=localhost\" -out " + Q(csr), d, "leaf request");
            File.WriteAllText(ext, "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n" + extraExt);
            LivePki.Run(openssl, "x509 -req -in " + Q(csr) + " -CA " + Q(pki.Pem) + " -CAkey " + Q(pki.Key) + " -days 2 -set_serial " + serial + " -extfile " + Q(ext) + " -out " + Q(pem), d, "leaf");
        }

        static ProbeResult Connect(Ctx c, string pem, string key, string what)
        {
            using (OpenSslPeer server = OpenSslPeer.StartServer(c, "-tls1_3 -groups X25519 -rev -cert " + Q(pem) + " -key " + Q(key)))
            {
                ProbeRequest req = ProbeKit.Request(WireProtocol.Tls13, server.Port, "localhost");
                req.Group = KexGroup.X25519;
                req.Send = Encoding.ASCII.GetBytes("hello\n");
                return ProbeKit.Connect(req, what);
            }
        }

        static void Control(Ctx c, Root pki)
        {
            string pem, key;
            Leaf(c, pki, "control", "", 40, out pem, out key);
            ProbeResult control = Connect(c, pem, key, "control: a plain leaf");
            Check.True(control.Completed, "control: a plain leaf under the training root should connect, and stopped: " + control.CheckName + " [" + control.Code + "]");
        }

        static string CriticalRefused(Ctx c, string stem, string ext, string what)
        {
            Root pki = TrainingRoot(c, stem);
            Control(c, pki);
            string pem, key;
            Leaf(c, pki, "critical", ext, 41, out pem, out key);
            ProbeResult r = Connect(c, pem, key, "a leaf with " + what);
            Check.True(!r.Completed, "the glass client accepted a leaf with " + what + ". So it now reads this extension, and the on-screen line A18.screen.l4-pki-leaves-out needs a change");
            Check.Equal("refusal code for a leaf with " + what, "CERT_UNKNOWN_CRITICAL", r.Code);
            return "a plain leaf connects; a leaf with " + what + " is refused: " + r.CheckName + " [" + r.Code + "]";
        }

        /// <summary>Matrix row 4, the client side: the glass client offers Ed25519 signatures only, so an OpenSSL server that holds another key type has nothing to sign with and sends an alert.</summary>
        static string ClientRefusesKeyType(Ctx c, string stem, string keyArgs, string what)
        {
            Root pki = TrainingRoot(c, stem);
            Control(c, pki);
            string pem, key;
            Leaf(c, pki, "other-key", "", 43, keyArgs, out pem, out key);
            ProbeResult r = Connect(c, pem, key, "a server with " + what);
            Check.True(!r.Completed, "the glass client completed a session with a server that holds " + what + ". The on-screen line A18.screen.l5-tls13-leaves-out needs a change");
            Check.Equal("refusal code against a server with " + what, "TLS13_ALERT_RECEIVED", r.Code);
            return "a plain leaf connects; a server with " + what + " stops the glass client: " + r.CheckName + " [" + r.Code + "]";
        }

        [Clause("A18.refuse.tls13.client-rsa-server")]
        public static string ClientRsaServer(Ctx c) { return ClientRefusesKeyType(c, "a18-t13-rsa", "-algorithm RSA -pkeyopt rsa_keygen_bits:2048", "an RSA key"); }

        [Clause("A18.refuse.tls13.client-ecdsa-server")]
        public static string ClientEcdsaServer(Ctx c) { return ClientRefusesKeyType(c, "a18-t13-ecdsa", "-algorithm EC -pkeyopt ec_paramgen_curve:P-256", "an ECDSA key"); }

        [Clause("A18.refuse.pki.critical-name-constraints")]
        public static string NameConstraints(Ctx c) { return CriticalRefused(c, "a18-pki-nc", "nameConstraints=critical,permitted;DNS:localhost\n", "a critical name constraints extension"); }

        [Clause("A18.refuse.pki.critical-policies")]
        public static string Policies(Ctx c) { return CriticalRefused(c, "a18-pki-policy", "certificatePolicies=critical,1.3.6.1.4.1.99999.1\n", "a critical certificate policies extension"); }

        /// <summary>OpenSSL, given the CRL, refuses this leaf. The glass client has no revocation check, so it connects. If it starts to refuse, the on-screen line needs a change.</summary>
        [Clause("A18.refuse.pki.revoked-leaf-is-accepted")]
        public static string RevokedLeaf(Ctx c)
        {
            Root pki = TrainingRoot(c, "a18-pki-crl");
            Control(c, pki);
            string pem, key;
            Leaf(c, pki, "revoked", "", 42, out pem, out key);
            string openssl = Referees.OpenSsl(c), d = pki.Dir, index = Path.Combine(d, "index.txt"), crl = Path.Combine(d, "root.crl"), conf = Path.Combine(d, "ca.cnf");
            File.WriteAllText(index, "");
            File.WriteAllText(Path.Combine(d, "crlnumber"), "01\n");
            File.WriteAllText(conf, "[ca]\ndefault_ca=d\n[d]\ndatabase=" + index.Replace('\\', '/') + "\ncrlnumber=" + Path.Combine(d, "crlnumber").Replace('\\', '/') + "\ncertificate=" + pki.Pem.Replace('\\', '/') + "\nprivate_key=" + pki.Key.Replace('\\', '/') + "\ndefault_md=null\ndefault_crl_days=2\n");
            LivePki.Run(openssl, "ca -config " + Q(conf) + " -revoke " + Q(pem), d, "revoke");
            LivePki.Run(openssl, "ca -config " + Q(conf) + " -gencrl -out " + Q(crl), d, "CRL");
            string output;
            int code = Proc.Run(openssl, "verify -crl_check -CRLfile " + Q(crl) + " -CAfile " + Q(pki.Pem) + " " + Q(pem), d, 30000, out output);
            Check.True(code != 0 && output.Contains("revoked"), "setup: OpenSSL should refuse the leaf with the CRL. Output: " + output);
            ProbeResult r = Connect(c, pem, key, "a revoked leaf");
            Check.True(r.Completed, "the glass client refused a revoked leaf: " + r.CheckName + " [" + r.Code + "]. So it may now check revocation, and the on-screen line A18.screen.l4-pki-leaves-out needs a change");
            return "OpenSSL, given the CRL, refuses the leaf; the glass client has no revocation check, and connects";
        }
    }
}
