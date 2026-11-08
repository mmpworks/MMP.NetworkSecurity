using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// The TLS 1.1 key schedule walk (docs/sections-plan.md line 159, slice P4b): GET /api/walk/tls11/schedule. It is a fixed teaching run on the
    /// built-in training key, which is public in the source, so it stays open with Show keys OFF. The plan names the anchors: an OpenSSL decrypt of
    /// the pre-master with the same key, and the key log line. The suite adds its own TLS 1.1 PRF (RFC 4346 section 5), built from the .NET MD5
    /// and SHA-1, for the master secret and the key block.
    /// </summary>
    public static class Tls11WalkClauses
    {
        public const string Path = "/api/walk/tls11/schedule";

        static byte[] PHash(HMAC mac, byte[] seed, int length)
        {
            byte[] outp = new byte[length], a = seed;
            int done = 0;
            while (done < length)
            {
                a = mac.ComputeHash(a);
                byte[] chunk = mac.ComputeHash(Concat(a, seed));
                int n = Math.Min(chunk.Length, length - done);
                Array.Copy(chunk, 0, outp, done, n);
                done += n;
            }
            return outp;
        }

        static byte[] Concat(byte[] x, byte[] y) { byte[] r = new byte[x.Length + y.Length]; Array.Copy(x, r, x.Length); Array.Copy(y, 0, r, x.Length, y.Length); return r; }

        /// <summary>RFC 4346 section 5: P_MD5 on the first half of the secret XOR P_SHA-1 on the second half, the halves sharing a middle byte when the length is odd.</summary>
        public static byte[] Prf(byte[] secret, string label, byte[] seed, int length)
        {
            int half = (secret.Length + 1) / 2;
            byte[] s1 = new byte[half], s2 = new byte[half];
            Array.Copy(secret, 0, s1, 0, half);
            Array.Copy(secret, secret.Length - half, s2, 0, half);
            byte[] ls = Concat(Encoding.ASCII.GetBytes(label), seed);
            byte[] md5, sha1;
            using (HMACMD5 m = new HMACMD5(s1)) md5 = PHash(m, ls, length);
            using (HMACSHA1 s = new HMACSHA1(s2)) sha1 = PHash(s, ls, length);
            byte[] r = new byte[length];
            for (int i = 0; i < length; i++) r[i] = (byte)(md5[i] ^ sha1[i]);
            return r;
        }

        static byte[] Bytes(Dictionary<string, object> d, string field, string where)
        {
            string hex = MiniJson.Str(d, field);
            Check.True(!string.IsNullOrEmpty(hex), where + ": no " + field);
            return Hex.Decode(hex);
        }

        static string Hx(byte[] b) { return Hex.Encode(b).ToLowerInvariant(); }

        [Clause("A19.host.tls11-schedule-open-and-prf")]
        public static string Tls11Schedule(Ctx c)
        {
            using (HostProc h = A17.Host(c, "walk-tls11"))
            {
                // The training key, read while Show keys is ON, before the walk is asked with it OFF.
                Reply key = A17.Key(h, "tls11.server");
                Check.True(key.Ok && !string.IsNullOrEmpty(MiniJson.Str(key.Json, "hex")), "the Host shows no built-in tls11.server key with Show keys ON: " + key);
                byte[] pkcs8 = Hex.Decode(MiniJson.Str(key.Json, "hex"));
                byte[] spki;
                using (RSA rsa = RSA.Create()) { rsa.ImportPkcs8PrivateKey(pkcs8, out _); spki = rsa.ExportSubjectPublicKeyInfo(); }

                Reply off = HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", false));
                Check.True(off.Ok, "PUT show-keys got " + off);
                Reply r = HostHttp.Get(h, Path);
                if (r.Status == 404 && string.IsNullOrEmpty(r.Code)) throw new NotRunException("PRODUCT_MISSING", "the Host has no route " + Path + " yet (slice P4b)");
                Check.True(r.Ok && r.Json != null, "OFF: GET " + Path + " got " + r + ". The walk runs on the public built-in training key, so it stays open");
                Check.Equal("keySource", "training", MiniJson.Str(r.Json, "keySource"));
                // The walk must run on the key the suite read. A learner's own tls11.server key would fail here, loudly, and not decrypt to garbage.
                Check.Equal("serverPublicKey is the public half of the built-in tls11.server key", Hx(spki), Hx(Bytes(r.Json, "serverPublicKey", "walk")));

                byte[] cr = Bytes(r.Json, "clientRandom", "walk"), sr = Bytes(r.Json, "serverRandom", "walk");
                byte[] enc = Bytes(r.Json, "encryptedPremaster", "walk"), pre = Bytes(r.Json, "premaster", "walk");
                Check.True(cr.Length == 32 && sr.Length == 32, "each random is 32 bytes");
                Check.True(pre.Length == 48 && pre[0] == 3 && pre[1] == 2, "the pre-master is 48 bytes and starts with the version 03 02 (TLS 1.1)");
                Check.True((int)MiniJson.Num(r.Json, "premasterVersion", 0) == 0x0302, "premasterVersion is not 770 (0x0302)");

                // OpenSSL decrypts the encrypted pre-master with the training key, as the plan says.
                string dir = A17.TempDir(c, "tls11-walk");
                string keyFile = System.IO.Path.Combine(dir, "server.der"), inFile = System.IO.Path.Combine(dir, "enc.bin"), outFile = System.IO.Path.Combine(dir, "pre.bin");
                File.WriteAllBytes(keyFile, pkcs8); File.WriteAllBytes(inFile, enc);
                string o;
                int code = Proc.Run(Referees.OpenSsl(c), "pkeyutl -decrypt -keyform DER -inkey \"" + keyFile + "\" -pkeyopt rsa_padding_mode:pkcs1 -in \"" + inFile + "\" -out \"" + outFile + "\"", dir, 30000, out o);
                Check.True(code == 0 && File.Exists(outFile), "OpenSSL could not decrypt the encrypted pre-master with the training key: " + o.Trim());
                Check.Equal("the pre-master OpenSSL decrypts with the training key", Hx(pre), Hx(File.ReadAllBytes(outFile)));

                // The suite's own PRF gives the master secret and the key block.
                byte[] master = Prf(pre, "master secret", Concat(cr, sr), 48);
                Dictionary<string, object> ms = MiniJson.Obj(r.Json, "masterSecret");
                Check.True(ms != null, "the walk has no masterSecret");
                Check.Equal("masterSecret.label", "master secret", MiniJson.Str(ms, "label"));
                Check.Equal("the master secret, by the suite's own TLS 1.1 PRF", Hx(master), Hx(Bytes(ms, "value", "masterSecret")));

                Dictionary<string, object> kb = MiniJson.Obj(r.Json, "keyBlock");
                Check.True(kb != null, "the walk has no keyBlock");
                Check.Equal("keyBlock.label", "key expansion", MiniJson.Str(kb, "label"));
                byte[] cm = Bytes(kb, "clientMacKey", "keyBlock"), sm = Bytes(kb, "serverMacKey", "keyBlock"), ck = Bytes(kb, "clientKey", "keyBlock"), sk = Bytes(kb, "serverKey", "keyBlock");
                Check.True(cm.Length == sm.Length && ck.Length == sk.Length && cm.Length > 0 && ck.Length > 0, "the 2 MAC keys and the 2 encryption keys should match in size");
                byte[] block = Prf(master, "key expansion", Concat(sr, cr), 2 * cm.Length + 2 * ck.Length);
                byte[] want = Concat(Concat(cm, sm), Concat(ck, sk));
                Check.Equal("the key block, client MAC, server MAC, client key, server key in order (RFC 4346 section 6.3)", Hx(block), Hx(want));

                string line = MiniJson.Str(r.Json, "keyLogLine") ?? "";
                Check.Equal("the key log line Wireshark reads", "CLIENT_RANDOM " + Hx(cr) + " " + Hx(master), line.Trim().ToLowerInvariant().Replace("client_random", "CLIENT_RANDOM"));
                HostHttp.Put(h, "/api/security/show-keys", A17.Obj("on", true));
                return "with Show keys OFF the TLS 1.1 walk answers: OpenSSL decrypts its pre-master with the training key, the suite's own PRF gives its master secret and its " + (2 * cm.Length + 2 * ck.Length) + "-byte key block, and its key log line names the client random and the master";
            }
        }
    }
}
