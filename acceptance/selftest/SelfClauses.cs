using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Acceptance
{
    /// <summary>
    /// Proof that the suite bites. These clauses use no product code. They run the real A1 clause bodies
    /// against a BCL stand-in, then break a vector or the stand-in on purpose and expect FAIL.
    /// </summary>
    public static class SelfClauses
    {
        delegate string Body(Ctx c);

        static Ctx Copy(Ctx c, string vectorsDir)
        {
            Ctx n = new Ctx();
            n.Build = "net10"; n.VectorsDir = vectorsDir; n.AcceptanceDir = c.AcceptanceDir; n.RepoRoot = c.RepoRoot; n.WorkDir = c.WorkDir;
            return n;
        }

        static string Run(Body b, Ctx c)
        {
            try { return "PASS: " + b(c); }
            catch (NotRunException ex) { return "NOT RUN: " + ex.Reason; }
            catch (FailException ex) { return "FAIL: " + ex.Message; }
        }

        [Clause("SELF.reference-passes")]
        public static string ReferencePasses(Ctx c)
        {
            Dictionary<string, Body> all = new Dictionary<string, Body>();
            foreach (MethodInfo m in typeof(PrimClauses).GetMethods(BindingFlags.Public | BindingFlags.Static))
                foreach (ClauseAttribute a in m.GetCustomAttributes(typeof(ClauseAttribute), false))
                {
                    MethodInfo mm = m;
                    all[a.Id] = delegate (Ctx x) { return (string)mm.Invoke(null, new object[] { x }); };
                }
            string[] mustPass = new string[] { "A1.aes-ecb", "A1.aes-cbc", "A1.aes-ctr", "A1.aes-gcm", "A1.sha1", "A1.sha256", "A1.sha384", "A1.sha512",
                "A1.md5", "A1.hmac-md5", "A1.hmac-sha1", "A1.hmac-sha256", "A1.hmac-sha384", "A1.hmac-sha512", "A1.cmac", "A1.hkdf-sha256", "A1.hkdf-sha1" };
            StringBuilder notRun = new StringBuilder();
            int passed = 0;
            List<string> keys = new List<string>(all.Keys);
            keys.Sort(StringComparer.Ordinal);
            foreach (string id in keys)
            {
                string r;
                try { r = Run(delegate (Ctx x) { try { return all[id](x); } catch (TargetInvocationException t) { throw t.InnerException; } }, c); }
                catch (Exception ex) { throw new FailException(id + " threw " + ex.GetType().Name + ": " + ex.Message); }
                if (r.StartsWith("FAIL")) throw new FailException(id + " fails on the BCL stand-in: " + r + ". A vector file or a checker is wrong.");
                if (r.StartsWith("PASS")) passed++;
                else
                {
                    if (Array.IndexOf(mustPass, id) >= 0) throw new FailException(id + " should pass on the BCL stand-in but gave " + r);
                    notRun.Append(id).Append(' ');
                }
            }
            return passed + " A1 clause bodies pass on the BCL stand-in. No BCL reference (NOT RUN): " + notRun.ToString().Trim();
        }

        [Clause("SELF.dukpt-vectors-pass")]
        public static string DukptVectorsPass(Ctx c)
        {
            Body[] mustPass = new Body[] { DukptClauses.Aes128FromAes128, DukptClauses.Aes128FromAes256, DukptClauses.Aes256FromAes256, DukptClauses.AllUsages, DukptClauses.PinBlockFormat4 };
            string[] names = new string[] { "A3.vec.aes128-from-aes128", "A3.vec.aes128-from-aes256", "A3.vec.aes256-from-aes256", "A3.vec.all-usages", "A3.pinblock.format4" };
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < mustPass.Length; i++)
            {
                string r = Run(mustPass[i], Copy(c, c.VectorsDir));
                if (!r.StartsWith("PASS")) throw new FailException(names[i] + " on the BCL reference: " + r);
                sb.Append(names[i]).Append(" [").Append(r.Substring(6)).Append("]; ");
            }
            string pad = Run(DukptClauses.Sales1000, Copy(c, c.VectorsDir));
            if (!pad.StartsWith("NOT RUN")) throw new FailException("A3.sales1000.agree should be NOT RUN without a terminal-side reference, got " + pad);
            return sb.ToString().Trim();
        }

        [Clause("SELF.kschedule-rfc8448-pass")]
        public static string KeyScheduleRfc8448Pass(Ctx c)
        {
            Body[] bodies = new Body[] { KeyScheduleClauses.EarlySecret, KeyScheduleClauses.HandshakeSecret, KeyScheduleClauses.HandshakeTrafficSecrets,
                KeyScheduleClauses.MasterSecret, KeyScheduleClauses.ApplicationTrafficSecrets, KeyScheduleClauses.ExporterAndResumption,
                KeyScheduleClauses.TrafficKeysAndIvs, KeyScheduleClauses.Finished, KeyScheduleClauses.TranscriptHashes };
            for (int i = 0; i < bodies.Length; i++)
            {
                string r = Run(bodies[i], Copy(c, c.VectorsDir));
                if (!r.StartsWith("PASS")) throw new FailException("A4 clause #" + i + " on the BCL reference: " + r);
            }
            string x = Run(KeyScheduleClauses.X25519Shared, Copy(c, c.VectorsDir));
            if (!x.StartsWith("NOT RUN")) throw new FailException("A4.rfc8448.x25519-shared-secret should be NOT RUN without a reference, got " + x);
            return bodies.Length + " RFC 8448 key schedule clauses pass on an RFC 8446 section 7.1 reference built on BCL HKDF";
        }

        [Clause("SELF.openssl-referee-smoke")]
        public static string OpenSslRefereeSmoke(Ctx c)
        {
            // Two OpenSSL processes talk to each other. The parsers and the process control the live clauses use must read both sides.
            string openssl = Referees.OpenSsl(c);
            string dir = Path.Combine(c.WorkDir, "smoke");
            Directory.CreateDirectory(dir);
            string key = Path.Combine(dir, "k.pem"), cert = Path.Combine(dir, "c.pem");
            string o;
            if (Proc.Run(openssl, "genpkey -algorithm ed25519 -out \"" + key + "\"", dir, 30000, out o) != 0) throw new FailException("genpkey: " + o);
            if (Proc.Run(openssl, "req -new -x509 -key \"" + key + "\" -subj \"/CN=localhost\" -days 2 -addext \"subjectAltName=DNS:localhost\" -out \"" + cert + "\"", dir, 30000, out o) != 0) throw new FailException("req: " + o);
            StringBuilder report = new StringBuilder();
            foreach (string g in new string[] { "X25519", "X25519MLKEM768" })
            {
                string slog = Path.Combine(dir, "s-" + g + ".log"), clog = Path.Combine(dir, "c-" + g + ".log");
                using (OpenSslPeer server = OpenSslPeer.StartServer(c, "-tls1_3 -groups " + g + " -cert \"" + cert + "\" -key \"" + key + "\" -keylogfile \"" + slog + "\""))
                using (OpenSslPeer client = OpenSslPeer.StartClient(c, "-connect 127.0.0.1:" + server.Port + " -tls1_3 -groups " + g + " -servername localhost -CAfile \"" + cert + "\" -verify_return_error -brief -keylogfile \"" + clog + "\""))
                {
                    client.P.WriteLine("hello");
                    if (client.P.WaitForLine(delegate (string l) { return l.Contains("olleh"); }, 20000) == null) throw new FailException(g + ": no echo from s_server -rev. Client output: " + client.Output);
                    if (server.WaitFor(@"Peer Temp Key:", 20000) == null) throw new FailException(g + ": s_server never printed Peer Temp Key. Output: " + server.Output);
                    Check.Equal(g + " group as s_server prints it", g, OpenSslLines.ServerGroup(server.Output));
                    Check.Equal(g + " group as s_client prints it", g, OpenSslLines.ClientGroup(client.Output));
                    Check.Equal(g + " protocol", "TLSv1.3", OpenSslLines.Protocol(server.Output));
                    Check.True(OpenSslLines.Ciphersuite(server.Output) != null, g + ": no Ciphersuite line");
                    Check.True(client.Output.Contains("Verification: OK"), g + ": s_client did not print Verification: OK. Output: " + client.Output);
                    // Both sides write an NSS key log. Take the random from the client's log and compare the server's lines.
                    Thread.Sleep(500);
                    Match first = Regex.Match(OpenSslLines.ReadShared(clog), @"(?m)^[A-Z0-9_]+ (?<r>[0-9a-f]{64}) ");
                    Check.True(first.Success, g + ": client key log is empty");
                    Dictionary<string, string> ours = OpenSslLines.KeyLog(clog, first.Groups["r"].Value), theirs = OpenSslLines.KeyLog(slog, first.Groups["r"].Value);
                    Check.True(ours.Count == 5 && theirs.Count == 5, g + ": expected 5 key log labels on each side, got " + ours.Count + " and " + theirs.Count);
                    foreach (KeyValuePair<string, string> kv in ours)
                        Check.True(theirs.ContainsKey(kv.Key) && theirs[kv.Key] == kv.Value, g + ": key log line " + kv.Key + " differs between client and server");
                    report.Append(g).Append(" ok; ");
                }
            }
            return report.ToString().Trim() + " (group, protocol, suite, verification and 5-label key log parsed from real s_server and s_client runs)";
        }

        [Clause("SELF.openssh-key-format")]
        public static string OpenSshKeyFormat(Ctx c)
        {
            // An Ed25519 key made by OpenSSL. We rebuild it as an OpenSSH key file and ask ssh-keygen what public key it holds.
            string openssl = Referees.OpenSsl(c);
            string ssh = Referees.SshExe(c);
            string keygen = Path.Combine(Path.GetDirectoryName(ssh), "ssh-keygen.exe");
            string dir = Path.Combine(c.WorkDir, "sshkey");
            Directory.CreateDirectory(dir);
            string pem = Path.Combine(dir, "k.pem"), spki = Path.Combine(dir, "k.spki"), mine = Path.Combine(dir, "mine");
            string o;
            if (Proc.Run(openssl, "genpkey -algorithm ed25519 -out \"" + pem + "\"", dir, 30000, out o) != 0) throw new FailException(o);
            if (Proc.Run(openssl, "pkey -in \"" + pem + "\" -pubout -outform DER -out \"" + spki + "\"", dir, 30000, out o) != 0) throw new FailException(o);
            byte[] pub = Hex.Slice(File.ReadAllBytes(spki), 12, 32);                   // SPKI for Ed25519 = 12 byte header + 32 byte key
            byte[] der = new byte[0];
            if (Proc.Run(openssl, "pkey -in \"" + pem + "\" -outform DER -out \"" + Path.Combine(dir, "k.der") + "\"", dir, 30000, out o) != 0) throw new FailException(o);
            der = File.ReadAllBytes(Path.Combine(dir, "k.der"));
            byte[] seed = Hex.Slice(der, der.Length - 32, 32);                          // PKCS#8 for Ed25519 ends with the 32 byte seed
            File.WriteAllText(mine, OpenSshKey.PrivatePem(seed, pub, "acceptance"));
            OpenSshKey.RestrictToCurrentUser(mine);
            if (Proc.Run(keygen, "-y -f \"" + mine + "\"", dir, 30000, out o) != 0) throw new FailException("ssh-keygen -y rejected our key file: " + o.Trim());
            string expected = OpenSshKey.AuthorizedLine(pub, "").Trim();
            Check.True(o.Trim().StartsWith(expected), "ssh-keygen -y printed '" + o.Trim() + "', we expected '" + expected + "'");
            return "ssh-keygen reads our OpenSSH key file and reports the same public key as our authorized_keys line";
        }

        [Clause("SELF.wire-parsers")]
        public static string WireParsers(Ctx c)
        {
            // JSON
            TraceLine tl = TraceLine.Parse("{\"actor\":\"ce\",\"type\":\"ssh.packet.sent\",\"from\":\"ce\",\"to\":\"gateway\",\"traceId\":\"T1\",\"hop\":\"hop1\",\"wire\":\"0aff\",\"secrets\":[{\"holder\":\"ce\",\"name\":\"k\",\"hex\":\"0102\"}],\"check\":{\"name\":\"HMAC compare\",\"result\":\"fail\",\"code\":\"SSH_PACKET_MAC\"}}");
            Check.True(tl.Actor == "ce" && tl.CheckCode == "SSH_PACKET_MAC" && tl.Wire.Length == 2 && tl.Secrets.Count == 1 && tl.Secrets[0].Bytes[1] == 2, "trace line fields not read");

            // TLS: real hybrid handshake captured through a relay that logs both directions.
            string openssl = Referees.OpenSsl(c);
            string dir = Path.Combine(c.WorkDir, "wireparse");
            Directory.CreateDirectory(dir);
            string key = Path.Combine(dir, "k.pem"), cert = Path.Combine(dir, "c.pem"), o;
            if (Proc.Run(openssl, "genpkey -algorithm ed25519 -out \"" + key + "\"", dir, 30000, out o) != 0) throw new FailException(o);
            if (Proc.Run(openssl, "req -new -x509 -key \"" + key + "\" -subj \"/CN=localhost\" -days 2 -addext \"subjectAltName=DNS:localhost\" -out \"" + cert + "\"", dir, 30000, out o) != 0) throw new FailException(o);
            byte[] c2s, s2c;
            using (OpenSslPeer server = OpenSslPeer.StartServer(c, "-tls1_3 -groups X25519MLKEM768 -cert \"" + cert + "\" -key \"" + key + "\""))
            using (CapturingRelay relay = new CapturingRelay(server.Port))
            using (OpenSslPeer client = OpenSslPeer.StartClient(c, "-connect 127.0.0.1:" + relay.Port + " -tls1_3 -groups X25519MLKEM768 -servername localhost -CAfile \"" + cert + "\" -brief"))
            {
                client.P.WriteLine("hello");
                if (client.P.WaitForLine(delegate (string l) { return l.Contains("olleh"); }, 20000) == null) throw new FailException("no echo through the relay: " + client.Output);
                Thread.Sleep(300);
                c2s = relay.ClientToServer; s2c = relay.ServerToClient;
            }
            ClientHelloInfo ch = TlsWire.ClientHello(c2s);
            Check.True(ch != null && ch.Random.Length == 32, "ClientHello not parsed from the captured bytes");
            Check.True(ch.SupportedGroups.Contains(0x11EC), "supported_groups lacks 0x11EC: " + string.Join(",", ch.SupportedGroups.ConvertAll(delegate (int g) { return g.ToString("x4"); }).ToArray()));
            Check.True(ch.KeyShareGroups.Contains(0x11EC), "key_share lacks 0x11EC");
            Check.True(ch.SupportedVersions.Contains(0x0304), "supported_versions lacks TLS 1.3");
            Check.True(TlsWire.ServerHelloRandom(s2c) != null, "ServerHello random not read");
            int firstProtected = TlsWire.FirstProtectedRecord(c2s);
            Check.True(firstProtected > 0, "no application_data record in the client-to-server capture");
            TlsRecord rec = TlsWire.Records(c2s).Find(delegate (TlsRecord r) { return r.Offset == firstProtected; });
            Check.True(rec != null && rec.Total <= c2s.Length - firstProtected, "record at the protected offset does not fit the capture");

            // SSH: ssh.exe talks to a stub that only sends a version line. ssh.exe answers with its version line and KEXINIT in the clear.
            byte[] sshBytes = SshClientHello(Referees.SshExe(c));
            Check.True(SshWire.StartsWithVersion(sshBytes), "ssh.exe did not start with SSH-2.0-: " + Encoding.ASCII.GetString(sshBytes, 0, Math.Min(20, sshBytes.Length)));
            List<SshPacket> clear;
            int enc = SshWire.FirstEncryptedPacket(sshBytes, out clear);
            Check.True(enc == -1 && clear.Count >= 1 && clear[0].Type == 20, "expected a clear KEXINIT (20) and no NEWKEYS yet, got " + clear.Count + " packets, first type " + (clear.Count > 0 ? clear[0].Type.ToString() : "none"));
            // Synthetic stream: version line, KEXINIT, NEWKEYS, then 16 bytes of 'ciphertext'.
            MemoryStream ms = new MemoryStream();
            byte[] ver = Encoding.ASCII.GetBytes("SSH-2.0-test\r\n");
            ms.Write(ver, 0, ver.Length);
            foreach (byte t in new byte[] { 20, 21 })
            {
                byte[] pk = new byte[] { 0, 0, 0, 12, 10, t, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };           // length 12 = 1 pad length + 1 type + 10 pad bytes
                ms.Write(pk, 0, pk.Length);
            }
            long expectOffset = ms.Length;
            ms.Write(new byte[16], 0, 16);
            Check.Equal("first encrypted offset", expectOffset, (long)SshWire.FirstEncryptedPacket(ms.ToArray(), out clear));

            // Tap log
            string logPath = Path.Combine(dir, "hop.hex");
            File.WriteAllText(logPath, "C2S 0102\nS2C ff\nC2S 03\n");
            TapLog tap = TapLog.Read(logPath);
            Check.True(Hex.Encode(tap.ClientToServer) == "010203" && Hex.Encode(tap.ServerToClient) == "ff", "tap log directions mixed up");
            return "MiniJson, TLS records and hellos (real hybrid capture), SSH clear packets (real ssh.exe bytes plus a synthetic NEWKEYS stream), TapLog";
        }

        /// <summary>Runs ssh.exe against a stub that sends a version line, and returns what ssh.exe sent first.</summary>
        static byte[] SshClientHello(string sshExe)
        {
            System.Net.Sockets.TcpListener l = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            l.Start();
            int port = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
            try
            {
                using (Proc p = Proc.Start(sshExe, "-F NUL -o BatchMode=yes -o ConnectTimeout=10 -o UserKnownHostsFile=NUL -p " + port + " user@127.0.0.1 true"))
                using (System.Net.Sockets.TcpClient cl = l.AcceptTcpClient())
                {
                    System.Net.Sockets.NetworkStream ns = cl.GetStream();
                    byte[] hello = Encoding.ASCII.GetBytes("SSH-2.0-stub\r\n");
                    ns.Write(hello, 0, hello.Length);
                    MemoryStream got = new MemoryStream();
                    byte[] buf = new byte[4096];
                    ns.ReadTimeout = 3000;
                    try { int n; while ((n = ns.Read(buf, 0, buf.Length)) > 0) { got.Write(buf, 0, n); if (got.Length > 1500) break; } } catch (IOException) { }
                    return got.ToArray();
                }
            }
            finally { l.Stop(); }
        }

        [Clause("SELF.binproof-detector")]
        public static string BinProofDetector(Ctx c)
        {
            string asyncCf = c.Prop("asyncproxy.cf", @"E:\dev\MMP.AsyncProxy\src\MMP.AsyncProxy.NetCF\bin\Release\net35\MMP.AsyncProxy.dll");
            string asyncNs = c.Prop("asyncproxy.ns2", @"E:\dev\MMP.AsyncProxy\src\MMP.AsyncProxy\bin\Release\netstandard2.0\MMP.AsyncProxy.dll");
            string refDir = c.Prop("netcf", @"E:\dev\tools\netcf35-ref");
            if (!File.Exists(asyncCf) || !File.Exists(asyncNs) || !File.Exists(Path.Combine(refDir, "mscorlib.dll")))
                throw new NotRunException("SIBLING_NOT_BUILT", "needs the MMP.AsyncProxy CF and netstandard builds and the CF references");
            string n;
            Check.Equal("AsyncProxy CF build mscorlib token", "969db8053d3322ac", BinProofClauses.MscorlibToken(asyncCf, out n));
            string tokNs = BinProofClauses.MscorlibToken(asyncNs, out n);
            Check.True(tokNs != "969db8053d3322ac", "the netstandard build carries the CF token; the check cannot tell the builds apart");
            string tmp = Path.Combine(c.WorkDir, "ctl");
            Directory.CreateDirectory(tmp);
            File.Copy(asyncCf, Path.Combine(tmp, "cf.dll"), true);
            File.Copy(asyncNs, Path.Combine(tmp, "ns.dll"), true);
            File.Copy(Path.Combine(refDir, "System.dll"), Path.Combine(tmp, "ref.dll"), true);
            File.WriteAllText(Path.Combine(tmp, "readme.txt"), "x");
            List<string> hits = BinProofClauses.CfBinariesIn(tmp, new List<string> { "cf.dll", "ns.dll", "ref.dll", "readme.txt" }, refDir);
            Check.True(hits.Count == 2 && hits.Exists(delegate (string h) { return h.StartsWith("cf.dll"); }) && hits.Exists(delegate (string h) { return h.StartsWith("ref.dll"); }),
                "detector hits were [" + string.Join("; ", hits.ToArray()) + "]; expected cf.dll and ref.dll only");
            return "CF token read from a real CF binary (" + (tokNs == null ? "the netstandard build has no mscorlib reference" : "netstandard build token " + tokNs) + "); detector flags a CF binary and a copy of a CF reference, and passes the netstandard build";
        }

        static Dictionary<string, string> RunDocs(Ctx c, string root, string ids)
        {
            string script = Path.Combine(c.AcceptanceDir, "checks", "docs_checks.py");
            string output;
            Proc.Run("python", "-I \"" + script + "\" --root \"" + root + "\" --ids " + ids, null, 120000, out output);
            Dictionary<string, string> r = new Dictionary<string, string>();
            foreach (string line in output.Split('\n'))
            {
                if (!line.StartsWith("@@CLAUSE ")) continue;
                Dictionary<string, object> d = MiniJson.AsObject(MiniJson.Parse(line.Substring(9)));
                r[MiniJson.Str(d, "id")] = MiniJson.Str(d, "status") + ":" + MiniJson.Str(d, "reason") + ":" + MiniJson.Str(d, "detail");
            }
            return r;
        }

        static void WriteTour(string root, int lesson, string stepsJson, string glossaryJson)
        {
            string dir = Path.Combine(root, "app", "src", "tours");
            Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, "lesson-" + lesson.ToString("00") + ".json"), "{\"lesson\":" + lesson + ",\"steps\":[" + stepsJson + "]}");
            File.WriteAllText(Path.Combine(root, "app", "src", "glossary.json"), glossaryJson);
        }

        static string Step(int lesson, int n, string kind, string text)
        {
            return "{\"id\":\"L" + lesson + "-S" + n.ToString("00") + "\",\"lesson\":" + lesson + ",\"title\":\"Step " + n + "\",\"text\":[\"" + text + "\"],\"glossary\":[]," +
                   "\"bind\":{\"kind\":\"" + kind + "\"" + (kind == "event" ? ",\"eventType\":\"dukpt.key.derived\"" : "") + "}}";
        }

        [Clause("SELF.text-checks-bite")]
        public static string TextChecksBite(Ctx c)
        {
            string tmp = Path.Combine(c.WorkDir, "docs-roots");
            string empty = Path.Combine(tmp, "empty"), good = Path.Combine(tmp, "good"), bad = Path.Combine(tmp, "bad");
            foreach (string d in new string[] { empty, good, bad }) Directory.CreateDirectory(d);
            const string gloss = "{\"terms\":[{\"id\":\"key\",\"term\":\"key\",\"short\":\"A secret number.\"}]}";
            const string gloss2 = gloss;
            string ids = "A3.tour.states-managed-heap-can-keep-copies,A14.tours.static-schema-and-concept-cap,A15.tours.reading-grade,A15.tours.tic-gate,A15a.tours.reader-verdicts";

            // empty root: nothing exists, so every clause is NOT RUN. None passes.
            foreach (KeyValuePair<string, string> kv in RunDocs(c, empty, ids))
                Check.True(kv.Value.StartsWith("NOT RUN:"), "empty root: " + kv.Key + " gave " + kv.Value);

            // good lesson 6: plain words, a heap statement, 25 percent concept steps, no tics.
            string goodSteps = Step(6, 1, "event", "The pad makes a new key for each sale.") + "," + Step(6, 2, "event", "It then erases the old key.") + "," +
                               Step(6, 3, "event", "The managed heap can keep copies of an erased key.") + "," + Step(6, 4, "concept", "Each sale gets its own key.");
            WriteTour(good, 6, goodSteps, gloss);
            Dictionary<string, string> g = RunDocs(c, good, ids);
            foreach (string id in new string[] { "A3.tour.states-managed-heap-can-keep-copies", "A14.tours.static-schema-and-concept-cap", "A15.tours.reading-grade", "A15.tours.tic-gate" })
                Check.True(g.ContainsKey(id) && g[id].StartsWith("PASS:"), "good root: " + id + " gave " + (g.ContainsKey(id) ? g[id] : "nothing"));
            Check.True(g["A15a.tours.reader-verdicts"].StartsWith("NOT RUN:ACCURACY_READER_PENDING"), "a lesson with no reader verdict must be NOT RUN ACCURACY_READER_PENDING, got " + g["A15a.tours.reader-verdicts"]);

            // bad lesson 6: two of three steps are concept steps, one step has long words and a tic, one term is not in the glossary.
            string badSteps = Step(6, 1, "concept", "Cryptographic authentication necessitates comprehensive interoperability considerations.") + "," +
                              Step(6, 2, "concept", "This exactly shows {{term:nonce}} use.") + "," + Step(6, 3, "event", "A key.");
            WriteTour(bad, 6, badSteps, gloss2);
            Dictionary<string, string> b = RunDocs(c, bad, ids);
            foreach (string id in new string[] { "A3.tour.states-managed-heap-can-keep-copies", "A14.tours.static-schema-and-concept-cap", "A15.tours.reading-grade", "A15.tours.tic-gate" })
                Check.True(b.ContainsKey(id) && b[id].StartsWith("FAIL:"), "bad root: " + id + " should FAIL, gave " + (b.ContainsKey(id) ? b[id] : "nothing"));
            return "empty root: all NOT RUN. good tour: 4 text clauses PASS, reader verdict NOT RUN by name. bad tour: heap statement, concept cap, reading grade and tic-gate all FAIL";
        }

        [Clause("SELF.type-clause-bites")]
        public static string TypeClauseBites(Ctx c)
        {
            string ap = c.Prop("asyncproxy.ns2", @"E:\dev\MMP.AsyncProxy\src\MMP.AsyncProxy\bin\Release\netstandard2.0\MMP.AsyncProxy.dll");
            if (!File.Exists(ap)) throw new NotRunException("SIBLING_NOT_BUILT", "needs the MMP.AsyncProxy netstandard2.0 build at " + ap);
            string src = Path.Combine(c.AcceptanceDir, "contract");
            string good = Path.Combine(c.WorkDir, "stub-good"), bad = Path.Combine(c.WorkDir, "stub-bad");
            foreach (string dst in new string[] { good, bad })
            {
                if (Directory.Exists(dst)) Directory.Delete(dst, true);
                Directory.CreateDirectory(dst);
                foreach (string f in Directory.GetFiles(src, "*.cs")) File.Copy(f, Path.Combine(dst, Path.GetFileName(f)));
                File.Copy(Path.Combine(src, "NetSec.Core.Contract.csproj"), Path.Combine(dst, "NetSec.Core.Contract.csproj"));
            }
            // The mutation: the glass factory takes anything, so an IKeyHandleSource can be given to it. D5 says it must not.
            string io = Path.Combine(bad, "Io.cs");
            string text = File.ReadAllText(io);
            const string ctor = "public GlassTransportFactory(ITrainingKeySource keys)";
            if (text.IndexOf(ctor, StringComparison.Ordinal) < 0) throw new FailException("self-test setup: the stub's GlassTransportFactory constructor changed");
            File.WriteAllText(io, text.Replace(ctor, "public GlassTransportFactory(object keys)"));
            string outp;
            string[] dlls = new string[2];
            for (int i = 0; i < 2; i++)
            {
                string dir = i == 0 ? good : bad;
                if (Proc.Run("dotnet", "build \"" + Path.Combine(dir, "NetSec.Core.Contract.csproj") + "\" -c Release -p:AsyncProxyDll=\"" + ap + "\" --nologo -v q", dir, 300000, out outp) != 0)
                    throw new FailException("stub build failed: " + outp.Trim());
                dlls[i] = Path.Combine(dir, "bin", "Release", "netstandard2.0", "NetSec.Core.dll");
            }
            Ctx okCtx = Copy(c, c.VectorsDir), badCtx = Copy(c, c.VectorsDir);
            okCtx.WorkDir = Path.Combine(c.WorkDir, "probe-good"); badCtx.WorkDir = Path.Combine(c.WorkDir, "probe-bad");
            okCtx.Props["core.net10"] = dlls[0]; badCtx.Props["core.net10"] = dlls[1];
            okCtx.Props["asyncproxy.ns2"] = ap; badCtx.Props["asyncproxy.ns2"] = ap;
            string r1 = Run(KeysClauses.KeyHandleCannotReachGlass, okCtx);
            if (!r1.StartsWith("PASS")) throw new FailException("the type clause should PASS on the faithful stub, gave " + r1);
            string r2 = Run(KeysClauses.KeyHandleCannotReachGlass, badCtx);
            if (!r2.StartsWith("FAIL")) throw new FailException("the type clause should FAIL when the glass factory accepts any object, gave " + r2);
            return "faithful stub -> PASS; glass factory taking object -> " + r2.Substring(0, Math.Min(r2.Length, 160));
        }

        [Clause("SELF.every-primitive-clause-bites")]
        public static string EveryPrimitiveClauseBites(Ctx c)
        {
            // Run each A1 clause body on a stand-in whose output has one flipped bit. A clause that still passes would pass a wrong implementation.
            string[] ids = new string[] { "A1.aes-ecb", "A1.aes-cbc", "A1.aes-ctr", "A1.aes-gcm", "A1.sha1", "A1.sha256", "A1.sha384", "A1.sha512", "A1.md5",
                "A1.sha3-256", "A1.sha3-512", "A1.shake128", "A1.shake256", "A1.hmac-md5", "A1.hmac-sha1", "A1.hmac-sha256", "A1.hmac-sha384", "A1.hmac-sha512",
                "A1.cmac", "A1.hkdf-sha256", "A1.hkdf-sha1" };
            Dictionary<string, MethodInfo> byId = new Dictionary<string, MethodInfo>();
            foreach (MethodInfo m in typeof(PrimClauses).GetMethods(BindingFlags.Public | BindingFlags.Static))
                foreach (ClauseAttribute a in m.GetCustomAttributes(typeof(ClauseAttribute), false)) byId[a.Id] = m;
            int bit = 0;
            foreach (string id in ids)
            {
                MethodInfo m = byId[id];
                Body body = delegate (Ctx x) { try { return (string)m.Invoke(null, new object[] { x }); } catch (TargetInvocationException t) { throw t.InnerException; } };
                string control = Run(body, Copy(c, c.VectorsDir));
                if (!control.StartsWith("PASS")) throw new FailException(id + ": control run on the faithful stand-in gave " + control);
                Subject.Sabotage = true;
                string attack;
                try { attack = Run(body, Copy(c, c.VectorsDir)); }
                finally { Subject.Sabotage = false; }
                if (!attack.StartsWith("FAIL")) throw new FailException(id + " passed on a stand-in with one flipped output bit: " + attack);
                bit++;
            }
            return bit + " A1 clauses each PASS on the faithful stand-in and FAIL when one output bit flips";
        }

        [Clause("SELF.wrong-aes-vector-fails")]
        public static string WrongAesVectorFails(Ctx c)
        {
            string dir = Path.Combine(c.WorkDir, "wrong-vectors");
            Directory.CreateDirectory(dir);
            string src = Path.Combine(c.VectorsDir, "aes-fips197.nsv");
            string text = File.ReadAllText(src);
            // FIPS 197 C.1 ciphertext 69c4e0d86a7b0430d8cdb78070b4c55a. Change one hex digit.
            const string good = "ciphertext = 69c4e0d86a7b0430d8cdb78070b4c55a";
            if (text.IndexOf(good, StringComparison.Ordinal) < 0) throw new FailException("self-test setup: FIPS 197 C.1 ciphertext not found in the vector file");
            File.WriteAllText(Path.Combine(dir, "aes-fips197.nsv"), text.Replace(good, "ciphertext = 69c4e0d86a7b0430d8cdb78070b4c55b"));
            File.Copy(Path.Combine(c.VectorsDir, "aes-modes-sp800-38a.nsv"), Path.Combine(dir, "aes-modes-sp800-38a.nsv"), true);
            string r = Run(PrimClauses.AesEcb, Copy(c, dir));
            if (!r.StartsWith("FAIL")) throw new FailException("a deliberately wrong AES vector gave '" + r + "' instead of FAIL");
            string control = Run(PrimClauses.AesEcb, Copy(c, c.VectorsDir));
            if (!control.StartsWith("PASS")) throw new FailException("control run with the real vector gave '" + control + "' instead of PASS");
            return "wrong vector -> " + r.Substring(0, Math.Min(r.Length, 110)) + " | control -> " + control;
        }

        [Clause("SELF.wrong-hash-vector-fails")]
        public static string WrongHashVectorFails(Ctx c)
        {
            string dir = Path.Combine(c.WorkDir, "wrong-vectors-md5");
            Directory.CreateDirectory(dir);
            string text = File.ReadAllText(Path.Combine(c.VectorsDir, "md5-rfc1321.nsv"));
            const string good = "digest = 900150983cd24fb0d6963f7d28e17f72";
            if (text.IndexOf(good, StringComparison.Ordinal) < 0) throw new FailException("self-test setup: MD5 abc digest not found");
            File.WriteAllText(Path.Combine(dir, "md5-rfc1321.nsv"), text.Replace(good, "digest = 900150983cd24fb0d6963f7d28e17f73"));
            string r = Run(PrimClauses.Md5, Copy(c, dir));
            if (!r.StartsWith("FAIL")) throw new FailException("a deliberately wrong MD5 vector gave '" + r + "' instead of FAIL");
            return r.Substring(0, Math.Min(r.Length, 140));
        }

        [Clause("SELF.wrong-implementation-fails")]
        public static string WrongImplementationFails(Ctx c)
        {
            Subject.Sabotage = true;
            string r;
            try { r = Run(PrimClauses.AesEcb, Copy(c, c.VectorsDir)); }
            finally { Subject.Sabotage = false; }
            if (!r.StartsWith("FAIL")) throw new FailException("an AES stand-in with one flipped output bit gave '" + r + "' instead of FAIL");
            return r.Substring(0, Math.Min(r.Length, 140));
        }

        [Clause("SELF.absent-product-is-not-run")]
        public static string AbsentProductIsNotRun(Ctx c)
        {
            Check.Equal("NotImplementedException", "NOT RUN:PRODUCT_MISSING", ClauseRunner.StatusOf(new NotImplementedException()));
            Check.Equal("TypeLoadException", "NOT RUN:PRODUCT_MISSING", ClauseRunner.StatusOf(new TypeLoadException("NetSec.Crypto.Hashes")));
            Check.Equal("MissingMethodException", "NOT RUN:PRODUCT_MISSING", ClauseRunner.StatusOf(new MissingMethodException("NetSec.Crypto.Hashes", "Sha256")));
            Check.Equal("FileNotFoundException for NetSec.Core", "NOT RUN:PRODUCT_MISSING", ClauseRunner.StatusOf(new FileNotFoundException("Could not load file or assembly 'NetSec.Core'")));
            Check.Equal("NullReferenceException", "FAIL:UNEXPECTED_EXCEPTION", ClauseRunner.StatusOf(new NullReferenceException()));
            Check.Equal("FailException", "FAIL:ASSERTION", ClauseRunner.StatusOf(new FailException("x")));
            Check.Equal("NotRunException", "NOT RUN:REFEREE_MISSING", ClauseRunner.StatusOf(new NotRunException("REFEREE_MISSING", "x")));
            return "an absent product or type maps to NOT RUN PRODUCT_MISSING; any other exception maps to FAIL";
        }

        [Clause("SELF.zero-checks-is-not-pass")]
        public static string ZeroChecksIsNotPass(Ctx c)
        {
            try { new Tally().Done(); }
            catch (NotRunException ex) { return "a clause that ran zero checks reports NOT RUN " + ex.Reason; }
            throw new FailException("Tally.Done() with zero checks did not throw");
        }

        [Clause("SELF.vector-provenance")]
        public static string VectorProvenance(Ctx c)
        {
            int files = 0, groups = 0, records = 0;
            List<string> nsvFiles = new List<string>(Directory.GetFiles(c.VectorsDir, "*.nsv"));
            if (Directory.Exists(Path.Combine(c.VectorsDir, "_cache"))) nsvFiles.AddRange(Directory.GetFiles(Path.Combine(c.VectorsDir, "_cache"), "*.nsv"));
            foreach (string path in nsvFiles)
            {
                files++;
                string file = Path.GetFileName(path);
                string cur = null; bool sawSource = false; bool sawRecord = false;
                List<string> seen = new List<string>();
                foreach (string raw in File.ReadAllLines(path))
                {
                    string ln = raw.Trim();
                    if (ln.StartsWith("[") && ln.EndsWith("]"))
                    {
                        if (cur != null && sawRecord && !sawSource) throw new FailException(file + " group " + cur + " has records and no '# source:' line");
                        cur = ln.Substring(1, ln.Length - 2); sawSource = false; sawRecord = false; groups++;
                        seen.Add(cur);
                    }
                    else if (ln.StartsWith("# source:") && ln.Length > 12) sawSource = true;
                    else if (ln.Contains(" = ")) { if (!sawRecord) { sawRecord = true; } records++; }
                }
                if (cur != null && sawRecord && !sawSource) throw new FailException(file + " group " + cur + " has records and no '# source:' line");
            }
            if (files < 10) throw new FailException("expected at least 10 vector files, found " + files);
            return files + " vector files, " + groups + " groups, " + records + " fields, every group names its source";
        }
    }
}
