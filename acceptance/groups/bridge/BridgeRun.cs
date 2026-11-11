using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace Acceptance
{
    public enum Topology
    {
        /// <summary>PIN pad, CE, Go gogateway (SSH server, TLS 1.3 client), Go tlspeer -relay (TLS 1.3 server), bank HSM.</summary>
        GoReferees,
        /// <summary>PIN pad, CE, our Gateway, our Server, bank HSM.</summary>
        Glass,
        /// <summary>Like Glass, but the CE sends plain bytes to a port and Windows ssh.exe -L carries them to the gateway.</summary>
        GlassSshExeForward
    }

    public sealed class Tamper
    {
        public bool Hop1Flip, Hop2Flip, EnvelopeFlip;
        public long Hop1Offset = -1, Hop2Offset = -1;
        public string Key { get { return (Hop1Flip ? "h1:" + Hop1Offset : "") + (Hop2Flip ? "h2:" + Hop2Offset : "") + (EnvelopeFlip ? "env" : ""); } }
    }

    /// <summary>What one run of the five-process lab produced, as seen from outside.</summary>
    public sealed class BridgeOutcome
    {
        public Topology Topology;
        public string CeReady;
        public TraceLine[] Trace;
        public TapLog Hop1, Hop2;
        public Dictionary<string, string> Output = new Dictionary<string, string>();
        public Dictionary<string, object> PinPad, Bank;
        public string TraceId;
        public ulong Seed;
        public byte[] Ksn;

        public string FailedCodes
        {
            get
            {
                List<string> codes = new List<string>();
                foreach (TraceLine t in Trace) if (t.CheckResult == "fail" && t.CheckCode != null && !codes.Contains(t.CheckCode)) codes.Add(t.CheckCode);
                return string.Join(",", codes.ToArray());
            }
        }

        /// <summary>The bank's RESULT code. Absent, empty or OK means the bank recovered the PIN block.</summary>
        public bool BankOk
        {
            get
            {
                if (Bank == null) return false;
                string code = MiniJson.Str(Bank, "code");
                return string.IsNullOrEmpty(code) || code == "OK";
            }
        }

        /// <summary>The event bytes a process wrote to the socket, joined in file order (type wire.sent, design section 2.1).</summary>
        public byte[] WireSent(string hop, string actor)
        {
            List<byte[]> parts = new List<byte[]>();
            foreach (TraceLine t in Trace)
                if (t.Type == "wire.sent" && t.Hop == hop && t.Actor == actor && t.Wire != null && t.Wire.Length > 0) parts.Add(t.Wire);
            return Hex.Concat(parts.ToArray());
        }

        public int WireSentEvents(string hop, string actor)
        {
            int n = 0;
            foreach (TraceLine t in Trace) if (t.Type == "wire.sent" && t.Hop == hop && t.Actor == actor) n++;
            return n;
        }
    }

    /// <summary>
    /// Starts the lab processes from outside, as program-design.md sections 6, 9 and 11 describe: nodes behind two tap relays, the CE exe,
    /// a wait for CE-READY, and the PIN pad that the CE connects to. Every node prints READY port=P first and a final RESULT line, and writes
    /// its trace to a file given by --trace-file. The suite reads those files after the run. Command lines the suite uses beyond section 11
    /// (--seed on a node, --tamper-envelope on the gateway) are ASSUMED and listed in CONTRACT.md.
    /// </summary>
    public sealed class BridgeRun : IDisposable
    {
        readonly Ctx _c;
        readonly Topology _topology;
        readonly Tamper _tamper;
        readonly ulong _seed;
        readonly bool _useSeed;
        readonly List<IDisposable> _owned = new List<IDisposable>();
        readonly string _dir;

        BridgeRun(Ctx c, Topology t, Tamper tamper, ulong seed, bool useSeed, string name)
        {
            _c = c; _topology = t; _tamper = tamper; _seed = seed; _useSeed = useSeed;
            _dir = Path.Combine(c.WorkDir, name);
            Directory.CreateDirectory(_dir);
        }

        public void Dispose() { for (int i = _owned.Count - 1; i >= 0; i--) { try { _owned[i].Dispose(); } catch (Exception) { } } }

        static readonly Dictionary<string, BridgeOutcome> Memo = new Dictionary<string, BridgeOutcome>();

        /// <summary>Runs (or returns the memoized result of) one lab run. useSeed false lets every process use OS randomness.</summary>
        public static BridgeOutcome Get(Ctx c, Topology t, Tamper tamper, ulong seed, bool useSeed, int variant)
        {
            string key = t + "|" + (tamper == null ? "" : tamper.Key) + "|" + (useSeed ? seed.ToString() : "os") + "|" + variant;
            lock (Memo)
            {
                BridgeOutcome o;
                if (Memo.TryGetValue(key, out o)) return o;
                using (BridgeRun r = new BridgeRun(c, t, tamper ?? new Tamper(), seed, useSeed, "bridge-" + Memo.Count))
                    o = r.Execute();
                Memo[key] = o;
                return o;
            }
        }

        // ---------------------------------------------------------------- paths

        string NodePath { get { string p = _c.Prop("node", ""); if (p.Length == 0 || !File.Exists(p)) throw new NotRunException("PRODUCT_MISSING", "NetSec.Node is not built (node=" + p + ")"); return p; } }
        string CeExe { get { string p = _c.Prop("ce", ""); if (p.Length == 0 || !File.Exists(p)) throw new NotRunException("PRODUCT_MISSING", "NetSec.CeDevice.exe is not built (ce=" + p + ")"); return p; } }

        Proc StartNode(string args)
        {
            string path = NodePath;
            Proc p = path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? Proc.Start("dotnet", "\"" + path + "\" " + args) : Proc.Start(path, args);
            _owned.Add(p);
            return p;
        }

        string Seed(int salt) { return _useSeed ? " --seed " + (_seed + (ulong)salt) : ""; }
        string TraceArg(string name) { return " --trace-file \"" + Path.Combine(_dir, name + ".ndjson") + "\""; }

        /// <summary>
        /// Waits for a line that starts with startsWith. A process that prints a code ending _NOT_BUILT (for example NODE_ROLE_NOT_BUILT)
        /// is a part of the product that is not there yet: that is NOT RUN PRODUCT_MISSING at once, never a FAIL after the full wait.
        /// </summary>
        static string WaitLine(Proc p, string startsWith, int ms, string what)
        {
            string found = Poll.Until(delegate
            {
                foreach (string l in p.Lines) if (l.StartsWith(startsWith)) return l;
                string all = p.AllOutput;
                if (all.IndexOf("_NOT_BUILT", StringComparison.Ordinal) >= 0)
                    throw new NotRunException("PRODUCT_MISSING", what + " reports a part of the product as not built yet: " + all.Trim());
                return null;
            }, ms, 100);
            if (found != null) return found;
            throw new FailException(what + " did not print '" + startsWith + "' within " + ms + " ms. Output: " + p.AllOutput);
        }

        /// <summary>Waits for "READY port=P" and returns P.</summary>
        static int WaitReady(Proc p, string what)
        {
            string line = WaitLine(p, "READY", 60000, what);
            Match m = Regex.Match(line, @"^READY port=(?<port>\d+)\s*$");
            if (!m.Success) throw new FailException(what + " printed '" + line + "', expected 'READY port=<p>' (design section 11)");
            return int.Parse(m.Groups["port"].Value);
        }

        static Dictionary<string, object> ResultOf(string line)
        {
            return MiniJson.AsObject(MiniJson.Parse(line.Substring(line.IndexOf(' ') + 1).Trim()));
        }

        /// <summary>Total size of the trace files and the tap logs. It stops changing when every writer has finished.</summary>
        long LogSignature(string hop1Log, string hop2Log)
        {
            long sum = 0;
            foreach (string name in new string[] { "ce", "pinpad", "gateway", "server", "bank" })
            {
                string f = Path.Combine(_dir, name + ".ndjson");
                if (File.Exists(f)) sum += new FileInfo(f).Length;
            }
            foreach (string f in new string[] { hop1Log, hop2Log }) if (File.Exists(f)) sum += new FileInfo(f).Length;
            return sum;
        }

        /// <summary>For each hop, true when the wire.sent bytes of the client end and of the server end equal the tap log bytes of that direction.</summary>
        bool WireMatchesTaps(string hop1Log, string hop2Log)
        {
            List<string> unparsed = new List<string>();
            List<TraceLine> lines = new List<TraceLine>();
            foreach (string name in new string[] { "ce", "pinpad", "gateway", "server", "bank" })
                lines.AddRange(TraceFile.ReadAll(Path.Combine(_dir, name + ".ndjson"), unparsed));
            BridgeOutcome probe = new BridgeOutcome();
            probe.Trace = lines.ToArray();
            try
            {
                TapLog t1 = File.Exists(hop1Log) ? TapLog.Read(hop1Log) : new TapLog();
                // Hop 1 carries our SSH only in the glass topology (the CE speaks plain bytes to ssh.exe, and Go is the gateway in the referee topology).
                if (_topology == Topology.Glass && (!Hex.Eq(probe.WireSent("hop1", "ce"), t1.ClientToServer) || !Hex.Eq(probe.WireSent("hop1", "gateway"), t1.ServerToClient))) return false;
                if (_topology != Topology.GoReferees)
                {
                    TapLog t2 = File.Exists(hop2Log) ? TapLog.Read(hop2Log) : new TapLog();
                    if (!Hex.Eq(probe.WireSent("hop2", "gateway"), t2.ClientToServer) || !Hex.Eq(probe.WireSent("hop2", "server"), t2.ServerToClient)) return false;
                }
                return true;
            }
            catch (FailException) { return false; }          // a tap record cut in the middle of a line: not settled yet
        }

        /// <summary>
        /// Waits until the processes have finished writing. A process writes a wire.sent event just before it writes the bytes, and tap writes its log
        /// record as the bytes pass, so a fixed sleep can read both too early on a loaded machine. The wait ends when the files stop growing for
        /// 1.5 s and, in a run with no tamper, the wire.sent bytes equal the tap bytes. The longest wait is 25 s. A comparison that is still unequal
        /// after that is left to the A10a clause to report.
        /// </summary>
        void SettleLogs(string hop1Log, string hop2Log, bool tampered)
        {
            DateTime end = DateTime.UtcNow.AddSeconds(25), stableSince = DateTime.UtcNow;
            long last = -1;
            while (DateTime.UtcNow < end)
            {
                long sig = LogSignature(hop1Log, hop2Log);
                if (sig != last) { last = sig; stableSince = DateTime.UtcNow; }
                bool quiet = (DateTime.UtcNow - stableSince).TotalMilliseconds >= 1500;
                if (quiet && (tampered || WireMatchesTaps(hop1Log, hop2Log))) return;
                Thread.Sleep(200);
            }
        }

        static string CeResultLine(Proc ce)
        {
            foreach (string l in ce.Lines) if (l.StartsWith("CE-RESULT")) return l;
            return null;
        }

        static string CeSummary(Proc ce)
        {
            string r = CeResultLine(ce);
            return r == null ? "The CE printed no CE-RESULT." : "The CE printed: " + r;
        }

        /// <summary>
        /// Waits for the RESULT line of a process. While it waits it reads the CE's CE-RESULT line. A CE that stopped with a code ending
        /// _NOT_BUILT (for example CE_LINK_NOT_BUILT) means the product is missing a part, so this throws NOT RUN PRODUCT_MISSING at once
        /// and not after the full wait. Returns null on timeout.
        /// </summary>
        string WaitOrCeStop(Proc p, string what, Proc ce, int ms)
        {
            return Poll.Until(delegate
            {
                foreach (string l in p.Lines) if (l.StartsWith("RESULT")) return l;
                string cr = CeResultLine(ce);
                if (cr != null)
                {
                    Dictionary<string, object> d = null;
                    try { d = ResultOf(cr); } catch (FormatException) { }
                    string code = d == null ? null : MiniJson.Str(d, "code");
                    if (code != null && code.EndsWith("_NOT_BUILT", StringComparison.Ordinal))
                        throw new NotRunException("PRODUCT_MISSING", "the CE stopped before the " + what + " could finish: " + cr);
                }
                return null;
            }, ms, 100);
        }

        // ---------------------------------------------------------------- the run

        BridgeOutcome Execute()
        {
            BridgeOutcome o = new BridgeOutcome();
            o.Topology = _topology; o.Seed = _seed;
            string hop1Log = Path.Combine(_dir, "hop1.hex"), hop2Log = Path.Combine(_dir, "hop2.hex");
            PkiDir pki = PkiDir.Export(_c, "bridge-pki-" + Path.GetFileName(_dir));

            // bank HSM, then the server end of hop 2
            Proc bankP = StartNode("--role bankhsm --listen 0" + TraceArg("bank") + Seed(1));
            int bank = WaitReady(bankP, "bank HSM");
            Proc serverP = null; GoPeer serverGo = null, gatewayGo = null;
            int server;
            NetSecPki goPki = null;
            if (_topology == Topology.GoReferees)
            {
                goPki = NetSecPki.Prepare(_c, Path.Combine(_dir, "gopki"));
                serverGo = GoPeer.StartListening(_c, "tlspeer", "-mode server -relay 127.0.0.1:" + bank + " -listen 127.0.0.1:0 -groups x25519mlkem768 -cert \"" + goPki.CertPem + "\" -key \"" + goPki.KeyPem + "\"");
                _owned.Add(serverGo);
                server = serverGo.Port;
            }
            else
            {
                serverP = StartNode("--role server --listen 0 --bank " + bank + TraceArg("server") + Seed(2));
                server = WaitReady(serverP, "server");
            }
            // tap 2 sits between gateway and server
            GoPeer tap2 = GoPeer.StartListening(_c, "tap", "-listen 127.0.0.1:0 -to 127.0.0.1:" + server + " -log \"" + hop2Log + "\"" + (_tamper.Hop2Flip ? " -flip-at " + _tamper.Hop2Offset : ""));
            _owned.Add(tap2);

            // the gateway end of hop 1
            Proc gatewayP = null;
            int gateway;
            if (_topology == Topology.GoReferees)
            {
                gatewayGo = GoPeer.StartListening(_c, "gogateway", "-listen 127.0.0.1:0 -host-key \"" + pki.HostKey + "\" -authorized \"" + pki.UserPub + "\" -kex curve25519-sha256 -cipher aes128-ctr -mac hmac-sha2-256 -next 127.0.0.1:" + tap2.Port + " -ca \"" + goPki.RootPem + "\" -server-name localhost -groups x25519mlkem768");
                _owned.Add(gatewayGo);
                gateway = gatewayGo.Port;
            }
            else
            {
                gatewayP = StartNode("--role gateway --listen 0 --server " + tap2.Port + " --link ssh" + (_tamper.EnvelopeFlip ? " --tamper-envelope" : "") + TraceArg("gateway") + Seed(3));
                gateway = WaitReady(gatewayP, "gateway");
            }
            GoPeer tap1 = GoPeer.StartListening(_c, "tap", "-listen 127.0.0.1:0 -to 127.0.0.1:" + gateway + " -log \"" + hop1Log + "\"" + (_tamper.Hop1Flip ? " -flip-at " + _tamper.Hop1Offset : ""));
            _owned.Add(tap1);

            // Windows ssh.exe -L for the forward topology: local port -> tap 1 -> gateway SSH server. The gateway ignores the target the client names.
            int forward = Proc.FreePort();
            if (_topology == Topology.GlassSshExeForward)
            {
                OpenSshKey.RestrictToCurrentUser(pki.UserKey);
                string known = Path.Combine(pki.Dir, "known_hosts");
                File.WriteAllText(known, "");
                Proc sshExe = Proc.Start(Referees.SshExe(_c), "-F NUL -o BatchMode=yes -o UserKnownHostsFile=\"" + known + "\" -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes -i \"" + pki.UserKey + "\" -L " + forward + ":127.0.0.1:1 -N training@127.0.0.1 -p " + tap1.Port);
                _owned.Add(sshExe);
                if (!Net.WaitPort(forward, 30000)) throw new FailException("ssh.exe did not open the local forward on port " + forward + ". Output: " + sshExe.AllOutput);
            }

            // the PIN pad listens. The CE connects to it, then to the gateway side.
            Proc pad = StartNode("--role pinpad --listen 0 --pin 1234 --pan 4111111111111111" + TraceArg("pinpad") + Seed(5));
            int padPort = WaitReady(pad, "PIN pad");

            // the CE exe, built from CF binaries, runs on the desktop CLR
            string ceLink = _topology == Topology.GlassSshExeForward ? "external-forward" : "glass-ssh";
            int ceGateway = _topology == Topology.GlassSshExeForward ? forward : tap1.Port;
            Proc ce = Proc.Start(CeExe, "--pinpad " + padPort + " --gateway " + ceGateway + " --trace-file \"" + Path.Combine(_dir, "ce.ndjson") + "\" --link " + ceLink + " --suite modern" + (_useSeed ? " --seed " + (_seed + 4) : "") + " --pool 25");
            _owned.Add(ce);
            o.CeReady = WaitLine(ce, "CE-READY", 10000, "CE");                      // a CE that stays silent is a failure (CE_DEVICE_SILENT)

            bool tampered = _tamper.Hop1Flip || _tamper.Hop2Flip || _tamper.EnvelopeFlip;
            // The CE is the first process that can stop the flow. Its CE-RESULT line names the stop, so the wait watches it too.
            // A code that ends in _NOT_BUILT means a part of the product is not there yet: that is NOT RUN PRODUCT_MISSING, never a fault of the bank.
            string padResult = WaitOrCeStop(pad, "PIN pad", ce, tampered ? 20000 : 60000);
            if (padResult != null) o.PinPad = ResultOf(padResult);
            else if (!tampered) throw new FailException("PIN pad printed no RESULT line. " + CeSummary(ce) + " PIN pad output: " + pad.AllOutput);

            // the bank ends the lab. A tamper that stops the flow gets a shorter wait.
            string bankResult = WaitOrCeStop(bankP, "bank HSM", ce, tampered ? 20000 : 60000);
            if (bankResult != null) o.Bank = ResultOf(bankResult);
            else if (!(_tamper.Hop1Flip || _tamper.Hop2Flip)) throw new FailException("bank HSM printed no RESULT line. " + CeSummary(ce) + " Bank output: " + bankP.AllOutput);
            SettleLogs(hop1Log, hop2Log, tampered);                                  // wait for the last trace lines and tap records, not for a fixed time

            List<string> unparsed = new List<string>();
            List<TraceLine> lines = new List<TraceLine>();
            foreach (string name in new string[] { "ce", "pinpad", "gateway", "server", "bank" })
                lines.AddRange(TraceFile.ReadAll(Path.Combine(_dir, name + ".ndjson"), unparsed));
            o.Trace = lines.ToArray();
            o.Hop1 = File.Exists(hop1Log) ? TapLog.Read(hop1Log) : new TapLog();
            o.Hop2 = File.Exists(hop2Log) ? TapLog.Read(hop2Log) : new TapLog();
            o.Output["bank"] = bankP.AllOutput; o.Output["ce"] = ce.AllOutput; o.Output["pinpad"] = pad.AllOutput;
            if (gatewayP != null) o.Output["gateway"] = gatewayP.AllOutput;
            if (serverP != null) o.Output["server"] = serverP.AllOutput;
            if (gatewayGo != null) o.Output["gogateway"] = gatewayGo.Output;
            if (serverGo != null) o.Output["tlspeer"] = serverGo.Output;
            string ksn = o.PinPad != null ? MiniJson.Str(o.PinPad, "ksn") : null;
            if (ksn != null) o.Ksn = Hex.Decode(ksn);
            foreach (TraceLine t in o.Trace) if (!string.IsNullOrEmpty(t.TraceId)) { o.TraceId = t.TraceId; break; }
            if (unparsed.Count > 0) o.Output["unparsed-trace-lines"] = string.Join("\n", unparsed.ToArray());
            return o;
        }
    }

    /// <summary>Keys and certificates for the Go referee topology. The Go tlspeer needs a certificate the Go gateway trusts, made with OpenSSL.</summary>
    public sealed class NetSecPki
    {
        public string RootPem, CertPem, KeyPem;

        public static NetSecPki Prepare(Ctx c, string dir)
        {
            Directory.CreateDirectory(dir);
            // The Go-referee topology uses gogateway as the TLS client, so its trust anchor is a CA that the suite makes with OpenSSL itself.
            string openssl = Referees.OpenSsl(c);
            NetSecPki p = new NetSecPki();
            string caKey = Path.Combine(dir, "ca.key");
            p.RootPem = Path.Combine(dir, "root.pem");
            p.KeyPem = Path.Combine(dir, "srv.key");
            p.CertPem = Path.Combine(dir, "srv.pem");
            string csr = Path.Combine(dir, "srv.csr"), ext = Path.Combine(dir, "ext.cnf");
            File.WriteAllText(ext, "subjectAltName=DNS:localhost\n");
            Run(openssl, "genpkey -algorithm ed25519 -out \"" + caKey + "\"", dir);
            Run(openssl, "req -new -x509 -key \"" + caKey + "\" -subj \"/CN=Acceptance Go-topology CA\" -days 2 -out \"" + p.RootPem + "\"", dir);
            Run(openssl, "genpkey -algorithm ed25519 -out \"" + p.KeyPem + "\"", dir);
            Run(openssl, "req -new -key \"" + p.KeyPem + "\" -subj \"/CN=localhost\" -out \"" + csr + "\"", dir);
            Run(openssl, "x509 -req -in \"" + csr + "\" -CA \"" + p.RootPem + "\" -CAkey \"" + caKey + "\" -CAcreateserial -days 2 -extfile \"" + ext + "\" -out \"" + p.CertPem + "\"", dir);
            return p;
        }

        static void Run(string exe, string args, string dir)
        {
            string output;
            int code = Proc.Run(exe, args, dir, 60000, out output);
            if (code != 0) throw new FailException(exe + " " + args + " exited " + code + ": " + output);
        }
    }
}
