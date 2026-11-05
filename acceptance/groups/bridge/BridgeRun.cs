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
    }

    /// <summary>
    /// Starts the lab processes from outside, as program-design.md section 9 describes: nodes behind two tap relays, the CE exe,
    /// a wait for CE-READY, then the PIN pad. Nothing here links against NetSec.Core. The command lines the suite needs from the
    /// builders are in acceptance/CONTRACT.md (section "Process contract").
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
        TraceCollector _traces;

        BridgeRun(Ctx c, Topology t, Tamper tamper, ulong seed, bool useSeed, string name)
        {
            _c = c; _topology = t; _tamper = tamper; _seed = seed; _useSeed = useSeed;
            _dir = LivePkiDir(c, name);
        }

        static string LivePkiDir(Ctx c, string name)
        {
            string d = Path.Combine(c.WorkDir, name);
            Directory.CreateDirectory(d);
            return d;
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

        string NodeDll { get { string p = _c.Prop("node", ""); if (p.Length == 0 || !File.Exists(p)) throw new NotRunException("PRODUCT_MISSING", "NetSec.Node is not built (node=" + p + ")"); return p; } }
        string CeExe { get { string p = _c.Prop("ce", ""); if (p.Length == 0 || !File.Exists(p)) throw new NotRunException("PRODUCT_MISSING", "NetSec.CeDevice.exe is not built (ce=" + p + ")"); return p; } }

        Proc StartNode(string args)
        {
            Proc p = Proc.Start("dotnet", "\"" + NodeDll + "\" " + args);
            _owned.Add(p);
            return p;
        }

        string Seed(int salt) { return _useSeed ? " --seed " + (_seed + (ulong)salt) : ""; }

        static string WaitLine(Proc p, string startsWith, int ms, string what)
        {
            string line = p.WaitForLine(delegate (string l) { return l.StartsWith(startsWith); }, ms);
            if (line == null) throw new FailException(what + " did not print '" + startsWith + "' within " + ms + " ms. Output: " + p.AllOutput);
            return line;
        }

        // ---------------------------------------------------------------- the run

        BridgeOutcome Execute()
        {
            BridgeOutcome o = new BridgeOutcome();
            o.Topology = _topology; o.Seed = _seed;
            o.TraceId = "acc-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            _traces = new TraceCollector();
            _owned.Add(_traces);
            int bank = Proc.FreePort(), server = Proc.FreePort(), gateway = Proc.FreePort(), cePort = Proc.FreePort();
            int h1 = Proc.FreePort(), h2 = Proc.FreePort(), plain = Proc.FreePort(), forward = Proc.FreePort();
            string common = " --trace-port " + _traces.Port + " --trace-id " + o.TraceId;
            string hop1Log = Path.Combine(_dir, "hop1.hex"), hop2Log = Path.Combine(_dir, "hop2.hex");

            string pki = Path.Combine(_dir, "pki");
            Directory.CreateDirectory(pki);
            NetSecPki goPki = null;

            // bank HSM, then the server end of hop 2
            Proc bankP = StartNode("--role bankhsm --listen " + bank + common + Seed(1));
            WaitLine(bankP, "NODE-READY", 60000, "bank HSM");
            Proc serverP = null; GoPeer serverGo = null, gatewayGo = null;
            if (_topology == Topology.GoReferees)
            {
                goPki = NetSecPki.Prepare(_c, pki);
                serverGo = GoPeer.StartListening(_c, "tlspeer", "-mode server -relay 127.0.0.1:" + bank + " -listen 127.0.0.1:" + server + " -groups x25519mlkem768 -cert \"" + goPki.CertPem + "\" -key \"" + goPki.KeyPem + "\"");
                _owned.Add(serverGo);
            }
            else
            {
                serverP = StartNode("--role server --listen " + server + " --bank-port " + bank + common + Seed(2));
                WaitLine(serverP, "NODE-READY", 60000, "server");
            }
            // tap 2 sits between gateway and server
            GoPeer tap2 = GoPeer.StartListening(_c, "tap", "-listen 127.0.0.1:" + h2 + " -to 127.0.0.1:" + server + " -log \"" + hop2Log + "\"" + (_tamper.Hop2Flip ? " -flip-at " + _tamper.Hop2Offset : ""));
            _owned.Add(tap2);

            // the gateway end of hop 1
            Proc gatewayP = null;
            string link = _topology == Topology.GlassSshExeForward ? "external-forward" : "glass-ssh";
            if (_topology == Topology.GoReferees)
            {
                string hostKey = Path.Combine(pki, "host_ed25519"), authorized = Path.Combine(pki, "user.pub");
                NodeKeys.WriteSshKey(NodeDll, "ssh-host-ed25519", hostKey, null);
                NodeKeys.WriteSshKey(NodeDll, "ssh-client", null, authorized);
                gatewayGo = GoPeer.StartListening(_c, "gogateway", "-listen 127.0.0.1:" + gateway + " -host-key \"" + hostKey + "\" -authorized \"" + authorized + "\" -kex curve25519-sha256 -cipher aes128-ctr -mac hmac-sha2-256 -upstream 127.0.0.1:" + h2 + " -upstream-ca \"" + goPki.RootPem + "\" -upstream-name localhost -groups x25519mlkem768");
                _owned.Add(gatewayGo);
            }
            else
            {
                gatewayP = StartNode("--role gateway --listen " + gateway + " --server-port " + h2 + " --link " + link + " --suite modern" + (_topology == Topology.GlassSshExeForward ? " --plain-listen " + plain : "") + (_tamper.EnvelopeFlip ? " --tamper-envelope" : "") + common + Seed(3));
                WaitLine(gatewayP, "NODE-READY", 60000, "gateway");
            }
            GoPeer tap1 = GoPeer.StartListening(_c, "tap", "-listen 127.0.0.1:" + h1 + " -to 127.0.0.1:" + gateway + " -log \"" + hop1Log + "\"" + (_tamper.Hop1Flip ? " -flip-at " + _tamper.Hop1Offset : ""));
            _owned.Add(tap1);

            // Windows ssh.exe -L for the forward topology: local port forward -> tap 1 -> gateway SSH server -> gateway plain port
            Proc sshExe = null;
            if (_topology == Topology.GlassSshExeForward)
            {
                string clientKey = Path.Combine(pki, "ssh_client");
                NodeKeys.WriteSshKey(NodeDll, "ssh-client", clientKey, null);
                OpenSshKey.RestrictToCurrentUser(clientKey);
                string known = Path.Combine(pki, "known_hosts");
                File.WriteAllText(known, "");
                sshExe = Proc.Start(Referees.SshExe(_c), "-F NUL -o BatchMode=yes -o UserKnownHostsFile=\"" + known + "\" -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes -i \"" + clientKey + "\" -L " + forward + ":127.0.0.1:" + plain + " -N training@127.0.0.1 -p " + h1);
                _owned.Add(sshExe);
                if (!Net.WaitPort(forward, 30000)) throw new FailException("ssh.exe did not open the local forward on port " + forward + ". Output: " + sshExe.AllOutput);
            }

            // the CE exe, built from CF binaries, runs on the desktop CLR
            string ceLink = _topology == Topology.GlassSshExeForward ? "external-forward" : "glass-ssh";
            int ceGateway = _topology == Topology.GlassSshExeForward ? forward : h1;
            Proc ce = Proc.Start(CeExe, "--pinpad " + cePort + " --gateway " + ceGateway + " --trace " + _traces.Port + " --trace-id " + o.TraceId + " --link " + ceLink + " --suite modern" + (_useSeed ? " --seed " + (_seed + 4) : "") + " --pool 25");
            _owned.Add(ce);
            o.CeReady = WaitLine(ce, "CE-READY", 10000, "CE");                      // a CE that stays silent is a failure (CE_DEVICE_SILENT)

            // the PIN pad starts the sale
            Proc pad = StartNode("--role pinpad --ce-port " + cePort + " --pin 1234 --pan 4111111111111111 --sales 1" + common + Seed(5));
            string padResult = WaitLine(pad, "PINPAD-RESULT", 60000, "PIN pad");
            o.PinPad = MiniJson.AsObject(MiniJson.Parse(padResult.Substring("PINPAD-RESULT".Length).Trim()));

            // the bank ends the lab: it prints one result per envelope, ok or not. A tamper that stops the flow gets a shorter wait.
            string bankResult = bankP.WaitForLine(delegate (string l) { return l.StartsWith("BANK-RESULT"); }, (_tamper.Hop1Flip || _tamper.Hop2Flip || _tamper.EnvelopeFlip) ? 20000 : 60000);
            if (bankResult != null) o.Bank = MiniJson.AsObject(MiniJson.Parse(bankResult.Substring("BANK-RESULT".Length).Trim()));
            else if (!(_tamper.Hop1Flip || _tamper.Hop2Flip)) throw new FailException("bank HSM printed no BANK-RESULT. Bank output: " + bankP.AllOutput);
            Thread.Sleep(1200);                                                     // let the last trace lines and the tap logs land

            o.Trace = _traces.Lines;
            o.Hop1 = File.Exists(hop1Log) ? TapLog.Read(hop1Log) : new TapLog();
            o.Hop2 = File.Exists(hop2Log) ? TapLog.Read(hop2Log) : new TapLog();
            o.Output["bank"] = bankP.AllOutput; o.Output["ce"] = ce.AllOutput; o.Output["pinpad"] = pad.AllOutput;
            if (gatewayP != null) o.Output["gateway"] = gatewayP.AllOutput;
            if (serverP != null) o.Output["server"] = serverP.AllOutput;
            if (gatewayGo != null) o.Output["gogateway"] = gatewayGo.Output;
            if (serverGo != null) o.Output["tlspeer"] = serverGo.Output;
            string ksn = o.PinPad != null && o.PinPad.ContainsKey("ksn") ? o.PinPad["ksn"] as string : null;
            if (ksn != null) o.Ksn = Hex.Decode(ksn);
            if (_traces.Unparsed.Length > 0) o.Output["unparsed-trace-lines"] = string.Join("\n", _traces.Unparsed);
            return o;
        }
    }

    /// <summary>Keys and certificates for the Go referee topology. The Go tlspeer needs a certificate the glass gateway trusts.</summary>
    public sealed class NetSecPki
    {
        public string RootPem, CertPem, KeyPem;
        /// <summary>Uses acceptance/lib/Live in no way: this group links no product code. The CA root and the leaf come from the Node executable.</summary>
        public static NetSecPki Prepare(Ctx c, string dir)
        {
            // The gateway under test is OUR glass TLS client in some runs and a Go client in others. The Go-referee topology uses
            // gogateway as the TLS client, so its trust anchor is a CA that the suite makes with OpenSSL itself.
            string openssl = Referees.OpenSsl(c);
            NetSecPki p = new NetSecPki();
            string caKey = Path.Combine(dir, "ca.key");
            p.RootPem = Path.Combine(dir, "root.pem");
            p.KeyPem = Path.Combine(dir, "srv.key");
            p.CertPem = Path.Combine(dir, "srv.pem");
            string csr = Path.Combine(dir, "srv.csr"), ext = Path.Combine(dir, "ext.cnf"), o;
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

    /// <summary>
    /// Training keys, read from the product's Node executable so this group links no product code. Process contract:
    /// `NetSec.Node --print-training-key &lt;keyId&gt;` prints "material &lt;hex&gt;" (the bytes ITrainingKey.CopyMaterial returns) and,
    /// for asymmetric keys, "public &lt;hex&gt;" (CopyPublic). Key ids are the KeyIds values.
    /// </summary>
    static class NodeKeys
    {
        public static void Print(string nodeDll, string keyId, out byte[] material, out byte[] pub)
        {
            string output;
            int code = Proc.Run("dotnet", "\"" + nodeDll + "\" --print-training-key " + keyId, null, 60000, out output);
            if (code != 0) throw new NotRunException("PRODUCT_MISSING", "NetSec.Node --print-training-key " + keyId + " exited " + code + ": " + output.Trim());
            Match s = Regex.Match(output, @"(?m)^material ([0-9a-f]+)\s*$"), p = Regex.Match(output, @"(?m)^public ([0-9a-f]+)\s*$");
            if (!s.Success) throw new FailException("--print-training-key " + keyId + " must print 'material <hex>'. Output: " + output.Trim());
            material = Hex.Decode(s.Groups[1].Value);
            pub = p.Success ? Hex.Decode(p.Groups[1].Value) : null;
        }

        /// <summary>Writes the OpenSSH private key file and the authorized_keys line for one Ed25519 training key.</summary>
        public static void WriteSshKey(string nodeDll, string keyId, string privatePath, string publicPath)
        {
            byte[] seed, pub;
            Print(nodeDll, keyId, out seed, out pub);
            if (pub == null) throw new FailException("--print-training-key " + keyId + " printed no 'public' line, and an SSH key needs one");
            if (privatePath != null) File.WriteAllText(privatePath, OpenSshKey.PrivatePem(seed, pub, keyId));
            if (publicPath != null) File.WriteAllText(publicPath, OpenSshKey.AuthorizedLine(pub, keyId));
        }
    }
}
