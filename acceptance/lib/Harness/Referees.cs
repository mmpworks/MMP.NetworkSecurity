using System;
using System.Collections.Generic;
using System.IO;

namespace Acceptance
{
    /// <summary>
    /// Finds referee programs and talks to the .NET 10 BCL oracle. run.ps1 builds the referees from acceptance/referees
    /// and passes their paths as --prop referee.bcl=... and --prop referee.go=... A missing referee is NOT RUN by name.
    /// See acceptance/referee-contract.md for the command lines and output lines this code expects.
    /// </summary>
    public static class Referees
    {
        public static string GoTool(Ctx c, string name)
        {
            string dir = c.Prop("referee.go", Path.Combine(c.AcceptanceDir, "referees", "go", "bin"));
            string path = Path.Combine(dir, name + ".exe");
            if (!File.Exists(path)) throw new NotRunException("REFEREE_MISSING", "Go referee " + name + " not found at " + path);
            return path;
        }

        public static string OpenSsl(Ctx c)
        {
            string path = c.Prop("openssl", @"C:\Program Files\Git\mingw64\bin\openssl.exe");
            if (!File.Exists(path)) throw new NotRunException("REFEREE_MISSING", "openssl not found at " + path);
            string output;
            Proc.Run(path, "version", null, 15000, out output);
            if (output.IndexOf("OpenSSL 3.5.7", StringComparison.Ordinal) < 0)
                throw new NotRunException("REFEREE_VERSION", "openssl at " + path + " reports: " + output.Trim());
            return path;
        }

        public static string SshExe(Ctx c)
        {
            string path = c.Prop("ssh", @"C:\Windows\System32\OpenSSH\ssh.exe");
            if (!File.Exists(path)) throw new NotRunException("REFEREE_MISSING", "ssh.exe not found at " + path);
            string output;
            Proc.Run(path, "-V", null, 15000, out output);
            if (output.IndexOf("OpenSSH_for_Windows_9.5p2", StringComparison.Ordinal) < 0)
                throw new NotRunException("REFEREE_VERSION", "ssh.exe reports: " + output.Trim());
            return path;
        }
    }

    /// <summary>
    /// A Go referee program (tlspeer, sshpeer, gogateway, tap, tokenverify). Servers print "LISTEN host:port" once ready.
    /// Other lines are free text, parsed by the clause that started the program. See acceptance/referee-contract.md.
    /// </summary>
    public sealed class GoPeer : IDisposable
    {
        public readonly Proc P;
        public int Port;
        public string Tool;
        GoPeer(Proc p, string tool) { P = p; Tool = tool; }

        /// <summary>Starts a program that listens, and waits for its LISTEN line.</summary>
        public static GoPeer StartListening(Ctx c, string tool, string args)
        {
            GoPeer g = Start(c, tool, args);
            string line = g.P.WaitForLine(delegate (string s) { return s.StartsWith("LISTEN "); }, 30000);
            if (line == null) { string o = g.P.AllOutput; g.Dispose(); throw new FailException(tool + " did not print 'LISTEN host:port' within 30 s. Output: " + o); }
            int colon = line.LastIndexOf(':');
            g.Port = int.Parse(line.Substring(colon + 1).Trim());
            return g;
        }

        public static GoPeer Start(Ctx c, string tool, string args)
        {
            return new GoPeer(Proc.Start(Referees.GoTool(c, tool), args), tool);
        }

        public string Output { get { return P.AllOutput; } }
        public void Dispose() { P.Dispose(); }
    }

    /// <summary>Line oracle over stdin and stdout. Hex arguments, "-" for empty. Reply "OK a b" or "ERR CODE".</summary>
    public sealed class BclOracle : IDisposable
    {
        readonly Proc _p;
        BclOracle(Proc p) { _p = p; }

        public static BclOracle Start(Ctx c)
        {
            string target = c.Prop("referee.bcl", "");
            if (target.Length == 0 || !File.Exists(target))
                throw new NotRunException("REFEREE_MISSING", "BCL oracle (acceptance/referees/bcl) not built; referee.bcl=" + target);
            Proc p = target.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                ? Proc.Start("dotnet", "\"" + target + "\"")
                : Proc.Start(target, "");
            string ready = p.WaitForLine(delegate (string s) { return s.StartsWith("READY"); }, 30000);
            if (ready == null || !ready.StartsWith("READY bcl-oracle/1"))
            {
                string got = ready ?? p.AllOutput;
                p.Dispose();
                throw new NotRunException("REFEREE_PROTOCOL", "BCL oracle did not say 'READY bcl-oracle/1': " + got);
            }
            return new BclOracle(p);
        }

        /// <summary>Sends one request. Returns the reply fields, or null when the oracle replies ERR.</summary>
        public string[] Call(string op, params string[] args)
        {
            string line = op;
            foreach (string a in args) line += " " + (a.Length == 0 ? "-" : a);
            _p.WriteLine(line);
            string reply = _p.NextLine(delegate (string s) { return s.StartsWith("OK") || s.StartsWith("ERR"); }, 60000);
            if (reply == null) throw new FailException("BCL oracle gave no reply to '" + op + "'");
            if (reply.StartsWith("ERR")) { LastError = reply.Length > 4 ? reply.Substring(4) : ""; return null; }
            LastError = null;
            string rest = reply.Length > 3 ? reply.Substring(3).Trim() : "";
            return rest.Length == 0 ? new string[0] : rest.Split(' ');
        }

        public string LastError;

        public byte[] Bytes(string op, params string[] args)
        {
            string[] r = Call(op, args);
            if (r == null) throw new FailException("BCL oracle error for " + op + ": " + LastError);
            return r.Length == 0 || r[0] == "-" ? new byte[0] : Hex.Decode(r[0]);
        }

        public void Dispose() { _p.CloseInput(); _p.Dispose(); }
    }

    /// <summary>A repeatable pseudo-random byte stream for the 10,000-input comparisons. Not cryptographic.</summary>
    public sealed class Rng
    {
        ulong _s0, _s1;
        public Rng(ulong seed)
        {
            _s0 = seed ^ 0x9E3779B97F4A7C15UL; _s1 = (seed << 17) ^ 0xBF58476D1CE4E5B9UL;
            if (_s0 == 0 && _s1 == 0) _s1 = 1;
            for (int i = 0; i < 8; i++) Next();
        }
        public ulong Next()
        {
            ulong s1 = _s0, s0 = _s1;
            _s0 = s0;
            s1 ^= s1 << 23;
            _s1 = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
            return _s1 + s0;
        }
        public int Int(int maxExclusive) { return (int)(Next() % (ulong)maxExclusive); }
        public byte[] Bytes(int n)
        {
            byte[] b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = (byte)(Next() >> 24);
            return b;
        }
    }
}
