using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Acceptance
{
    /// <summary>
    /// Finds referee programs and talks to the .NET 10 BCL oracle. run.ps1 builds the referees from acceptance/referees
    /// and passes their paths as --prop referee.bcl=... and --prop referee.go=... A missing referee is NOT RUN by name.
    /// The command lines and output lines are in acceptance/referees/README.md (written by the referee author).
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

        /// <summary>ssh-keygen.exe from the same OpenSSH folder as ssh.exe.</summary>
        public static string SshKeygen(Ctx c)
        {
            string path = Path.Combine(Path.GetDirectoryName(SshExe(c)), "ssh-keygen.exe");
            if (!File.Exists(path)) throw new NotRunException("REFEREE_MISSING", "ssh-keygen.exe not found at " + path);
            return path;
        }
    }

    /// <summary>
    /// A Go referee program (tlspeer, sshpeer, gogateway, tap, tokenverify). A server prints its port as the first stdout line.
    /// Every later stdout line is one JSON object with an "event" field. A failure is {"event":"error","code":"..."}.
    /// </summary>
    public sealed class GoPeer : IDisposable
    {
        public readonly Proc P;
        public int Port;
        public string Tool;
        GoPeer(Proc p, string tool) { P = p; Tool = tool; }

        /// <summary>Starts a program that listens, and waits for the port line.</summary>
        public static GoPeer StartListening(Ctx c, string tool, string args)
        {
            GoPeer g = Start(c, tool, args);
            string line = g.P.WaitForLine(delegate (string s) { return s.Trim().Length > 0 && s.Trim().Length <= 5 && IsDigits(s.Trim()); }, 30000);
            if (line == null) { string o = g.P.AllOutput; g.Dispose(); throw new FailException(tool + " did not print its port as the first line within 30 s. Output: " + o); }
            g.Port = int.Parse(line.Trim());
            return g;
        }

        static bool IsDigits(string s) { foreach (char ch in s) if (ch < '0' || ch > '9') return false; return true; }

        public static GoPeer Start(Ctx c, string tool, string args)
        {
            return new GoPeer(Proc.Start(Referees.GoTool(c, tool), args), tool);
        }

        public string Output { get { return P.AllOutput; } }

        /// <summary>Every JSON event line printed so far.</summary>
        public List<Dictionary<string, object>> Events()
        {
            List<Dictionary<string, object>> r = new List<Dictionary<string, object>>();
            foreach (string l in P.Lines)
            {
                string t = l.Trim();
                if (!t.StartsWith("{")) continue;
                try { Dictionary<string, object> d = MiniJson.AsObject(MiniJson.Parse(t)); if (d != null) r.Add(d); } catch (FormatException) { }
            }
            return r;
        }

        /// <summary>Waits for the first event with this name. Returns null on timeout.</summary>
        public Dictionary<string, object> WaitEvent(string name, int timeoutMs)
        {
            return Poll.Until(delegate
            {
                foreach (Dictionary<string, object> d in Events()) if (MiniJson.Str(d, "event") == name) return d;
                return null;
            }, timeoutMs, 50);
        }

        /// <summary>The code of the first error event, or null.</summary>
        public string ErrorCode
        {
            get { foreach (Dictionary<string, object> d in Events()) if (MiniJson.Str(d, "event") == "error") return MiniJson.Str(d, "code"); return null; }
        }

        public void Dispose() { P.Dispose(); }
    }

    /// <summary>
    /// The .NET 10 BCL oracle. One JSON request per line on stdin, one JSON reply per line on stdout.
    /// Byte values are lowercase hex. Operations and fields: acceptance/referees/README.md, "BCL oracle".
    /// </summary>
    public sealed class BclOracle : IDisposable
    {
        readonly Proc _p;
        int _id;
        BclOracle(Proc p) { _p = p; }

        public static BclOracle Start(Ctx c)
        {
            string target = c.Prop("referee.bcl", "");
            if (target.Length == 0 || !File.Exists(target))
                throw new NotRunException("REFEREE_MISSING", "BCL oracle (acceptance/referees/bcl) not built; referee.bcl=" + target);
            Proc p = target.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                ? Proc.Start("dotnet", "\"" + target + "\"")
                : Proc.Start(target, "");
            BclOracle o = new BclOracle(p);
            Dictionary<string, object> info = o.Request("info");
            if (info == null || !(info.ContainsKey("ok") && info["ok"] is bool && (bool)info["ok"]))
            {
                string got = p.AllOutput; p.Dispose();
                throw new NotRunException("REFEREE_PROTOCOL", "BCL oracle did not answer {\"op\":\"info\"} with ok:true. Output: " + got);
            }
            return o;
        }

        static string J(string s)
        {
            StringBuilder sb = new StringBuilder("\"");
            foreach (char ch in s)
            {
                if (ch == '"' || ch == '\\') sb.Append('\\').Append(ch); else sb.Append(ch);
            }
            return sb.Append('"').ToString();
        }

        /// <summary>Sends one request (op, then key and value pairs; a byte[] is sent as hex, an int as a number). Returns the reply object.</summary>
        public Dictionary<string, object> Request(string op, params object[] kv)
        {
            int id = ++_id;
            StringBuilder sb = new StringBuilder("{\"id\":").Append(id).Append(",\"op\":").Append(J(op));
            for (int i = 0; i + 1 < kv.Length; i += 2)
            {
                sb.Append(',').Append(J((string)kv[i])).Append(':');
                object v = kv[i + 1];
                if (v is byte[]) sb.Append(J(Hex.Encode((byte[])v)));
                else if (v is int) sb.Append((int)v);
                else sb.Append(J((string)v));
            }
            sb.Append('}');
            _p.WriteLine(sb.ToString());
            string reply = _p.NextLine(delegate (string s) { return s.TrimStart().StartsWith("{"); }, 60000);
            if (reply == null) throw new FailException("BCL oracle gave no reply to '" + op + "'");
            return MiniJson.AsObject(MiniJson.Parse(reply));
        }

        public bool LastOk;
        public string LastCode;

        /// <summary>Calls an op and returns the named result field as bytes. A reply with ok:false throws, unless allowFail is true (then null and LastCode is set).</summary>
        public byte[] Bytes(string field, string op, bool allowFail, params object[] kv)
        {
            Dictionary<string, object> r = Request(op, kv);
            object ok;
            LastOk = r.TryGetValue("ok", out ok) && ok is bool && (bool)ok;
            LastCode = MiniJson.Str(r, "error") ?? MiniJson.Str(r, "code");
            if (!LastOk)
            {
                if (allowFail) return null;
                throw new FailException("BCL oracle error for " + op + ": " + (LastCode ?? "?") + " " + MiniJson.Str(r, "detail"));
            }
            string hx = MiniJson.Str(r, field);
            if (hx == null) throw new FailException("BCL oracle reply to " + op + " has no field " + field);
            return hx.Length == 0 ? new byte[0] : Hex.Decode(hx);
        }

        public byte[] Bytes(string field, string op, params object[] kv) { return Bytes(field, op, false, kv); }

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
