using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Acceptance
{
    /// <summary>A child process with captured output. Used to run referees and to build things from outside the code under test.</summary>
    public sealed class Proc : IDisposable
    {
        readonly Process _p;
        readonly List<string> _lines = new List<string>();
        readonly object _gate = new object();
        public string Name;

        Proc(Process p, string name) { _p = p; Name = name; }

        public static Proc Start(string exe, string args, string workDir, IDictionary<string, string> env)
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.RedirectStandardInput = true;
            psi.CreateNoWindow = true;
            if (!string.IsNullOrEmpty(workDir)) psi.WorkingDirectory = workDir;
            if (env != null)
                foreach (KeyValuePair<string, string> kv in env) psi.EnvironmentVariables[kv.Key] = kv.Value;
            Process p = new Process();
            p.StartInfo = psi;
            Proc me = new Proc(p, Path.GetFileName(exe));
            p.OutputDataReceived += delegate (object s, DataReceivedEventArgs e) { if (e.Data != null) me.Add(e.Data); };
            p.ErrorDataReceived += delegate (object s, DataReceivedEventArgs e) { if (e.Data != null) me.Add(e.Data); };
            try { p.Start(); }
            catch (Exception ex) { throw new NotRunException("EXECUTABLE_MISSING", exe + ": " + ex.Message); }
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            return me;
        }

        public static Proc Start(string exe, string args) { return Start(exe, args, null, null); }

        void Add(string line) { lock (_gate) { _lines.Add(line); Monitor.PulseAll(_gate); } }

        public string[] Lines { get { lock (_gate) { return _lines.ToArray(); } } }
        public string AllOutput { get { return string.Join("\n", Lines); } }
        public int Pid { get { return _p.Id; } }
        public bool HasExited { get { return _p.HasExited; } }
        public int ExitCode { get { return _p.ExitCode; } }

        int _cursor;

        /// <summary>
        /// Waits for the next output line that satisfies the test, starting after the last line this method returned.
        /// WaitForLine always scans from the first line, so a request and reply protocol needs this one.
        /// </summary>
        public string NextLine(Predicate<string> test, int timeoutMs)
        {
            DateTime end = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            lock (_gate)
            {
                while (true)
                {
                    while (_cursor < _lines.Count)
                    {
                        string ln = _lines[_cursor++];
                        if (test(ln)) return ln;
                    }
                    double left = (end - DateTime.UtcNow).TotalMilliseconds;
                    if (left <= 0) return null;
                    Monitor.Wait(_gate, (int)Math.Min(left, 200));
                }
            }
        }

        /// <summary>Waits for an output line that satisfies the test. Returns null on timeout.</summary>
        public string WaitForLine(Predicate<string> test, int timeoutMs)
        {
            DateTime end = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            int seen = 0;
            lock (_gate)
            {
                while (true)
                {
                    while (seen < _lines.Count)
                    {
                        string ln = _lines[seen++];
                        if (test(ln)) return ln;
                    }
                    if (_p.HasExited && seen >= _lines.Count) { Monitor.Wait(_gate, 100); if (seen >= _lines.Count) return null; }
                    double left = (end - DateTime.UtcNow).TotalMilliseconds;
                    if (left <= 0) return null;
                    Monitor.Wait(_gate, (int)Math.Min(left, 200));
                }
            }
        }

        public void WriteLine(string s) { _p.StandardInput.WriteLine(s); _p.StandardInput.Flush(); }
        public void CloseInput() { try { _p.StandardInput.Close(); } catch (IOException) { } }

        public bool WaitExit(int ms) { return _p.WaitForExit(ms); }

        public void Kill()
        {
            try
            {
                if (!_p.HasExited)
                {
                    // taskkill /T ends the tree. Process.Kill(bool) does not exist on net48.
                    Process k = Process.Start(new ProcessStartInfo("taskkill", "/T /F /PID " + _p.Id) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true });
                    k.WaitForExit(5000);
                }
            }
            catch (Exception) { }
        }

        public void Dispose() { Kill(); _p.Dispose(); }

        /// <summary>Runs a command to completion and returns its exit code and output.</summary>
        public static int Run(string exe, string args, string workDir, int timeoutMs, out string output)
        {
            using (Proc p = Start(exe, args, workDir, null))
            {
                p.CloseInput();
                if (!p.WaitExit(timeoutMs)) { output = p.AllOutput + "\n<timeout after " + timeoutMs + " ms>"; return -999; }
                p._p.WaitForExit();            // flush async readers
                Thread.Sleep(50);
                output = p.AllOutput;
                return p._p.ExitCode;
            }
        }

        public static int FreePort()
        {
            TcpListener l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            int port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }
    }

    /// <summary>Plain-socket helpers for tests that talk to a listening port.</summary>
    public static class Net
    {
        public static bool WaitPort(int port, int timeoutMs)
        {
            DateTime end = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            while (DateTime.UtcNow < end)
            {
                try
                {
                    using (TcpClient c = new TcpClient())
                    {
                        IAsyncResult ar = c.BeginConnect(IPAddress.Loopback, port, null, null);
                        if (ar.AsyncWaitHandle.WaitOne(300) && c.Connected) { c.EndConnect(ar); return true; }
                    }
                }
                catch (SocketException) { }
                Thread.Sleep(50);
            }
            return false;
        }
    }
}
