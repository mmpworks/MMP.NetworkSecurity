using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Acceptance
{
    public sealed class TraceSecretLine { public string Holder, Name; public byte[] Bytes; }

    /// <summary>One NDJSON trace line from a node. Field names follow ux-design.md section 0 and program-design.md section 2.1.</summary>
    public sealed class TraceLine
    {
        public string Json, Actor, Type, From, To, TraceId, Hop, Message, StreamId, CheckResult, CheckCode, CheckName;
        public long StreamSeq;
        public byte[] Wire, Plain;
        public List<TraceSecretLine> Secrets = new List<TraceSecretLine>();

        public static TraceLine Parse(string json)
        {
            Dictionary<string, object> d = MiniJson.AsObject(MiniJson.Parse(json));
            if (d == null) throw new FormatException("trace line is not a JSON object");
            TraceLine t = new TraceLine();
            t.Json = json;
            t.Actor = MiniJson.Str(d, "actor"); t.Type = MiniJson.Str(d, "type"); t.From = MiniJson.Str(d, "from"); t.To = MiniJson.Str(d, "to");
            t.TraceId = MiniJson.Str(d, "traceId"); t.Hop = MiniJson.Str(d, "hop"); t.Message = MiniJson.Str(d, "message"); t.StreamId = MiniJson.Str(d, "streamId");
            object sq; if (d.TryGetValue("streamSeq", out sq) && sq is double) t.StreamSeq = (long)(double)sq;
            string w = MiniJson.Str(d, "wire"), p = MiniJson.Str(d, "plain");
            t.Wire = string.IsNullOrEmpty(w) ? new byte[0] : Hex.Decode(w);
            t.Plain = string.IsNullOrEmpty(p) ? new byte[0] : Hex.Decode(p);
            Dictionary<string, object> chk = MiniJson.Obj(d, "check");
            if (chk != null) { t.CheckResult = MiniJson.Str(chk, "result"); t.CheckCode = MiniJson.Str(chk, "code"); t.CheckName = MiniJson.Str(chk, "name"); }
            List<object> secs = MiniJson.Arr(d, "secrets");
            if (secs != null)
                foreach (object o in secs)
                {
                    Dictionary<string, object> sd = MiniJson.AsObject(o);
                    if (sd == null) continue;
                    TraceSecretLine sl = new TraceSecretLine();
                    sl.Holder = MiniJson.Str(sd, "holder"); sl.Name = MiniJson.Str(sd, "name");
                    string hx = MiniJson.Str(sd, "hex");
                    sl.Bytes = string.IsNullOrEmpty(hx) ? new byte[0] : Hex.Decode(hx);
                    t.Secrets.Add(sl);
                }
            return t;
        }
    }

    /// <summary>A TCP listener that the lab processes send their NDJSON trace to (the --trace port of CeDevice and Node).</summary>
    public sealed class TraceCollector : IDisposable
    {
        readonly TcpListener _l;
        readonly Thread _t;
        readonly List<TraceLine> _lines = new List<TraceLine>();
        readonly List<string> _bad = new List<string>();
        volatile bool _stop;
        public int Port;

        public TraceCollector()
        {
            _l = new TcpListener(IPAddress.Loopback, 0);
            _l.Start();
            Port = ((IPEndPoint)_l.LocalEndpoint).Port;
            _t = new Thread(Accept);
            _t.IsBackground = true;
            _t.Start();
        }

        void Accept()
        {
            while (!_stop)
            {
                TcpClient c;
                try { c = _l.AcceptTcpClient(); } catch (SocketException) { return; } catch (ObjectDisposedException) { return; }
                Thread r = new Thread(delegate ()
                {
                    using (c)
                    using (StreamReader sr = new StreamReader(c.GetStream(), Encoding.UTF8))
                    {
                        string line;
                        try
                        {
                            while ((line = sr.ReadLine()) != null)
                            {
                                if (line.Trim().Length == 0) continue;
                                try { TraceLine tl = TraceLine.Parse(line); lock (_lines) { _lines.Add(tl); } }
                                catch (Exception ex) { lock (_bad) { _bad.Add(ex.Message + ": " + line.Substring(0, Math.Min(80, line.Length))); } }
                            }
                        }
                        catch (IOException) { }
                    }
                });
                r.IsBackground = true;
                r.Start();
            }
        }

        public TraceLine[] Lines { get { lock (_lines) { return _lines.ToArray(); } } }
        public string[] Unparsed { get { lock (_bad) { return _bad.ToArray(); } } }

        public bool WaitFor(Predicate<TraceLine> test, int timeoutMs)
        {
            DateTime end = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            while (DateTime.UtcNow < end)
            {
                foreach (TraceLine t in Lines) if (test(t)) return true;
                Thread.Sleep(50);
            }
            return false;
        }

        public void Dispose() { _stop = true; try { _l.Stop(); } catch (SocketException) { } }
    }
}
