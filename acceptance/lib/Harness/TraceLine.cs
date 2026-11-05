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
    /// <summary>The NDJSON file a lab process writes with --trace-file (design section 11). One trace object per line.</summary>
    public static class TraceFile
    {
        public static TraceLine[] ReadAll(string path, List<string> unparsed)
        {
            List<TraceLine> r = new List<TraceLine>();
            if (!File.Exists(path)) return r.ToArray();
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (line.Trim().Length == 0) continue;
                    try { r.Add(TraceLine.Parse(line)); }
                    catch (Exception ex) { if (unparsed != null) unparsed.Add(Path.GetFileName(path) + ": " + ex.Message + ": " + line.Substring(0, Math.Min(80, line.Length))); }
                }
            }
            return r.ToArray();
        }
    }
}
