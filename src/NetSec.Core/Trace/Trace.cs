using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using NetSec.Bytes;
using NetSec.Platform;

namespace NetSec.Trace
{
    public sealed class TraceField
    {
        public string Name;
        public int Offset;
        public int Length;
        public string Kind;
        public bool VisibleToWire;
        public string Gloss;

        public static TraceField[] From(FieldMark[] marks)
        {
            TraceField[] fields = new TraceField[marks.Length];
            for (int i = 0; i < marks.Length; i++)
            {
                TraceField f = new TraceField();
                f.Name = marks[i].Name; f.Offset = marks[i].Offset; f.Length = marks[i].Length;
                f.Kind = marks[i].Kind; f.VisibleToWire = marks[i].VisibleToWire; f.Gloss = marks[i].Gloss;
                fields[i] = f;
            }
            return fields;
        }
    }

    public sealed class TraceSecret
    {
        public string Holder;
        public string Name;
        public byte[] Bytes;
        public string[] DerivedFrom;
        /// <summary>Set only on a hidden secret, with Bytes null: "fp:" and 16 hex, the byte count, and why it is hidden ("toggle" or "non-exportable").</summary>
        public string Fingerprint;
        public int Length;
        public string Hidden;
    }

    /// <summary>The key a lab runs on, named on the Host's key.in-use event: its security type, version (0 for a built-in key) and provider.</summary>
    public sealed class TraceKeyUse
    {
        public string TypeId;
        public int Version;
        public string Provider;
    }

    public sealed class TraceCheck
    {
        public string Id;
        public string Name;
        public bool Passed;
        public string Code;
        public string Detail;
    }

    /// <summary>The fields a caller chooses. TraceStream adds the identity and the time.</summary>
    public sealed class TraceEventDraft
    {
        public string Type, Message, Step, From, To, WaitingFor, Detail;
        public byte[] Wire, Plain;
        public TraceField[] Fields;
        public TraceSecret[] Secrets;
        public TraceCheck Check;
        public TraceKeyUse KeyUse;

        /// <summary>Names the wire.sent event whose bytes may not have left. It carries no Wire, because only bytes that left carry Wire.</summary>
        public static TraceEventDraft LostWrite(TraceEvent sent, string code)
        {
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = "wire.write.failed"; draft.From = sent.From; draft.To = sent.To; draft.Message = sent.Message;
            draft.Detail = code + ": the write for event " + sent.EventId + " failed, so its bytes may not have left";
            return draft;
        }
    }

    /// <summary>Immutable. Only an event that went over a socket carries Wire, so the Wire fields joined by direction equal the bytes a tap sees.</summary>
    public sealed class TraceEvent
    {
        public const int CurrentSchema = 1;

        public readonly int Schema;
        public readonly string EventId;
        public readonly string StreamId;
        public readonly long StreamSeq;
        public readonly string SessionId, TraceId, Hop;
        public readonly string Actor, From, To;
        public readonly string Type, Message, Step, Detail;
        public readonly byte[] Wire, Plain;
        public readonly TraceField[] Fields;
        public readonly TraceSecret[] Secrets;
        public readonly TraceCheck Check;
        public readonly TraceKeyUse KeyUse;
        public readonly string WaitingFor;
        public readonly long AtMicros;

        internal TraceEvent(TraceStream stream, long seq, long atMicros, TraceEventDraft draft)
        {
            Schema = CurrentSchema;
            StreamId = stream.StreamId;
            StreamSeq = seq;
            EventId = stream.StreamId + "#" + seq;
            SessionId = stream.SessionId; TraceId = stream.TraceId; Hop = stream.Hop; Actor = stream.Actor;
            From = draft.From; To = draft.To; Type = draft.Type; Message = draft.Message; Step = draft.Step; Detail = draft.Detail;
            Wire = Copy(draft.Wire); Plain = Copy(draft.Plain);
            Fields = draft.Fields; Secrets = draft.Secrets; Check = draft.Check; KeyUse = draft.KeyUse;
            WaitingFor = draft.WaitingFor;
            AtMicros = atMicros;
        }

        TraceEvent(TraceEvent e, string traceId, TraceSecret[] secrets)
        {
            Schema = e.Schema; EventId = e.EventId; StreamId = e.StreamId; StreamSeq = e.StreamSeq;
            SessionId = e.SessionId; TraceId = traceId; Hop = e.Hop; Actor = e.Actor;
            From = e.From; To = e.To; Type = e.Type; Message = e.Message; Step = e.Step; Detail = e.Detail;
            Wire = e.Wire; Plain = e.Plain; Fields = e.Fields; Secrets = secrets; Check = e.Check; KeyUse = e.KeyUse;
            WaitingFor = e.WaitingFor; AtMicros = e.AtMicros;
        }

        /// <summary>The same event under a trace id its process learned after it stamped the event.</summary>
        public TraceEvent WithTraceId(string traceId) { return new TraceEvent(this, traceId, Secrets); }

        /// <summary>The same event with other secrets. Everything else, the event id and the stream place too, stays.</summary>
        internal TraceEvent WithSecrets(TraceSecret[] secrets) { return new TraceEvent(this, TraceId, secrets); }

        static byte[] Copy(byte[] bytes)
        {
            return bytes == null ? null : (byte[])bytes.Clone();
        }
    }

    public interface ITraceSink
    {
        void Write(TraceEvent e);
    }

    public sealed class NullSink : ITraceSink
    {
        public void Write(TraceEvent e) { }
    }

    /// <summary>Appends one JSON line per event, and flushes each one, so a killed process still leaves its trace. A lab process owns one for its life.</summary>
    public sealed class NdjsonFileSink : ITraceSink
    {
        readonly StreamWriter _file;

        public NdjsonFileSink(string path)
        {
            if (path == null) throw new ArgumentNullException("path");
            _file = new StreamWriter(path, false, new UTF8Encoding(false));
            _file.AutoFlush = true;
        }

        public void Write(TraceEvent e)
        {
            string line = TraceJson.ToLine(e);
            lock (_file) _file.WriteLine(line);
        }
    }

    public sealed class ListSink : ITraceSink
    {
        readonly List<TraceEvent> _events = new List<TraceEvent>();

        public void Write(TraceEvent e) { lock (_events) _events.Add(e); }

        public TraceEvent[] Events { get { lock (_events) return _events.ToArray(); } }
    }

    /// <summary>One per engine. Stamps stable ids and a per-stream sequence number.</summary>
    public sealed class TraceStream
    {
        public readonly string StreamId, SessionId, TraceId, Hop, Actor;
        readonly IClock _clock;
        readonly object _gate = new object();
        long _nextSeq = 1;

        public TraceStream(string streamId, string sessionId, string traceId, string hop, string actor, IClock clock)
        {
            StreamId = streamId; SessionId = sessionId; TraceId = traceId; Hop = hop; Actor = actor;
            _clock = clock;
        }

        /// <summary>The sequence number the next Stamp gives. A tamper hook addresses a message by this number.</summary>
        public long NextSeq { get { lock (_gate) return _nextSeq; } }

        public TraceEvent Stamp(TraceEventDraft draft)
        {
            long seq;
            lock (_gate) seq = _nextSeq++;
            return new TraceEvent(this, seq, _clock.NowMicros, draft);
        }
    }

    /// <summary>Writes the field names of ux-design.md section 0. One writer for both builds. An absent field is left out.</summary>
    /// <summary>The Show keys boundary (modes-design.md section 6.4). Pure: same input, same output. Rules, engines and labs never call it.</summary>
    public static class TraceRedaction
    {
        public const string HiddenByToggle = "toggle";

        /// <summary>"fp:" and the first 8 bytes of SHA-256, as 16 lowercase hex. Same key, same fingerprint; that is its one job.</summary>
        public static string Fingerprint(byte[] secret)
        {
            NetSec.Crypto.IHash hash = NetSec.Crypto.Hashes.Sha256();
            hash.Update(secret, 0, secret.Length);
            byte[] digest = hash.Finish();
            byte[] head = new byte[8];
            Array.Copy(digest, head, head.Length);
            return "fp:" + Hex.Encode(head);
        }

        /// <summary>A new event in which each secret that holds bytes holds a fingerprint, its length and "toggle" instead. All else stays. The input is not changed.</summary>
        public static TraceEvent Hide(TraceEvent e)
        {
            if (e.Secrets == null) return e;
            TraceSecret[] hidden = new TraceSecret[e.Secrets.Length];
            for (int i = 0; i < hidden.Length; i++) hidden[i] = Hide(e.Secrets[i]);
            return e.WithSecrets(hidden);
        }

        static TraceSecret Hide(TraceSecret s)
        {
            if (s.Bytes == null) return s;
            TraceSecret h = new TraceSecret();
            h.Holder = s.Holder;
            h.Name = s.Name;
            h.DerivedFrom = s.DerivedFrom;
            h.Fingerprint = Fingerprint(s.Bytes);
            h.Length = s.Bytes.Length;
            h.Hidden = HiddenByToggle;
            return h;
        }
    }

    public static class TraceJson
    {
        public static string ToLine(TraceEvent e)
        {
            Writer w = new Writer();
            w.Number("schema", e.Schema);
            w.Text("eventId", e.EventId);
            w.Text("streamId", e.StreamId);
            w.Number("streamSeq", e.StreamSeq);
            w.Text("sessionId", e.SessionId);
            w.Text("traceId", e.TraceId);
            w.Text("hop", e.Hop);
            w.Text("actor", e.Actor);
            w.Text("from", e.From);
            w.Text("to", e.To);
            w.Text("type", e.Type);
            w.Text("message", e.Message);
            w.Text("step", e.Step);
            w.Text("detail", e.Detail);
            w.Bytes("wire", e.Wire);
            w.Bytes("plain", e.Plain);
            w.Raw("fields", FieldsJson(e.Fields));
            w.Raw("secrets", SecretsJson(e.Secrets));
            w.Raw("check", CheckJson(e.Check));
            if (e.KeyUse != null)
            {
                w.Text("typeId", e.KeyUse.TypeId);
                w.Number("version", e.KeyUse.Version);
                w.Text("provider", e.KeyUse.Provider);
            }
            if (e.WaitingFor != null) w.Raw("waiting", "{\"actor\":" + MiniJson.Quote(e.WaitingFor) + "}");
            w.Number("atMicros", e.AtMicros);
            return w.Finish();
        }

        static string FieldsJson(TraceField[] fields)
        {
            if (fields == null) return null;
            string[] items = new string[fields.Length];
            for (int i = 0; i < fields.Length; i++)
            {
                Writer w = new Writer();
                w.Text("name", fields[i].Name);
                w.Number("offset", fields[i].Offset);
                w.Number("length", fields[i].Length);
                w.Text("kind", fields[i].Kind);
                w.Raw("visibleToWire", fields[i].VisibleToWire ? "true" : "false");
                w.Text("gloss", fields[i].Gloss);
                items[i] = w.Finish();
            }
            return "[" + string.Join(",", items) + "]";
        }

        static string SecretsJson(TraceSecret[] secrets)
        {
            if (secrets == null) return null;
            string[] items = new string[secrets.Length];
            for (int i = 0; i < secrets.Length; i++)
            {
                Writer w = new Writer();
                w.Text("holder", secrets[i].Holder);
                w.Text("name", secrets[i].Name);
                w.Bytes("hex", secrets[i].Bytes);
                w.Raw("derivedFrom", QuotedList(secrets[i].DerivedFrom));
                if (secrets[i].Hidden != null)
                {
                    w.Text("fingerprint", secrets[i].Fingerprint);
                    w.Number("length", secrets[i].Length);
                    w.Text("hidden", secrets[i].Hidden);
                }
                items[i] = w.Finish();
            }
            return "[" + string.Join(",", items) + "]";
        }

        static string QuotedList(string[] values)
        {
            if (values == null) return "[]";
            string[] items = new string[values.Length];
            for (int i = 0; i < values.Length; i++) items[i] = MiniJson.Quote(values[i]);
            return "[" + string.Join(",", items) + "]";
        }

        static string CheckJson(TraceCheck check)
        {
            if (check == null) return null;
            Writer w = new Writer();
            w.Text("id", check.Id);
            w.Text("name", check.Name);
            w.Text("result", check.Passed ? "pass" : "fail");
            w.Text("code", check.Code);
            w.Text("detail", check.Detail);
            return w.Finish();
        }

        sealed class Writer
        {
            readonly StringBuilder _text = new StringBuilder("{");

            public void Text(string name, string value) { if (value != null) Raw(name, MiniJson.Quote(value)); }
            public void Number(string name, long value) { Raw(name, value.ToString()); }
            public void Bytes(string name, byte[] value) { if (value != null) Raw(name, "\"" + Hex.Encode(value) + "\""); }

            public void Raw(string name, string json)
            {
                if (json == null) return;
                if (_text.Length > 1) _text.Append(',');
                _text.Append('"').Append(name).Append("\":").Append(json);
            }

            public string Finish() { return _text.Append('}').ToString(); }
        }
    }
}
