using System;
using System.Collections.Generic;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Machine;
using NetSec.Trace;

namespace NetSec.Tls13
{
    /// <summary>
    /// TLS 1.3, bytes in and bytes out. Feed joins bytes into records, opens them, joins the contents into messages, and hands each message to
    /// the table. It holds no socket and no clock. Data sent before the handshake ends waits here until the state is Open.
    /// </summary>
    public sealed class Tls13Engine : IProtocolEngine
    {
        const int CloseNotify = 0;

        readonly Tls13Session _session;
        readonly Interpreter<Tls13Session> _machine;
        readonly TraceStream _stream;
        readonly string _peer;
        readonly RecordBuffer _records = new RecordBuffer();
        readonly HandshakeBuffer _handshake = new HandshakeBuffer();
        readonly Queue<byte[]> _waitingToSend = new Queue<byte[]>();
        bool _noAlertOwed;

        Tls13Engine(StepTable<Tls13Session> table, string startState, Tls13Options options)
        {
            if (options.Stream == null) throw new ArgumentNullException("options");
            _session = new Tls13Session(options);
            _stream = options.Stream;
            _peer = options.Peer;
            _machine = new Interpreter<Tls13Session>(table, _session, startState, _stream, _peer, options.Tamper);
        }

        public static Tls13Engine CreateClient(Tls13Options options)
        {
            return new Tls13Engine(Tls13ClientTable.Table, Tls13ClientTable.Start, options);
        }

        public static Tls13Engine CreateServer(Tls13Options options)
        {
            return new Tls13Engine(Tls13ServerTable.Table, Tls13ServerTable.Start, options);
        }

        public EngineStatus Status { get { return _machine.Status; } }
        public TraceStream Stream { get { return _stream; } }
        public string Peer { get { return _peer; } }

        /// <summary>The alert number the peer sent, or -1.</summary>
        public int AlertReceived { get; private set; }
        public bool ReachedOpen { get; private set; }
        public string[] KeyLogLines { get { return _session.KeyLogLines.ToArray(); } }
        public string SuiteName { get { return _session.Suite == null ? null : _session.Suite.Name; } }
        public string GroupName { get { return ReachedOpen ? Tls13GroupInfo.Name(_session.Options.Group) : null; } }

        public EngineOutput Start()
        {
            AlertReceived = -1;
            Guarded(delegate { _machine.Dispatch(InboundMessage.Start); });
            return Take();
        }

        public EngineOutput Feed(byte[] b, int off, int n)
        {
            _records.Append(b, off, n);
            Guarded(ReadRecords);
            return Take();
        }

        public EngineOutput Command(EngineCommand c)
        {
            switch (c.Kind)
            {
                case EngineCommandKind.Send: Send(c.Bytes); break;
                case EngineCommandKind.Close: Close(); break;
                case EngineCommandKind.PeerClosed: PeerClosed(); break;
            }
            return Take();
        }

        void Send(byte[] bytes)
        {
            if (!_machine.IsEnded) _waitingToSend.Enqueue((byte[])bytes.Clone());
        }

        void Close()
        {
            if (_machine.IsEnded) return;
            if (_session.OutboundProtected) SendAlert(1, CloseNotify);
            _machine.CloseCleanly();
        }

        void PeerClosed()
        {
            if (_machine.IsEnded) return;
            _noAlertOwed = true;
            if (_machine.Status == EngineStatus.Open) _machine.CloseCleanly();
            else _machine.Fail(ErrorCodes.PeerClosedEarly, "peer stayed until the end", "the peer closed in state " + _machine.State, null);
        }

        /// <summary>Every parse failure inside the engine stops here and becomes a named check. Feed never throws for bad input.</summary>
        void Guarded(Action work)
        {
            try { work(); }
            catch (ParseFailure failure)
            {
                _machine.Fail(failure.Code, Tls13Codes.CheckName(failure.Code), failure.Message, null);
            }
        }

        void ReadRecords()
        {
            RawRecord record;
            while (!_machine.IsEnded && (record = _records.Next()) != null) ReadRecord(record);
        }

        void ReadRecord(RawRecord record)
        {
            int type = record.Type;
            byte[] content = record.Payload;
            if (type == ContentType.ChangeCipherSpec)
            {
                _machine.Perform(null, Effect.Note("tls.ccs.ignored", "a dummy change_cipher_spec for old middleboxes. TLS 1.3 reads it and drops it"));
                return;
            }
            if (type == ContentType.ApplicationData)
            {
                if (_session.Inbound == null)
                {
                    _machine.Fail(ErrorCodes.UnexpectedMessage, Tls13Codes.CheckName(ErrorCodes.UnexpectedMessage), "a protected record arrived before any keys exist", null);
                    return;
                }
                if (!_session.Inbound.TryOpen(record.Header, record.Payload, out type, out content))
                {
                    _machine.Fail(Tls13Codes.AeadTag, Tls13Codes.CheckName(Tls13Codes.AeadTag), "record " + (_session.Inbound.Count - 1) + " failed its tag, so its bytes changed or the two sides hold different keys", null);
                    return;
                }
            }
            Dispatch(type, content);
        }

        void Dispatch(int type, byte[] content)
        {
            bool visible = _session.Inbound == null;
            switch (type)
            {
                case ContentType.Handshake:
                    _handshake.Append(content);
                    byte[] message;
                    while (!_machine.IsEnded && (message = _handshake.Next()) != null) DispatchHandshake(message, visible);
                    break;
                case ContentType.Alert:
                    ReadAlert(content);
                    break;
                case ContentType.ApplicationData:
                    _machine.Dispatch(new InboundMessage(HandshakeType.ApplicationData, Tls13Session.ApplicationMessage, content, content, DataField(content.Length), "tls.record.received"));
                    break;
                default:
                    _machine.Fail(ErrorCodes.UnexpectedMessage, Tls13Codes.CheckName(ErrorCodes.UnexpectedMessage), "a record has content type " + type, null);
                    break;
            }
        }

        void DispatchHandshake(byte[] message, bool visible)
        {
            int type = message[0];
            byte[] body = new byte[message.Length - 4];
            Buffer.BlockCopy(message, 4, body, 0, body.Length);
            TraceField[] fields = Tls13Messages.FieldsOf(type, message, visible);
            _machine.Dispatch(new InboundMessage(type, HandshakeType.Name(type), message, body, fields));
        }

        void ReadAlert(byte[] content)
        {
            if (content.Length != 2) throw new ParseFailure(ErrorCodes.ParseTruncated, "an alert has " + content.Length + " bytes and needs 2");
            AlertReceived = content[1];
            _noAlertOwed = true;
            _machine.Perform(null, Effect.Note("tls.alert.received", "alert level " + content[0] + ", number " + content[1]));
            if (content[1] == CloseNotify) { _machine.CloseCleanly(); return; }
            _machine.Fail(Tls13Codes.AlertReceived, "peer sent no alert", "the peer sent alert " + content[1], null);
        }

        /// <summary>After each call: send what has waited for Open, or owe the peer one alert after a failure.</summary>
        EngineOutput Take()
        {
            if (_machine.Status == EngineStatus.Open)
            {
                ReachedOpen = true;
                while (_waitingToSend.Count > 0)
                {
                    byte[] data = _waitingToSend.Dequeue();
                    _machine.Perform(null, Effect.SendAs("tls.record.sent", Tls13Session.ApplicationMessage, data, DataField(data.Length)));
                }
            }
            if (_machine.Status == EngineStatus.Failed && !_noAlertOwed)
            {
                _noAlertOwed = true;
                SendAlert(2, Tls13Codes.AlertFor(_machine.Error.Code));
            }
            return _machine.TakeOutput();
        }

        void SendAlert(int level, int number)
        {
            byte[] alert = new byte[] { (byte)level, (byte)number };
            ByteReader r = new ByteReader(alert, 0, 2, !_session.OutboundProtected);
            r.U8("alert.level", "header");
            r.U8("alert.description", "header");
            _machine.Perform(null, Effect.SendAs("tls.alert.sent", Tls13Session.AlertMessage, alert, TraceField.From(r.Marks)));
        }

        static TraceField[] DataField(int length)
        {
            ByteReader r = new ByteReader(new byte[length], 0, length, false);
            r.Take("application_data", "data", length);
            return TraceField.From(r.Marks);
        }
    }
}
