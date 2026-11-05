using System;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Machine;
using NetSec.Trace;

namespace NetSec.Tls11
{
    /// <summary>
    /// The sans-IO shell of the TLS 1.1 engine: bytes in, records out of the reader, each message through the table. It holds no socket and no thread.
    /// A wire length that never arrives leaves this engine waiting, and the pump's read deadline ends that wait with LINK_DEADLINE.
    /// </summary>
    public sealed class Tls11Engine : IProtocolEngine
    {
        const string AppStep = "tls11.app";

        readonly Interpreter<Tls11Session> _machine;
        readonly Tls11Session _session;
        readonly TraceStream _stream;
        readonly string _peer;
        readonly Tls11RecordReader _records = new Tls11RecordReader();
        readonly Tls11HandshakeReader _handshake = new Tls11HandshakeReader();
        bool _opened;

        Tls11Engine(StepTable<Tls11Session> table, Tls11Options options, string peer)
        {
            if (options == null) throw new ArgumentNullException("options");
            if (options.Suite == null) throw new ArgumentException("the options name no suite", "options");
            _session = new Tls11Session(options);
            _stream = options.Stream;
            _peer = peer;
            _machine = new Interpreter<Tls11Session>(table, _session, Tls11Rules.StartState, options.Stream, peer, options.Tamper);
        }

        public static Tls11Engine CreateClient(Tls11Options options)
        {
            if (options != null && options.Anchors == null) throw new ArgumentException("a client needs trust anchors", "options");
            return new Tls11Engine(Tls11Rules.Client, options, "server");
        }

        public static Tls11Engine CreateServer(Tls11Options options)
        {
            if (options != null && (options.Chain == null || options.ServerKey == null)) throw new ArgumentException("a server needs a chain and a key", "options");
            return new Tls11Engine(Tls11Rules.Server, options, "client");
        }

        public EngineStatus Status { get { return _machine.Status; } }
        public TraceStream Stream { get { return _stream; } }
        public string Peer { get { return _peer; } }
        public bool Opened { get { return _opened; } }
        public string Suite { get { return _session.Options.Suite.Name; } }

        /// <summary>The description byte of the last alert from the peer, or 0.</summary>
        public int AlertReceived { get; private set; }

        /// <summary>One NSS key log line, so Wireshark can open the capture. Empty until the master secret exists.</summary>
        public string[] KeyLog
        {
            get
            {
                if (!_session.Holds(Tls11Session.Master)) return new string[0];
                return new string[] { "CLIENT_RANDOM " + Hex.Encode(_session.ClientRandom) + " " + Hex.Encode(_session.Secret(Tls11Session.Master)) };
            }
        }

        public EngineOutput Start()
        {
            _machine.Dispatch(InboundMessage.Start);
            return _machine.TakeOutput();
        }

        public EngineOutput Feed(byte[] b, int off, int n)
        {
            _records.Append(b, off, n);
            try
            {
                while (!_machine.IsEnded)
                {
                    Tls11RawRecord record = _records.Next();
                    if (record == null) break;
                    HandleRecord(record);
                }
            }
            catch (ParseFailure failure) { _machine.Fail(failure.Code, Tls11Checks.MessageShape, failure.Message, null); }
            catch (NetSecException named) { _machine.Fail(named.Error.Code, Tls11Checks.MessageShape, named.Error.Message, null); }
            catch (ArgumentException refused) { _machine.Fail(Tls11Codes.EngineFault, Tls11Checks.MessageShape, refused.Message, null); }
            catch (ArithmeticException refused) { _machine.Fail(Tls11Codes.EngineFault, Tls11Checks.MessageShape, refused.Message, null); }
            catch (IndexOutOfRangeException refused) { _machine.Fail(Tls11Codes.EngineFault, Tls11Checks.MessageShape, refused.Message, null); }
            return _machine.TakeOutput();
        }

        public EngineOutput Command(EngineCommand c)
        {
            if (c.Kind == EngineCommandKind.PeerClosed && !_machine.IsEnded)
                _machine.Fail(ErrorCodes.PeerClosedEarly, "peer stayed until the end", "the peer closed in state " + _machine.State + " with no close_notify", null);
            else if (c.Kind == EngineCommandKind.Close)
                Close();
            else if (c.Kind == EngineCommandKind.Send)
                SendApp(c.Bytes);
            return _machine.TakeOutput();
        }

        void HandleRecord(Tls11RawRecord record)
        {
            byte[] content = record.Payload;
            bool wasProtected = _session.Inbound != null;
            if (wasProtected && !_session.Inbound.TryOpen(record.Type, record.Version, record.Payload, out content))
            {
                _machine.Fail(Tls11Codes.RecordMac, Tls11Checks.RecordHmac, "a record failed its MAC or padding check", null);
                return;
            }
            switch (record.Type)
            {
                case Tls11Content.Handshake: HandleHandshake(content, wasProtected); break;
                case Tls11Content.ChangeCipherSpec: DispatchWhole(Tls11Messages.ChangeCipherSpecKey, content, wasProtected); break;
                case Tls11Content.Alert: HandleAlert(content, wasProtected); break;
                case Tls11Content.ApplicationData: HandleData(content, wasProtected); break;
                default: _machine.Fail(ErrorCodes.UnexpectedMessage, "message allowed in this state", "a record has content type " + record.Type, null); break;
            }
        }

        void HandleHandshake(byte[] content, bool wasProtected)
        {
            _handshake.Append(content);
            while (!_machine.IsEnded)
            {
                byte[] message = _handshake.Next();
                if (message == null) return;
                byte[] body = new byte[message.Length - 4];
                Buffer.BlockCopy(message, 4, body, 0, body.Length);
                _machine.Dispatch(Inbound(message[0], message, body, wasProtected));
                AfterDispatch();
            }
        }

        void DispatchWhole(int key, byte[] content, bool wasProtected)
        {
            _machine.Dispatch(Inbound(key, content, content, wasProtected));
        }

        void HandleAlert(byte[] content, bool wasProtected)
        {
            if (content.Length != 2) throw new ParseFailure(ErrorCodes.ParseTruncated, "an alert has " + content.Length + " bytes, and it needs 2");
            AlertReceived = content[1];
            DispatchWhole(Tls11Messages.AlertKey, content, wasProtected);
        }

        void HandleData(byte[] content, bool wasProtected)
        {
            if (!wasProtected)
            {
                _machine.Fail(ErrorCodes.UnexpectedMessage, "message allowed in this state", "application data arrived with no keys in place", null);
                return;
            }
            DispatchWhole(Tls11Messages.ApplicationDataKey, content, wasProtected);
            if (_machine.IsEnded || content.Length == 0) return;
            Tls11Options options = _session.Options;
            if (options.EchoReceived) SendApp(content);
            if (options.CloseAfterReply) Close();
        }

        InboundMessage Inbound(int key, byte[] bytes, byte[] body, bool wasProtected)
        {
            TraceField[] fields = Tls11Messages.InboundFields(key, bytes, !wasProtected, _session.Options.Suite);
            return new InboundMessage(key, Tls11Messages.NameOf(key), bytes, body, fields);
        }

        /// <summary>The first time the table reaches Open, the shell runs what the options ask for.</summary>
        void AfterDispatch()
        {
            if (_opened || _machine.Status != EngineStatus.Open) return;
            _opened = true;
            Tls11Options options = _session.Options;
            if (options.SendOnOpen != null) SendApp(options.SendOnOpen);
            else if (options.CloseAfterReply) Close();
        }

        void SendApp(byte[] bytes)
        {
            if (_machine.Status != EngineStatus.Open)
            {
                _machine.Fail(ErrorCodes.MessageRefused, "records open before data", "application data was asked for before the handshake ended", AppStep);
                return;
            }
            for (int off = 0; off < bytes.Length; off += Tls11RecordCipher.MaxContent)
            {
                byte[] chunk = new byte[Math.Min(Tls11RecordCipher.MaxContent, bytes.Length - off)];
                Buffer.BlockCopy(bytes, off, chunk, 0, chunk.Length);
                _machine.Perform(AppStep, Effect.Send(Tls11Messages.ApplicationDataName, chunk, Tls11Messages.ProtectedFields(chunk.Length)));
            }
        }

        /// <summary>Sends close_notify when the record layer is open. Before that, nothing protected can go out.</summary>
        void Close()
        {
            if (_machine.Status == EngineStatus.Open)
            {
                byte[] alert = Tls11Messages.BuildAlert(Tls11Messages.WarningLevel, Tls11Messages.CloseNotify);
                _machine.Perform(AppStep, Effect.Send(Tls11Messages.AlertName, alert, Tls11Messages.ProtectedFields(alert.Length)));
            }
            _machine.CloseCleanly();
        }
    }
}
