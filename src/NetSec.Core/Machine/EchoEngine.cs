using System;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Trace;

namespace NetSec.Machine
{
    /// <summary>
    /// The toy protocol of S0. A client sends bytes, the server sends them back, and the client compares. It has no lock.
    /// Frame: 1-byte type, 2-byte length, body. It proves the table, the interpreter, and the pump before any cryptography exists.
    /// </summary>
    public sealed class EchoEngine : IProtocolEngine
    {
        public const int HelloType = 1;
        public const int ReplyType = 2;
        public const string HelloName = "EchoHello";
        public const string ReplyName = "EchoReply";
        public const string CompareCheck = "echo compare";

        const int HeaderSize = 3;
        const string WaitHello = "WaitHello";
        const string WaitReply = "WaitReply";
        const string Start0 = "Start";

        sealed class Session : IMachineSession
        {
            public byte[] Sent;
            public string SentType { get { return "echo.message.sent"; } }
            public string ReceivedType { get { return "echo.message.received"; } }
            public void Absorb(byte[] message) { }
            public byte[] Protect(string message, byte[] body) { return body; }
            public void InstallKeys(Direction direction, string suite, byte[] key, byte[] iv) { }
        }

        static readonly StepTable<Session> ClientTable = new StepTable<Session>(
            new StepRow<Session>("echo.c.hello", Start0, InboundMessage.StartType, ClientHello, WaitReply),
            new StepRow<Session>("echo.c.reply", WaitReply, ReplyType, ClientReply, MachineStates.Closed));

        static readonly StepTable<Session> ServerTable = new StepTable<Session>(
            new StepRow<Session>("echo.s.start", Start0, InboundMessage.StartType, ServerStart, WaitHello),
            new StepRow<Session>("echo.s.hello", WaitHello, HelloType, ServerHello, MachineStates.Closed));

        /// <summary>The steps of both roles, for a test over the tour bindings.</summary>
        public static string[] AllSteps
        {
            get
            {
                string[] c = ClientTable.Steps, s = ServerTable.Steps, all = new string[c.Length + s.Length];
                c.CopyTo(all, 0);
                s.CopyTo(all, c.Length);
                return all;
            }
        }

        static StepDecision ClientHello(Session session, InboundMessage message)
        {
            return StepDecision.Advance(Effect.Send(HelloName, Frame(HelloType, session.Sent), Fields(HelloType, session.Sent.Length)));
        }

        static StepDecision ClientReply(Session session, InboundMessage message)
        {
            if (!SameBytes(session.Sent, message.Body))
                return StepDecision.Fail(ErrorCodes.EchoMismatch, CompareCheck, "the reply differs from the bytes the client sent");
            return StepDecision.Advance(Effect.Deliver(0, message.Body), Effect.Check(CompareCheck, ErrorCodes.EchoMismatch));
        }

        static StepDecision ServerStart(Session session, InboundMessage message)
        {
            return StepDecision.Advance();
        }

        static StepDecision ServerHello(Session session, InboundMessage message)
        {
            return StepDecision.Advance(Effect.Deliver(0, message.Body), Effect.Send(ReplyName, Frame(ReplyType, message.Body), Fields(ReplyType, message.Body.Length)));
        }

        static bool SameBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        static byte[] Frame(int type, byte[] body)
        {
            return new ByteWriter().U8(type).U16(body.Length).Put(body).ToArray();
        }

        static TraceField[] Fields(int type, int bodyLength)
        {
            ByteReader reader = new ByteReader(new byte[HeaderSize + bodyLength], 0, HeaderSize + bodyLength, true);
            reader.U8("type", "header");
            reader.U16("length", "length");
            reader.Take("body", "data", bodyLength);
            return TraceField.From(reader.Marks);
        }

        readonly Interpreter<Session> _machine;
        readonly TraceStream _stream;
        readonly string _peer;
        byte[] _pending = new byte[0];

        EchoEngine(StepTable<Session> table, Session session, TraceStream stream, string peer, ITamperHook tamper)
        {
            _stream = stream;
            _peer = peer;
            _machine = new Interpreter<Session>(table, session, Start0, stream, peer, tamper);
        }

        public static EchoEngine Client(byte[] message, TraceStream stream, ITamperHook tamper)
        {
            if (message == null) throw new ArgumentNullException("message");
            Session session = new Session();
            session.Sent = (byte[])message.Clone();
            return new EchoEngine(ClientTable, session, stream, "server", tamper);
        }

        public static EchoEngine Server(TraceStream stream, ITamperHook tamper)
        {
            return new EchoEngine(ServerTable, new Session(), stream, "client", tamper);
        }

        public EngineStatus Status { get { return _machine.Status; } }
        public TraceStream Stream { get { return _stream; } }
        public string Peer { get { return _peer; } }

        public EngineOutput Start()
        {
            _machine.Dispatch(InboundMessage.Start);
            return _machine.TakeOutput();
        }

        public EngineOutput Feed(byte[] b, int off, int n)
        {
            Append(b, off, n);
            try
            {
                while (!_machine.IsEnded && HasWholeFrame()) _machine.Dispatch(NextFrame());
            }
            catch (ParseFailure failure)
            {
                _machine.Fail(failure.Code, "frame parse", failure.Message, null);
            }
            return _machine.TakeOutput();
        }

        public EngineOutput Command(EngineCommand c)
        {
            if (c.Kind == EngineCommandKind.PeerClosed && !_machine.IsEnded)
                _machine.Fail(ErrorCodes.PeerClosedEarly, "peer stayed until the end", "the peer closed in state " + _machine.State, null);
            else if (c.Kind == EngineCommandKind.Close)
                _machine.CloseCleanly();
            return _machine.TakeOutput();
        }

        void Append(byte[] b, int off, int n)
        {
            byte[] joined = new byte[_pending.Length + n];
            Buffer.BlockCopy(_pending, 0, joined, 0, _pending.Length);
            Buffer.BlockCopy(b, off, joined, _pending.Length, n);
            _pending = joined;
        }

        bool HasWholeFrame()
        {
            if (_pending.Length < HeaderSize) return false;
            int length = (_pending[1] << 8) | _pending[2];
            return _pending.Length >= HeaderSize + length;
        }

        InboundMessage NextFrame()
        {
            int length = (_pending[1] << 8) | _pending[2];
            int size = HeaderSize + length;
            byte[] frame = new byte[size];
            Buffer.BlockCopy(_pending, 0, frame, 0, size);
            byte[] rest = new byte[_pending.Length - size];
            Buffer.BlockCopy(_pending, size, rest, 0, rest.Length);
            _pending = rest;

            ByteReader reader = new ByteReader(frame, 0, size, true);
            int type = reader.U8("type", "header");
            reader.U16("length", "length");
            byte[] body = reader.Take("body", "data", length);
            string name = type == HelloType ? HelloName : type == ReplyType ? ReplyName : "Unknown";
            return new InboundMessage(type, name, frame, body, TraceField.From(reader.Marks));
        }
    }
}
