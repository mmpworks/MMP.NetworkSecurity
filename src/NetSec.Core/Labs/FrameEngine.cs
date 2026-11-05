using System;
using System.Collections.Generic;
using System.Net;
using MMP.AsyncProxy;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Machine;
using NetSec.Platform;
using NetSec.Tls13;
using NetSec.Trace;

namespace NetSec.Labs
{
    /// <summary>What a primitive lab's rules read. One side effect stays: Draw takes bytes from the lab's random source, in rule order.</summary>
    public abstract class FrameSession : IMachineSession
    {
        readonly Dictionary<string, byte[]> _secrets = new Dictionary<string, byte[]>();
        readonly IRandomSource _random;

        protected FrameSession(IRandomSource random) { _random = random; }

        public abstract string Protocol { get; }
        public abstract string NameOf(int type);
        public string SentType { get { return Protocol + ".message.sent"; } }
        public string ReceivedType { get { return Protocol + ".message.received"; } }

        public virtual void Absorb(byte[] message) { }
        public byte[] Protect(string message, byte[] body) { return body; }
        public void InstallKeys(Direction direction, string suite, byte[] key, byte[] iv) { }
        public void Remember(string name, byte[] value) { _secrets[name] = value; }
        public virtual byte[] PlainOf(InboundMessage message) { return message.Body; }

        public byte[] Secret(string name) { return _secrets[name]; }

        public byte[] Draw(int count)
        {
            byte[] bytes = new byte[count];
            _random.Fill(bytes, 0, count);
            return bytes;
        }
    }

    /// <summary>The wire form of a primitive lab: 1-byte type, 3-byte length, body. Each body layout names its own fields.</summary>
    public static class Frame
    {
        public const int HeaderSize = 4;

        public static byte[] Build(int type, byte[] body)
        {
            return new ByteWriter().U8(type).U24(body.Length).Put(body).ToArray();
        }

        /// <summary>The fields of a frame: the header, then one named span per entry. A length of -1 takes the rest of the body.</summary>
        public static TraceField[] Fields(int bodyLength, params FieldSpan[] spans)
        {
            List<FieldMark> marks = new List<FieldMark>();
            marks.Add(new FieldMark("type", 0, 1, "header", true, "type"));
            marks.Add(new FieldMark("length", 1, 3, "length", true, "length"));
            int at = HeaderSize, left = bodyLength;
            for (int i = 0; i < spans.Length; i++)
            {
                int length = spans[i].Length < 0 ? left - spans[i].Tail : spans[i].Length;
                marks.Add(new FieldMark(spans[i].Name, at, length, spans[i].Kind, spans[i].VisibleToWire, spans[i].Name));
                at += length;
                left -= length;
            }
            return TraceField.From(marks.ToArray());
        }
    }

    public sealed class FieldSpan
    {
        public readonly string Name, Kind;
        public readonly int Length, Tail;
        public readonly bool VisibleToWire;

        /// <param name="length">Bytes, or -1 for the rest of the body less tail bytes.</param>
        public FieldSpan(string name, string kind, int length, int tail, bool visibleToWire)
        {
            Name = name; Kind = kind; Length = length; Tail = tail; VisibleToWire = visibleToWire;
        }
    }

    /// <summary>A table-driven engine for a primitive lab. Each lesson gives it a table and a session, and this class parses frames.</summary>
    public sealed class FrameEngine<TSession> : IProtocolEngine where TSession : FrameSession
    {
        readonly Interpreter<TSession> _machine;
        readonly TSession _session;
        readonly TraceStream _stream;
        readonly string _peer;
        byte[] _pending = new byte[0];

        public FrameEngine(StepTable<TSession> table, TSession session, string startState, TraceStream stream, string peer, ITamperHook tamper)
        {
            _session = session;
            _stream = stream;
            _peer = peer;
            _machine = new Interpreter<TSession>(table, session, startState, stream, peer, tamper);
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
            catch (ArgumentException refused)
            {
                _machine.Fail(ErrorCodes.MessageRefused, "message shape", refused.Message, null);
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

        int BodyLength { get { return (_pending[1] << 16) | (_pending[2] << 8) | _pending[3]; } }

        bool HasWholeFrame()
        {
            return _pending.Length >= Frame.HeaderSize && _pending.Length >= Frame.HeaderSize + BodyLength;
        }

        InboundMessage NextFrame()
        {
            int size = Frame.HeaderSize + BodyLength;
            byte[] frame = new byte[size];
            Buffer.BlockCopy(_pending, 0, frame, 0, size);
            byte[] rest = new byte[_pending.Length - size];
            Buffer.BlockCopy(_pending, size, rest, 0, rest.Length);
            _pending = rest;
            byte[] body = new byte[size - Frame.HeaderSize];
            Buffer.BlockCopy(frame, Frame.HeaderSize, body, 0, body.Length);
            return new InboundMessage(frame[0], _session.NameOf(frame[0]), frame, body, Frame.Fields(body.Length));
        }
    }

    /// <summary>Runs a client and a server engine on loopback, each its own EnginePump. A tamper hook applies to both directions.</summary>
    public static class LabPair
    {
        public const int DeadlineMs = 30000;

        /// <summary>Lets a lab set each pump's OnApp before the pumps start.</summary>
        public delegate void PumpSetup(EnginePump client, EnginePump server);

        public static IFuture<LabResult> Run(LabContext c, IProtocolEngine client, IProtocolEngine server, ITamperHook tamper)
        {
            return Run(c, client, server, tamper, null);
        }

        public static IFuture<LabResult> Run(LabContext c, IProtocolEngine client, IProtocolEngine server, ITamperHook tamper, PumpSetup setup)
        {
            return AsyncProxy.Run<LabResult>(delegate(Return<LabResult> ret) { return Body(c, client, server, tamper, setup, ret); });
        }

        static IEnumerable<IFuture> Body(LabContext c, IProtocolEngine client, IProtocolEngine server, ITamperHook tamper, PumpSetup setup, Return<LabResult> ret)
        {
            LinkListener listener = new LinkListener(new IPEndPoint(IPAddress.Loopback, 0));
            IFuture<SocketLink> accepted = listener.Accept();
            IFuture<SocketLink> connected = SocketLink.Connect(new IPEndPoint(IPAddress.Loopback, listener.Port));
            yield return accepted;
            yield return connected;
            listener.Close();

            int deadline = c.DeadlineMs > 0 ? c.DeadlineMs : DeadlineMs;
            EnginePump serverPump = new EnginePump(server, accepted.Result, c.Sink, c.Gate, tamper, deadline, c.Clock);
            EnginePump clientPump = new EnginePump(client, connected.Result, c.Sink, c.Gate, tamper, deadline, c.Clock);
            if (setup != null) setup(clientPump, serverPump);
            IFuture<PumpResult> serverRun = serverPump.Run();
            IFuture<PumpResult> clientRun = clientPump.Run();
            yield return clientRun;
            yield return serverRun;

            ret.Value = Result(clientRun.Result, serverRun.Result);
        }

        /// <summary>The catch is the side that named a check. The other side then only saw its peer close.</summary>
        public static LabResult Result(PumpResult client, PumpResult server)
        {
            NetSecError first = Named(server.Error) ?? Named(client.Error) ?? server.Error ?? client.Error;
            LabResult result = new LabResult();
            result.Completed = first == null;
            if (first != null)
            {
                result.FailedCode = first.Code;
                result.FailedCheck = first.CheckName;
            }
            return result;
        }

        /// <summary>False for a code that only follows from a catch on the other side.</summary>
        public static bool NamesACause(string code)
        {
            return code != null && Named(NetSecError.Of(code, code)) != null;
        }

        static NetSecError Named(NetSecError error)
        {
            return error != null && error.Code != ErrorCodes.PeerClosedEarly && error.Code != ErrorCodes.LinkLost && error.Code != Tls13Codes.AlertReceived && error.Code != NetSec.Tls11.Tls11Codes.Alert ? error : null;
        }

        public static TraceStream Stream(LabContext c, string actor, string protocol)
        {
            return new TraceStream(c.SessionId + "/" + actor + "/" + protocol, c.SessionId, c.TraceId, null, actor, c.Clock);
        }

        public static string Option(LabContext c, string name)
        {
            if (c.Attack == null || c.Attack.Options == null) return null;
            for (int i = 0; i < c.Attack.Options.Length; i++)
                if (c.Attack.Options[i].Name == name) return c.Attack.Options[i].Value;
            return null;
        }

        /// <summary>A random stream for one side, drawn before the pumps start. Two sides draw in an order threads choose, so a shared stream would change between same-seed runs.</summary>
        public static IRandomSource Fork(LabContext c)
        {
            byte[] seed = new byte[32];
            c.Random.Fill(seed, 0, seed.Length);
            return new SeededRandom(seed);
        }

        public static ITamperHook Plan(LabContext c)
        {
            return c.Attack == null ? null : c.Attack.Plan;
        }
    }
}
