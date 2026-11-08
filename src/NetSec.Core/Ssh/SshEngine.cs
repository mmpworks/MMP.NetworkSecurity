using System;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Machine;
using NetSec.Trace;

namespace NetSec.Ssh
{
    /// <summary>
    /// A sans-IO SSH-2 engine: bytes in, bytes out, no socket, no thread, no file. RFC 4253 and RFC 8731, with the host keys of RFC 8709 and
    /// RFC 4253. Built to show the parts. Do not copy. It shows every key on purpose, and it has had no side-channel review.
    /// The CF build compiles this same source. It runs on the desktop CLR, and it has never run on CE.
    /// </summary>
    public sealed class SshEngine : IProtocolEngine, IPartialInput
    {
        const string PacketStep = "ssh.packet";

        readonly Interpreter<SshSession> _machine;
        readonly SshSession _session;
        readonly TraceStream _stream;
        readonly string _peer;

        SshEngine(StepTable<SshSession> table, SshSession session, string start, TraceStream stream, string peer, ITamperHook tamper)
        {
            _session = session;
            _stream = stream;
            _peer = peer;
            _machine = new Interpreter<SshSession>(table, session, start, stream, peer, tamper);
        }

        public static SshEngine Client(SshClientOptions options, TraceStream stream, ITamperHook tamper, string peer)
        {
            if (options == null) throw new ArgumentNullException("options");
            return new SshEngine(SshClientRules.Table, new SshSession(options, stream.Actor), SshClientRules.Start, stream, peer, tamper);
        }

        public static SshEngine Server(SshServerOptions options, TraceStream stream, ITamperHook tamper, string peer)
        {
            if (options == null) throw new ArgumentNullException("options");
            return new SshEngine(SshServerRules.Table, new SshSession(options, stream.Actor), SshServerRules.Start, stream, peer, tamper);
        }

        public EngineStatus Status { get { return _machine.Status; } }
        public TraceStream Stream { get { return _stream; } }
        public string Peer { get { return _peer; } }

        /// <summary>The negotiated names, for a report.</summary>
        public SshAlgorithms Algorithms { get { return _session.Algorithms; } }

        public EngineOutput Start()
        {
            _machine.Dispatch(InboundMessage.Start);
            return _machine.TakeOutput();
        }

        public EngineOutput Feed(byte[] b, int off, int n)
        {
            _session.Reader.Append(b, off, n);
            Guarded(delegate { while (!_machine.IsEnded && DispatchNext()) { } });
            return _machine.TakeOutput();
        }

        public EngineOutput Command(EngineCommand c)
        {
            if (!_machine.IsEnded) Guarded(delegate { Run(c); });
            return _machine.TakeOutput();
        }

        /// <summary>Every named failure of a parse or a seal ends here, from a feed or from a command.</summary>
        void Guarded(Action work)
        {
            try
            {
                work();
            }
            catch (ParseFailure failure)
            {
                _machine.Fail(failure.Code, CheckFor(failure.Code), failure.Message, null);
            }
            catch (NetSecException refused)
            {
                _machine.Fail(refused.Error.Code, refused.Error.CheckName ?? "message values", refused.Error.Message, null);
            }
            catch (ArgumentException refused)
            {
                _machine.Fail(ErrorCodes.MessageRefused, "message shape", refused.Message, null);
            }
        }

        /// <summary>The SSH client dials the server in every lab, so a pump uses this as its opener role (issue #309).</summary>
        public bool IsClient { get { return _session.IsClient; } }

        /// <summary>The packet reader holds part of a line or a packet (issue #309).</summary>
        public bool HoldsPartialInput { get { return _session.Reader.HoldsPartial; } }

        void Run(EngineCommand c)
        {
            if (c.Kind == EngineCommandKind.Expire)
            {
                _machine.Fail(c.Expiry.Code, c.Expiry.CheckName, c.Expiry.Message, null);
                return;
            }
            if (c.Kind == EngineCommandKind.PeerClosed)
            {
                if (_session.IsOpen && _session.Channels.Count == 0) _machine.CloseCleanly();
                else _machine.Fail(ErrorCodes.PeerClosedEarly, SshChecks.PeerStayed, "the peer closed in state " + _machine.State, null);
                return;
            }
            // A close with text is a polite one, and it needs an open session to carry the Disconnect. The pump's own last close has no text.
            if (c.Kind == EngineCommandKind.Close && (c.Text == null || !_session.IsOpen))
            {
                _machine.CloseCleanly();
                return;
            }
            _session.Pending = c;
            _machine.Dispatch(InboundMessage.Start);
        }

        bool DispatchNext()
        {
            if (!_session.PeerVersionSeen) return DispatchVersion();
            SshPacket packet = _session.Reader.TryNext();
            if (packet == null) return false;
            // The reader throws on a bad MAC, so a packet that reaches this line passed. The tour shows the first pass in each direction, and later packets stay quiet.
            if (_session.ReaderArmed && !_session.MacPassShown)
            {
                _session.MacPassShown = true;
                _machine.Perform(PacketStep, Effect.Check(SshChecks.PacketMac, SshCodes.PacketMac));
            }
            TraceField[] fields = _session.ReaderArmed
                ? SshFields.OfCipher(packet.Wire.Length - _session.Algorithms.MacSize, _session.Algorithms.MacSize)
                : SshFields.Clear(packet.Payload, packet.PaddingLength, _session.Algorithms.IsLegacy);
            _machine.Dispatch(new InboundMessage(packet.Payload[0], SshFields.NameOf(packet.Payload, _session.Algorithms.IsLegacy), packet.Wire, packet.Payload, fields));
            return true;
        }

        /// <summary>RFC 4253 section 4.2: a server may send other lines before its version line. A client may not.</summary>
        bool DispatchVersion()
        {
            byte[] line = _session.Reader.TryLine();
            if (line == null) return false;
            bool isVersion = line.Length >= 4 && SshFields.Text(line).StartsWith("SSH-");
            if (!isVersion && _session.IsClient) return true;
            _session.PeerVersionSeen = true;
            _machine.Dispatch(new InboundMessage(SshMsg.VersionLine, SshNames.VersionLine, line, line, SshFields.VersionLine(line.Length)));
            return true;
        }

        static string CheckFor(string code)
        {
            switch (code)
            {
                case SshCodes.PacketMac: return SshChecks.PacketMac;
                case SshCodes.PacketLength: return SshChecks.PacketLength;
                case SshCodes.Version: return SshChecks.Version;
                case SshCodes.HostKeyBad: return SshChecks.HostKeyShape;
                case SshCodes.SequenceExhausted: return SshChecks.Sequence;
                default: return "message shape";
            }
        }
    }
}
