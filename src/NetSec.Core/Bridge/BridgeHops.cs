using System;
using System.Collections.Generic;
using System.Net;
using MMP.AsyncProxy;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Platform;
using NetSec.Ssh;
using NetSec.Trace;

namespace NetSec.Bridge
{
    /// <summary>One channel of a secure session, as a byte stream. A fault in the session faults the read, so the engine's named error reaches the caller.</summary>
    public sealed class ChannelByteLink : IByteLink
    {
        readonly ISecureChannel _session;
        readonly int _channel;
        readonly bool _closesSession;
        byte[] _held = new byte[0];
        int _heldAt;

        public ChannelByteLink(ISecureChannel session, int channel, bool closesSession)
        {
            if (session == null) throw new ArgumentNullException("session");
            _session = session; _channel = channel; _closesSession = closesSession;
        }

        public IFuture<int> Read(byte[] b, int off, int n)
        {
            return AsyncProxy.Run<int>(delegate(Return<int> ret) { return ReadBody(b, off, n, ret); });
        }

        IEnumerable<IFuture> ReadBody(byte[] b, int off, int n, Return<int> ret)
        {
            while (_heldAt >= _held.Length)
            {
                IFuture<AppChunk> next = _session.Receive();
                yield return next;
                if (next.Result.Channel != _channel) continue;
                if (next.Result.Bytes.Length == 0) { ret.Value = 0; yield break; }
                _held = next.Result.Bytes;
                _heldAt = 0;
            }
            int take = Math.Min(n, _held.Length - _heldAt);
            Buffer.BlockCopy(_held, _heldAt, b, off, take);
            _heldAt += take;
            ret.Value = take;
        }

        public IFuture Write(byte[] b, int off, int n)
        {
            byte[] copy = new byte[n];
            Buffer.BlockCopy(b, off, copy, 0, n);
            return _session.Send(_channel, copy);
        }

        public void Close()
        {
            if (_closesSession) _session.Close();
            else _session.Send(_channel, new byte[0]);
        }
    }

    /// <summary>The first write passes through a function, and every later write goes unchanged. A gateway reads the trace id there, and the lab's tamper flips a byte there.</summary>
    public sealed class FirstWriteLink : IByteLink
    {
        readonly IByteLink _inner;
        readonly Func<byte[], byte[]> _first;
        int _used;

        public FirstWriteLink(IByteLink inner, Func<byte[], byte[]> first)
        {
            if (inner == null) throw new ArgumentNullException("inner");
            if (first == null) throw new ArgumentNullException("first");
            _inner = inner; _first = first;
        }

        public IFuture<int> Read(byte[] b, int off, int n) { return _inner.Read(b, off, n); }
        public void Close() { _inner.Close(); }

        public IFuture Write(byte[] b, int off, int n)
        {
            if (System.Threading.Interlocked.Exchange(ref _used, 1) != 0) return _inner.Write(b, off, n);
            byte[] copy = new byte[n];
            Buffer.BlockCopy(b, off, copy, 0, n);
            byte[] changed = _first(copy);
            return _inner.Write(changed, 0, changed.Length);
        }
    }

    /// <summary>
    /// Opens its link at the first write. A read waits for that open, and a close before it opens nothing and ends the read. ssh.exe -L opens a
    /// tunnel for any local connection, and a port check is one, so a tunnel that never carries a byte must not start a handshake on the next hop.
    /// </summary>
    public sealed class FirstWriteOpensLink : IByteLink
    {
        readonly Func<IFuture<IByteLink>> _open;
        readonly Promise<IByteLink> _ready = new Promise<IByteLink>(PromiseOptions.RunContinuationsAsynchronously);
        int _started;

        public FirstWriteOpensLink(Func<IFuture<IByteLink>> open)
        {
            if (open == null) throw new ArgumentNullException("open");
            _open = open;
        }

        bool ClaimStart() { return System.Threading.Interlocked.Exchange(ref _started, 1) == 0; }

        public IFuture<int> Read(byte[] b, int off, int n)
        {
            return AsyncProxy.Run<int>(delegate(Return<int> ret) { return ReadBody(b, off, n, ret); });
        }

        IEnumerable<IFuture> ReadBody(byte[] b, int off, int n, Return<int> ret)
        {
            yield return _ready.Future;
            if (_ready.Future.Result == null) { ret.Value = 0; yield break; }
            IFuture<int> read = _ready.Future.Result.Read(b, off, n);
            yield return read;
            ret.Value = read.Result;
        }

        public IFuture Write(byte[] b, int off, int n)
        {
            byte[] copy = new byte[n];
            Buffer.BlockCopy(b, off, copy, 0, n);
            return AsyncProxy.Run(WriteBody(copy));
        }

        IEnumerable<IFuture> WriteBody(byte[] bytes)
        {
            if (ClaimStart())
            {
                IFuture<IByteLink> opening = _open();
                yield return Futures.Observe(opening);
                if (opening.IsFaulted) _ready.TrySetException(opening.Exception);
                else if (opening.IsCanceled) _ready.TrySetResult(null);
                else _ready.TrySetResult(opening.Result);
            }
            yield return _ready.Future;
            if (_ready.Future.Result != null) yield return _ready.Future.Result.Write(bytes, 0, bytes.Length);
        }

        public void Close()
        {
            if (ClaimStart()) { _ready.TrySetResult(null); return; }
            AsyncProxy.Run(CloseBody());
        }

        IEnumerable<IFuture> CloseBody()
        {
            yield return Futures.Observe(_ready.Future);
            if (!_ready.Future.IsFaulted && !_ready.Future.IsCanceled && _ready.Future.Result != null) _ready.Future.Result.Close();
        }
    }

    /// <summary>Copies both ways between two links until one side ends, then closes both. A relay opens nothing it carries.</summary>
    public static class BridgeRelay
    {
        const int BufferSize = 16384;

        /// <summary>Completes when the first direction ends. It never faults: a fault here is a link that ended, and the engine has already named it.</summary>
        public static IFuture Join(IByteLink a, IByteLink b)
        {
            return AsyncProxy.Run(JoinBody(a, b));
        }

        static IEnumerable<IFuture> JoinBody(IByteLink a, IByteLink b)
        {
            Promise ended = new Promise(PromiseOptions.RunContinuationsAsynchronously);
            AsyncProxy.Run(Copy(a, b, ended));
            AsyncProxy.Run(Copy(b, a, ended));
            yield return ended.Future;
            a.Close();
            b.Close();
        }

        static IEnumerable<IFuture> Copy(IByteLink from, IByteLink to, Promise ended)
        {
            byte[] buffer = new byte[BufferSize];
            while (true)
            {
                IFuture<int> read = from.Read(buffer, 0, buffer.Length);
                yield return Futures.Observe(read);
                if (read.IsFaulted || read.IsCanceled || read.Result == 0) break;
                IFuture wrote = to.Write(buffer, 0, read.Result);
                yield return Futures.Observe(wrote);
                if (wrote.IsFaulted || wrote.IsCanceled) break;
            }
            ended.TrySetResult();
        }
    }

    /// <summary>
    /// A process that serves a hop starts its handshake before the envelope names the trace id, so this sink holds events until it knows the id,
    /// then writes them in order under that id. Flush writes what it holds with no id, for a session that ended before any envelope crossed.
    /// </summary>
    public sealed class LateTraceSink : ITraceSink
    {
        readonly ITraceSink _inner;
        readonly List<TraceEvent> _held = new List<TraceEvent>();
        string _traceId;
        bool _open;

        public LateTraceSink(ITraceSink inner)
        {
            if (inner == null) throw new ArgumentNullException("inner");
            _inner = inner;
        }

        public void Write(TraceEvent e)
        {
            lock (_held)
            {
                if (!_open) { _held.Add(e); return; }
                _inner.Write(_traceId == null ? e : e.WithTraceId(_traceId));
            }
        }

        public void Learn(string traceId)
        {
            lock (_held)
            {
                _traceId = traceId;
                Release();
            }
        }

        public void Flush()
        {
            lock (_held) Release();
        }

        void Release()
        {
            _open = true;
            for (int i = 0; i < _held.Count; i++) _inner.Write(_traceId == null ? _held[i] : _held[i].WithTraceId(_traceId));
            _held.Clear();
        }
    }

    public sealed class HopServerOptions
    {
        public ITrainingKeySource Keys;
        public IRandomSource Random;

        /// <summary>The gateway's SSH suite. One gateway speaks one suite, so a CE on the other suite stops at SSH_NO_COMMON_ALG.</summary>
        public SshSuite Suite;

        /// <summary>The gateway's hop 2 draws here, so the two hops cannot race for one stream. Null shares Random.</summary>
        public IRandomSource NextHopRandom;
        public ITraceSink Sink;
        public IStepGate Gate;
        public ITamperHook Tamper;

        /// <summary>Null means "bridge", for a process that serves whoever connects.</summary>
        public string SessionId;

        /// <summary>A caller that knows the id ahead of time sets it. Null means learn it from the first frame.</summary>
        public string TraceId;
    }

    /// <summary>
    /// The bridge's two middle processes. Each ends one hop and starts the next, and forwards the envelope unopened (D13). The gateway ends SSH and
    /// starts TLS 1.3. The server ends TLS 1.3 and sends the bytes to the bank.
    /// </summary>
    public static class BridgeHopServers
    {
        public const string Hop1 = "hop1", Hop2 = "hop2";
        const string Session = "bridge";
        const int FrameHeader = 4;
        const string NoOpenNote = "PIN block: gateway cannot open this";
        const int LockedBlockFromEnd = 17;

        /// <summary>One CE connection. Ends when the SSH session ends. flipEnvelope changes one byte of the locked PIN block after SSH and before TLS, so the bank is the one that catches it.</summary>
        public static IFuture ServeGateway(IByteLink ce, HopServerOptions o, int nextPort, bool flipEnvelope)
        {
            return AsyncProxy.Run(GatewayBody(ce, o, nextPort, flipEnvelope));
        }

        static IEnumerable<IFuture> GatewayBody(IByteLink ce, HopServerOptions o, int nextPort, bool flipEnvelope)
        {
            LateTraceSink late = o.TraceId == null ? new LateTraceSink(o.Sink) : null;
            ITraceSink sink = late ?? o.Sink;
            string session = o.SessionId ?? Session;
            GlassTransportFactory factory = new GlassTransportFactory(o.Keys);
            TraceStream notes = new TraceStream(session + "/gateway/bridge", session, o.TraceId, null, "gateway", new MonotonicClock());

            TransportRequest ssh = new TransportRequest();
            ssh.Protocol = WireProtocol.Ssh;
            ssh.Role = EngineRole.Server;
            ssh.Suite = o.Suite;
            ssh.Link = ce;
            ssh.Random = o.Random;
            ssh.Sink = sink;
            ssh.Gate = o.Gate;
            ssh.Tamper = o.Tamper;
            ssh.TraceId = o.TraceId;
            ssh.Hop = Hop1;
            ssh.SessionId = session;
            ssh.Actor = "gateway";
            ssh.PeerActor = "ce";
            // The gateway forwards to one place and ignores the target name, as Go gogateway does, so an ssh.exe -L run works.
            ssh.AllowTunnel = delegate(string host, int port) { return true; };
            ssh.OpenTarget = delegate(string host, int port)
            {
                return Futures.FromResult<IByteLink>(new FirstWriteOpensLink(delegate { return OpenNextHop(factory, o, sink, late, notes, nextPort, flipEnvelope); }));
            };

            IFuture<ISecureChannel> opened = factory.Open(ssh);
            yield return Futures.Observe(opened);
            if (!opened.IsFaulted && !opened.IsCanceled)
            {
                IFuture<PumpResult> finished = ((GlassSshSession)opened.Result).Finished;
                yield return Futures.Observe(finished);
            }
            if (late != null) late.Flush();
            ce.Close();
        }

        static IFuture<IByteLink> OpenNextHop(GlassTransportFactory factory, HopServerOptions o, ITraceSink sink, LateTraceSink late, TraceStream notes, int nextPort, bool flipEnvelope)
        {
            return AsyncProxy.Run<IByteLink>(delegate(Return<IByteLink> ret) { return NextHopBody(factory, o, sink, late, notes, nextPort, flipEnvelope, ret); });
        }

        static IEnumerable<IFuture> NextHopBody(GlassTransportFactory factory, HopServerOptions o, ITraceSink sink, LateTraceSink late, TraceStream notes, int nextPort, bool flipEnvelope, Return<IByteLink> ret)
        {
            IFuture<SocketLink> connected = SocketLink.Connect(new IPEndPoint(IPAddress.Loopback, nextPort));
            yield return connected;

            TransportRequest tls = new TransportRequest();
            tls.Protocol = WireProtocol.Tls13;
            tls.Role = EngineRole.Client;
            tls.Group = KexGroup.X25519MlKem768;
            tls.Link = connected.Result;
            tls.Random = o.NextHopRandom ?? o.Random;
            tls.Sink = sink;
            tls.Gate = o.Gate;
            tls.Tamper = o.Tamper;
            tls.TraceId = o.TraceId;
            tls.Hop = Hop2;
            tls.SessionId = o.SessionId ?? Session;
            tls.Actor = "gateway";
            IFuture<ISecureChannel> opened = factory.Open(tls);
            yield return opened;

            ret.Value = new FirstWriteLink(new ChannelByteLink(opened.Result, 0, true), delegate(byte[] first)
            {
                Learn(late, first);
                TraceEventDraft note = new TraceEventDraft();
                note.Type = "gateway.envelope.relayed";
                note.Message = "PinEnvelope";
                note.Detail = NoOpenNote;
                sink.Write(notes.Stamp(note));
                if (flipEnvelope) first[first.Length - LockedBlockFromEnd] ^= 1;
                return first;
            });
        }

        /// <summary>One gateway connection. Ends when the TLS session ends. A new socket to the bank serves each connection.</summary>
        public static IFuture ServeServer(IByteLink gateway, HopServerOptions o, int bankPort)
        {
            return AsyncProxy.Run(ServerBody(gateway, o, bankPort));
        }

        static IEnumerable<IFuture> ServerBody(IByteLink gateway, HopServerOptions o, int bankPort)
        {
            LateTraceSink late = o.TraceId == null ? new LateTraceSink(o.Sink) : null;
            // With no bank to reach, the hop ends now. The gateway and the CE then see a closed peer, and neither waits for a deadline.
            IFuture<SocketLink> bank = SocketLink.Connect(new IPEndPoint(IPAddress.Loopback, bankPort));
            yield return Futures.Observe(bank);
            if (bank.IsFaulted || bank.IsCanceled)
            {
                gateway.Close();
                yield break;
            }

            TransportRequest tls = new TransportRequest();
            tls.Protocol = WireProtocol.Tls13;
            tls.Role = EngineRole.Server;
            tls.Group = KexGroup.X25519MlKem768;
            tls.Link = gateway;
            tls.Random = o.Random;
            tls.Sink = late ?? o.Sink;
            tls.Gate = o.Gate;
            tls.Tamper = o.Tamper;
            tls.TraceId = o.TraceId;
            tls.Hop = Hop2;
            tls.SessionId = o.SessionId ?? Session;
            tls.Actor = "server";
            tls.PeerActor = "gateway";
            IFuture<ISecureChannel> opened = new GlassTransportFactory(o.Keys).Open(tls);
            yield return opened;

            IByteLink toBank = new FirstWriteLink(bank.Result, delegate(byte[] first)
            {
                Learn(late, first);
                return first;
            });
            yield return BridgeRelay.Join(new ChannelByteLink(opened.Result, 0, true), toBank);
            if (late != null) late.Flush();
        }

        static void Learn(LateTraceSink late, byte[] firstWrite)
        {
            if (late == null) return;
            string traceId = TraceIdOf(firstWrite);
            if (traceId != null) late.Learn(traceId);
        }

        /// <summary>The id the first frame claims, or null when it does not read as an envelope. A hop only labels its trace with this. The bank alone can verify it.</summary>
        static string TraceIdOf(byte[] firstWrite)
        {
            if (firstWrite.Length <= FrameHeader) return null;
            byte[] body = new byte[firstWrite.Length - FrameHeader];
            Buffer.BlockCopy(firstWrite, FrameHeader, body, 0, body.Length);
            try { return PinEnvelope.Parse(body).TraceId; }
            catch (ParseFailure) { return null; }
        }
    }

    /// <summary>D7's glass route. The CE speaks SSH itself and asks for one tunnel. A frame goes down the tunnel, and the gateway decides where it leads.</summary>
    public sealed class GlassSshLink : IDeviceLink
    {
        public const string KindName = "glass-ssh";
        const string TargetHost = "server.lab";
        const int TargetPort = 443;

        readonly IPEndPoint _endpoint;
        readonly TransportRequest _request;
        readonly ITransportFactory _factory;
        GlassSshSession _session;
        IByteLink _tunnel;

        public GlassSshLink(IPEndPoint endpoint, ITrainingKeySource keys, SshSuite suite, IRandomSource random, ITraceSink sink, string traceId, string sessionId, IStepGate gate, ITamperHook tamper)
        {
            _endpoint = endpoint;
            _factory = new GlassTransportFactory(keys);
            _request = new TransportRequest();
            _request.Protocol = WireProtocol.Ssh;
            _request.Role = EngineRole.Client;
            _request.Suite = suite;
            _request.Random = random;
            _request.Sink = sink;
            _request.TraceId = traceId;
            _request.SessionId = sessionId ?? traceId;
            _request.Gate = gate;
            _request.Tamper = tamper;
            _request.Hop = BridgeHopServers.Hop1;
            _request.Actor = "ce";
            _request.PeerActor = "gateway";
            _request.PeerName = endpoint.Address.ToString();
            _request.PeerPort = endpoint.Port;
            _request.KnownHosts = SshSetup.KnownHostLine(keys, suite, _request.PeerName, endpoint.Port);
            _request.Profile = DeviceProfile.Ce;
        }

        public string Kind { get { return KindName; } }

        public IFuture Open() { return AsyncProxy.Run(OpenBody()); }

        IEnumerable<IFuture> OpenBody()
        {
            IFuture<SocketLink> connected = SocketLink.Connect(_endpoint);
            yield return connected;
            _request.Link = connected.Result;
            IFuture<ISecureChannel> opened = _factory.Open(_request);
            yield return opened;
            _session = (GlassSshSession)opened.Result;
            IFuture<int> tunnel = _session.OpenTunnel(TargetHost, TargetPort);
            yield return tunnel;
            _tunnel = new ChannelByteLink(_session, tunnel.Result, false);
        }

        public IFuture Send(byte[] frame) { return FrameIo.WriteFrame(_tunnel, frame); }

        public IFuture<byte[]> Receive() { return FrameIo.ReadFrame(_tunnel); }

        public IFuture Close()
        {
            if (_session == null) return Futures.Completed;
            return _session.Close();
        }
    }
}
