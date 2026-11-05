using System;
using System.Collections.Generic;
using System.Net;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Platform;
using NetSec.Tls13;
using NetSec.Trace;

namespace NetSec.Io
{
    public sealed class ProbeRequest
    {
        public WireProtocol Protocol;
        public string Host;
        public int Port;
        public KexGroup Group;
        public string Suite;
        public SshSuite SshSuite;
        public string PeerName;
        public string KnownHostsFile;
        public bool OfferOnlyTls11;
        public string ClientKeyId;
        public string ExecCommand;
        public string TunnelTo;
        public byte[] Send;
        // The contract keeps TamperPlan in NetSec.Labs. tools/layer_check.py allows this one upward name.
        public NetSec.Labs.TamperPlan Tamper;
        /// <summary>0 means OsRandom.</summary>
        public int Seed;
    }

    public sealed class ProbeResult
    {
        public bool Completed;
        public string Code, CheckName, Version, Suite, Group;
        public int AlertReceived;
        public string[] KeyLog;
        public byte[] Received;
        public TraceEvent[] Events;
    }

    public sealed class ProbeListener
    {
        public int Port;
        public IFuture<ProbeResult> Result;
    }

    /// <summary>One socket and one engine, on both builds. The referee suites reach the glass engines through here (design section 11).</summary>
    public static class Probe
    {
        const int DeadlineMs = 20000;
        const string ProbeSession = "probe";

        public static IFuture<ProbeResult> Connect(ProbeRequest r)
        {
            if (r == null) throw new ArgumentNullException("r");
            NeedBuilt(r);
            return AsyncProxy.Run<ProbeResult>(delegate(Return<ProbeResult> ret) { return ConnectBody(r, ret); });
        }

        /// <summary>Binds now, so the port is known at return. Answers one session.</summary>
        public static ProbeListener Listen(ProbeRequest r)
        {
            if (r == null) throw new ArgumentNullException("r");
            NeedBuilt(r);
            LinkListener listener = new LinkListener(new IPEndPoint(IPAddress.Loopback, r.Port));
            ProbeListener result = new ProbeListener();
            result.Port = listener.Port;
            result.Result = AsyncProxy.Run<ProbeResult>(delegate(Return<ProbeResult> ret) { return ListenBody(r, listener, ret); });
            return result;
        }

        /// <summary>TLS 1.1 and SSH arrive in S4. The suite maps this exception to NOT RUN.</summary>
        static void NeedBuilt(ProbeRequest r)
        {
            if (r.Protocol != WireProtocol.Tls13) throw new NotImplementedException("the glass " + r.Protocol + " engine is not built yet");
        }

        static IEnumerable<IFuture> ConnectBody(ProbeRequest r, Return<ProbeResult> ret)
        {
            IFuture<SocketLink> connected = SocketLink.Connect(new IPEndPoint(IPAddress.Parse(r.Host), r.Port));
            yield return Futures.Observe(connected);
            if (connected.IsFaulted || connected.IsCanceled)
            {
                ret.Value = LinkFailure(connected.IsFaulted ? connected.Exception.Message : "connect canceled");
                yield break;
            }
            foreach (IFuture step in RunSession(r, connected.Result, Tls13Engine.CreateClient(ClientOptions(r)), ret)) yield return step;
        }

        static IEnumerable<IFuture> ListenBody(ProbeRequest r, LinkListener listener, Return<ProbeResult> ret)
        {
            IFuture<SocketLink> accepted = listener.Accept();
            yield return Futures.Observe(accepted);
            listener.Close();
            if (accepted.IsFaulted || accepted.IsCanceled)
            {
                ret.Value = LinkFailure(accepted.IsFaulted ? accepted.Exception.Message : "accept canceled");
                yield break;
            }
            foreach (IFuture step in RunSession(r, accepted.Result, Tls13Engine.CreateServer(ServerOptions(r)), ret)) yield return step;
        }

        static IEnumerable<IFuture> RunSession(ProbeRequest r, IByteLink link, Tls13Engine engine, Return<ProbeResult> ret)
        {
            bool isClient = engine.Peer == "server";
            ListSink events = new ListSink();
            List<byte> received = new List<byte>();
            CloseWhenDone[] watcher = new CloseWhenDone[1];
            if (r.Send != null) engine.Command(new EngineCommand(EngineCommandKind.Send, 0, r.Send, null));
            EnginePump pump = new EnginePump(engine, link, new WatchedSink(events, delegate { watcher[0].OnEvent(); }), new FreeRunGate(), r.Tamper, DeadlineMs);
            watcher[0] = new CloseWhenDone(pump, engine, isClient && r.Send == null);
            pump.OnApp = delegate(AppChunk chunk)
            {
                lock (received)
                {
                    received.AddRange(chunk.Bytes);
                    if (HaveReply(received, r.Send, isClient)) watcher[0].Close();
                }
            };

            IFuture<PumpResult> run = pump.Run();
            yield return run;

            ProbeResult result = new ProbeResult();
            result.Completed = engine.ReachedOpen && run.Result.Error == null;
            result.Version = engine.ReachedOpen ? "TLSv1.3" : null;
            result.Suite = engine.SuiteName;
            result.Group = engine.GroupName;
            result.AlertReceived = engine.AlertReceived > 0 ? engine.AlertReceived : 0;
            result.KeyLog = engine.KeyLogLines;
            lock (received) result.Received = received.ToArray();
            result.Events = events.Events;
            if (run.Result.Error != null)
            {
                result.Code = run.Result.Error.Code;
                result.CheckName = run.Result.Error.CheckName;
            }
            ret.Value = result;
        }

        /// <summary>A client waits for as many bytes as it sent. A server waits for one whole line. Either side's close_notify also ends the session.</summary>
        static bool HaveReply(List<byte> received, byte[] sent, bool isClient)
        {
            if (isClient) return sent == null || received.Count >= sent.Length;
            return received.Contains(10);
        }

        static Tls13Options CommonOptions(ProbeRequest r, string actor, string peer)
        {
            Tls13Options o = new Tls13Options();
            string streamId = ProbeSession + "/" + actor + "/tls13";
            o.Stream = new TraceStream(streamId, ProbeSession, ProbeSession, null, actor, new MonotonicClock());
            o.Peer = peer;
            o.Random = r.Seed == 0 ? (IRandomSource)new OsRandom() : new SeededRandom(r.Seed);
            o.Tamper = r.Tamper;
            o.Group = r.Group == KexGroup.X25519 ? Tls13Group.X25519 : Tls13Group.X25519MlKem768;
            o.ServerName = r.PeerName ?? TrainingPki.ServerName;
            o.Now = DateTime.UtcNow;
            return o;
        }

        static Tls13Options ClientOptions(ProbeRequest r)
        {
            Tls13Options o = CommonOptions(r, "client", "server");
            o.TrustAnchors = new byte[][] { new TrainingCa(new TrainingKeySource()).RootCertificateDer };
            o.OfferOnlyTls11 = r.OfferOnlyTls11;
            return o;
        }

        static Tls13Options ServerOptions(ProbeRequest r)
        {
            Tls13Options o = CommonOptions(r, "server", "client");
            ITrainingKeySource keys = new TrainingKeySource();
            ITrainingKey key = keys.Find(KeyIds.ServerTlsEd25519);
            o.CertificateChain = new byte[][] { TrainingPki.ServerCertificate(new TrainingCa(keys), key) };
            o.SigningSeed = key.CopyMaterial();
            return o;
        }

        static ProbeResult LinkFailure(string detail)
        {
            ProbeResult result = new ProbeResult();
            result.Code = ErrorCodes.LinkLost;
            result.CheckName = detail;
            result.KeyLog = new string[0];
            result.Received = new byte[0];
            result.Events = new TraceEvent[0];
            return result;
        }

        sealed class WatchedSink : ITraceSink
        {
            readonly ITraceSink _inner;
            readonly Action _after;
            public WatchedSink(ITraceSink inner, Action after) { _inner = inner; _after = after; }
            public void Write(TraceEvent e) { _inner.Write(e); _after(); }
        }

        /// <summary>Ends the session once. With nothing to send, a client ends it the moment the engine reaches Open.</summary>
        sealed class CloseWhenDone
        {
            readonly EnginePump _pump;
            readonly Tls13Engine _engine;
            readonly bool _closeAtOpen;
            int _closed;

            public CloseWhenDone(EnginePump pump, Tls13Engine engine, bool closeAtOpen)
            {
                _pump = pump; _engine = engine; _closeAtOpen = closeAtOpen;
            }

            public void OnEvent()
            {
                if (_closeAtOpen && _engine.ReachedOpen) Close();
            }

            public void Close()
            {
                if (System.Threading.Interlocked.Exchange(ref _closed, 1) == 0) _pump.Enqueue(EngineCommand.Close);
            }
        }
    }
}
