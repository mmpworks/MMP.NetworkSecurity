using System;
using System.Collections.Generic;
using MMP.AsyncProxy;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Platform;
using NetSec.Tls13;
using NetSec.Trace;

namespace NetSec.Io
{
    /// <summary>
    /// A glass TLS 1.3 engine on a link, behind ISecureChannel. Open returns at once. Data sent early waits in the engine until the handshake ends.
    /// A failed handshake faults the next Receive with the engine's named error. A clean close gives a chunk with empty Bytes.
    /// </summary>
    sealed class GlassTls13Channel : ISecureChannel
    {
        const int DeadlineMs = 30000;

        readonly object _lock = new object();
        readonly Queue<AppChunk> _arrived = new Queue<AppChunk>();
        readonly Tls13Engine _engine;
        readonly EnginePump _pump;
        Promise<AppChunk> _waiter;
        PumpResult _ended;

        public GlassTls13Channel(TransportRequest request, Tls13Engine engine)
        {
            _engine = engine;
            _pump = new EnginePump(engine, request.Link, request.Sink, request.Gate, request.Tamper, DeadlineMs);
            _pump.OnApp = Arrive;
            IFuture<PumpResult> run = _pump.Run();
            run.GetAwaiter().OnCompleted(delegate { End(run); });
        }

        public ChannelInfo Info
        {
            get
            {
                ChannelInfo info = new ChannelInfo();
                info.Protocol = "TLSv1.3";
                info.Suite = _engine.SuiteName;
                info.Group = _engine.GroupName;
                info.PeerName = _engine.Peer;
                return info;
            }
        }

        public IFuture<AppChunk> Receive()
        {
            lock (_lock)
            {
                if (_arrived.Count > 0) return Futures.FromResult<AppChunk>(_arrived.Dequeue());
                if (_ended != null) return Ending(_ended);
                _waiter = new Promise<AppChunk>(PromiseOptions.RunContinuationsAsynchronously);
                return _waiter.Future;
            }
        }

        public IFuture Send(int channel, byte[] bytes)
        {
            return _pump.Enqueue(new EngineCommand(EngineCommandKind.Send, channel, bytes, null));
        }

        public IFuture Close()
        {
            return _pump.Enqueue(EngineCommand.Close);
        }

        void Arrive(AppChunk chunk)
        {
            Promise<AppChunk> waiter;
            lock (_lock)
            {
                waiter = _waiter;
                _waiter = null;
                if (waiter == null) _arrived.Enqueue(chunk);
            }
            if (waiter != null) waiter.TrySetResult(chunk);
        }

        void End(IFuture<PumpResult> run)
        {
            Promise<AppChunk> waiter;
            PumpResult result = run.IsFaulted ? new PumpResult(EngineStatus.Failed, NetSecError.Of(ErrorCodes.LinkLost, run.Exception.Message), 0, 0) : run.Result;
            lock (_lock)
            {
                _ended = result;
                waiter = _waiter;
                _waiter = null;
            }
            if (waiter == null) return;
            if (result.Error != null) waiter.TrySetException(new NetSecException(result.Error));
            else waiter.TrySetResult(EndChunk());
        }

        static IFuture<AppChunk> Ending(PumpResult result)
        {
            if (result.Error != null) return Futures.FromException<AppChunk>(new NetSecException(result.Error));
            return Futures.FromResult<AppChunk>(EndChunk());
        }

        static AppChunk EndChunk()
        {
            AppChunk chunk = new AppChunk();
            chunk.Bytes = new byte[0];
            return chunk;
        }

        /// <summary>Builds the engine for a request. The key source comes from the factory, and the request carries no key (D5).</summary>
        public static Tls13Engine CreateEngine(TransportRequest r, ITrainingKeySource keys)
        {
            bool client = r.Role == EngineRole.Client;
            string actor = r.Actor ?? (client ? "client" : "server");
            string session = r.SessionId ?? r.TraceId ?? "glass";
            Tls13Options o = new Tls13Options();
            o.Stream = new TraceStream(session + "/" + actor + "/tls13", session, r.TraceId, r.Hop, actor, new MonotonicClock());
            o.Peer = client ? "server" : "client";
            o.Random = r.Random ?? new OsRandom();
            o.Tamper = r.Tamper;
            o.Group = r.Group == KexGroup.X25519 ? Tls13Group.X25519 : Tls13Group.X25519MlKem768;
            o.ServerName = r.PeerName ?? TrainingPki.ServerName;
            o.Now = DateTime.UtcNow;
            TrainingCa ca = new TrainingCa(keys);
            if (client)
            {
                o.TrustAnchors = new byte[][] { ca.RootCertificateDer };
                return Tls13Engine.CreateClient(o);
            }
            ITrainingKey key = keys.Find(KeyIds.ServerTlsEd25519);
            o.CertificateChain = new byte[][] { TrainingPki.ServerCertificate(ca, key) };
            o.SigningSeed = key.CopyMaterial();
            return Tls13Engine.CreateServer(o);
        }
    }
}
