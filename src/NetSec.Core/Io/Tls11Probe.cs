using System;
using System.Collections.Generic;
using System.Net;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Platform;
using NetSec.Tls11;
using NetSec.Trace;

namespace NetSec.Io
{
    /// <summary>The TLS 1.1 half of Probe: one socket and one engine. The engine's own options send and close, so this code only joins the parts and reads the result.</summary>
    public static class Tls11Probe
    {
        const int DeadlineMs = 20000;
        const string ProbeSession = "probe";

        public static IFuture<ProbeResult> Connect(ProbeRequest r)
        {
            return AsyncProxy.Run<ProbeResult>(delegate(Return<ProbeResult> ret) { return ConnectBody(r, ret); });
        }

        /// <summary>Binds now, so the port is known at return. Answers one session.</summary>
        public static ProbeListener Listen(ProbeRequest r)
        {
            LinkListener listener = new LinkListener(new IPEndPoint(IPAddress.Loopback, r.Port));
            ProbeListener result = new ProbeListener();
            result.Port = listener.Port;
            result.Result = AsyncProxy.Run<ProbeResult>(delegate(Return<ProbeResult> ret) { return ListenBody(r, listener, ret); });
            return result;
        }

        static IEnumerable<IFuture> ConnectBody(ProbeRequest r, Return<ProbeResult> ret)
        {
            Tls11CipherSuite suite = SuiteOf(r);
            if (suite == null)
            {
                ret.Value = Failure(Tls11Codes.SuiteRefused, Tls11Checks.SuiteOffered);
                yield break;
            }
            IFuture<SocketLink> connected = SocketLink.Connect(new IPEndPoint(IPAddress.Parse(r.Host), r.Port));
            yield return Futures.Observe(connected);
            if (connected.IsFaulted || connected.IsCanceled)
            {
                ret.Value = Failure(ErrorCodes.LinkLost, connected.IsFaulted ? connected.Exception.Message : "connect canceled");
                yield break;
            }
            Tls11Options options = Common(r, suite, "client");
            options.PeerName = r.PeerName;
            Tls11Training.TrustTrainingRoot(options, new TrainingKeySource(), DateTime.UtcNow);
            options.CloseAfterReply = true;
            foreach (IFuture step in RunSession(r, connected.Result, Tls11Engine.CreateClient(options), ret)) yield return step;
        }

        static IEnumerable<IFuture> ListenBody(ProbeRequest r, LinkListener listener, Return<ProbeResult> ret)
        {
            IFuture<SocketLink> accepted = listener.Accept();
            yield return Futures.Observe(accepted);
            listener.Close();
            Tls11CipherSuite suite = SuiteOf(r);
            if (suite == null || accepted.IsFaulted || accepted.IsCanceled)
            {
                ret.Value = suite == null ? Failure(Tls11Codes.SuiteRefused, Tls11Checks.SuiteOffered) : Failure(ErrorCodes.LinkLost, "accept failed");
                yield break;
            }
            Tls11Options options = Common(r, suite, "server");
            Tls11Training.UseTrainingServerKey(options, new TrainingKeySource());
            foreach (IFuture step in RunSession(r, accepted.Result, Tls11Engine.CreateServer(options), ret)) yield return step;
        }

        static IEnumerable<IFuture> RunSession(ProbeRequest r, IByteLink link, Tls11Engine engine, Return<ProbeResult> ret)
        {
            ListSink events = new ListSink();
            List<byte> received = new List<byte>();
            EnginePump pump = new EnginePump(engine, link, events, new FreeRunGate(), r.Tamper, DeadlineMs);
            pump.OnApp = delegate(AppChunk chunk) { lock (received) received.AddRange(chunk.Bytes); };
            IFuture<PumpResult> run = pump.Run();
            yield return run;

            ProbeResult result = new ProbeResult();
            result.Completed = engine.Opened && run.Result.Error == null;
            result.Version = engine.Opened ? "TLSv1.1" : null;
            result.Suite = engine.Suite;
            result.AlertReceived = engine.AlertReceived;
            result.KeyLog = engine.KeyLog;
            lock (received) result.Received = received.ToArray();
            result.Events = events.Events;
            if (run.Result.Error != null)
            {
                result.Code = run.Result.Error.Code;
                result.CheckName = run.Result.Error.CheckName;
            }
            ret.Value = result;
        }

        /// <summary>No suite named means the weak one, because a default run would otherwise pick the best case.</summary>
        static Tls11CipherSuite SuiteOf(ProbeRequest r)
        {
            return r.Suite == null ? Tls11CipherSuite.RsaAes128CbcSha : Tls11CipherSuite.Find(r.Suite);
        }

        static Tls11Options Common(ProbeRequest r, Tls11CipherSuite suite, string actor)
        {
            Tls11Options o = new Tls11Options();
            o.Suite = suite;
            o.Random = r.Seed == 0 ? (IRandomSource)new OsRandom() : new SeededRandom(r.Seed);
            o.Stream = new TraceStream(ProbeSession + "/" + actor + "/tls11", ProbeSession, ProbeSession, null, actor, new MonotonicClock());
            o.Tamper = r.Tamper;
            o.SendOnOpen = r.Send;
            return o;
        }

        static ProbeResult Failure(string code, string checkName)
        {
            ProbeResult result = new ProbeResult();
            result.Code = code;
            result.CheckName = checkName;
            result.KeyLog = new string[0];
            result.Received = new byte[0];
            result.Events = new TraceEvent[0];
            return result;
        }
    }
}
