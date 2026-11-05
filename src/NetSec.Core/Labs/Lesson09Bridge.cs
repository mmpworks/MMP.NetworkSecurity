using System;
using System.Collections.Generic;
using System.Net;
using MMP.AsyncProxy;
using NetSec.Bridge;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Dukpt;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Tls13;
using NetSec.Trace;

namespace NetSec.Labs
{
    /// <summary>
    /// Lesson 9. One PIN crosses two hops inside two different secure channels, and only the bank can open it. This lab runs the bridge's own code in
    /// one process, on loopback, so a learner can step through it. The acceptance suite runs the same code as five processes.
    /// Built to show the parts. Do not copy. Nothing here has run on CE. docs/lesson-9-names.md lists every name.
    /// </summary>
    public sealed class Lesson09Bridge : ILab
    {
        public const string OptionFlipPinBlock = "flip-pin-block";

        const string Pin = "1234", Pan = "4111111111111111";
        const string DefaultTraceId = "lab-09-trace";

        public string LabId { get { return "lab-09-bridge"; } }

        public IFuture<LabResult> Run(LabContext c)
        {
            if (c == null) throw new ArgumentNullException("c");
            return AsyncProxy.Run<LabResult>(delegate(Return<LabResult> ret) { return Body(c, ret); });
        }

        static IEnumerable<IFuture> Body(LabContext c, Return<LabResult> ret)
        {
            string traceId = c.TraceId ?? c.SessionId ?? DefaultTraceId;
            ITrainingKeySource keys = new TrainingKeySource();
            ITamperHook plan = LabPair.Plan(c);
            FailureWatch watch = new FailureWatch(c.Sink);

            // Each side's random stream forks here, before any pump starts, so thread timing cannot change who draws which bytes.
            IRandomSource saleRandom = LabPair.Fork(c), ceRandom = LabPair.Fork(c), gatewayRandom = LabPair.Fork(c), nextHopRandom = LabPair.Fork(c), serverRandom = LabPair.Fork(c);

            LinkListener padListener = NewListener(), gatewayListener = NewListener(), serverListener = NewListener(), bankListener = NewListener();

            PadSale sale = PinPadCore.Sell(new DukptPinPad(Hex.Decode(PinPadCore.InjectedInitialKey), Hex.Decode(PinPadCore.InjectedKeyId)), traceId, Pin, Pan, saleRandom);
            TraceEventDraft locked = new TraceEventDraft();
            locked.Type = "pin.block.locked";
            locked.Message = "PinEnvelope";
            locked.Plain = sale.Envelope.Bytes;
            yield return Publish(c, watch, Stream(c, traceId, "reader").Stamp(locked));

            HopServerOptions gateway = HopOptions(c, keys, gatewayRandom, watch, plan, traceId);
            gateway.NextHopRandom = nextHopRandom;
            HopServerOptions server = HopOptions(c, keys, serverRandom, watch, plan, traceId);
            bool flip = LabPair.Option(c, OptionFlipPinBlock) == "yes";

            IFuture padRun = AsyncProxy.Run(PadBody(padListener, sale));
            IFuture gatewayRun = AsyncProxy.Run(GatewayBody(gatewayListener, gateway, serverListener.Port, flip));
            IFuture serverRun = AsyncProxy.Run(ServerBody(serverListener, server, bankListener.Port));
            IFuture bankRun = AsyncProxy.Run(BankBody(bankListener, c, watch, keys, traceId));

            CeRunOptions ce = new CeRunOptions();
            ce.PinPad = new IPEndPoint(IPAddress.Loopback, padListener.Port);
            ce.Gateway = new IPEndPoint(IPAddress.Loopback, gatewayListener.Port);
            ce.LinkKind = GlassSshLink.KindName;
            ce.Suite = SshSuite.Modern;
            ce.Random = ceRandom;
            ce.Keys = keys;
            ce.Sink = watch;
            ce.Clock = c.Clock;
            ce.Gate = c.Gate;
            ce.Tamper = plan;
            ce.SessionId = c.SessionId;
            IFuture<CeRunResult> flow = CeDeviceFlow.Run(ce);
            yield return Futures.Observe(flow);

            // A hop that the run never reached still waits at its Accept. Closing the listener ends that wait.
            padListener.Close();
            gatewayListener.Close();
            serverListener.Close();
            bankListener.Close();
            yield return Futures.Observe(padRun);
            yield return Futures.Observe(gatewayRun);
            yield return Futures.Observe(serverRun);
            yield return Futures.Observe(bankRun);

            ret.Value = Result(flow, watch);
        }

        /// <summary>LabPair.Stream takes the trace id from the context, and a context may hold none. Every stream here carries the one id.</summary>
        static TraceStream Stream(LabContext c, string traceId, string actor)
        {
            string session = c.SessionId ?? traceId;
            return new TraceStream(session + "/" + actor + "/bridge", session, traceId, null, actor, c.Clock);
        }

        static LinkListener NewListener() { return new LinkListener(new IPEndPoint(IPAddress.Loopback, 0)); }

        static HopServerOptions HopOptions(LabContext c, ITrainingKeySource keys, IRandomSource random, ITraceSink sink, ITamperHook plan, string traceId)
        {
            HopServerOptions o = new HopServerOptions();
            o.Keys = keys;
            o.Random = random;
            o.Sink = sink;
            o.Gate = c.Gate;
            o.Tamper = plan;
            o.SessionId = c.SessionId;
            o.TraceId = traceId;
            return o;
        }

        static LabResult Result(IFuture<CeRunResult> flow, FailureWatch watch)
        {
            LabResult result = new LabResult();
            if (watch.Code != null)
            {
                result.FailedCode = watch.Code;
                result.FailedCheck = watch.Check;
                return result;
            }
            if (flow.IsFaulted || flow.IsCanceled || !flow.Result.Ok)
            {
                result.FailedCode = flow.IsFaulted || flow.IsCanceled ? ErrorCodes.LinkLost : flow.Result.Code;
                result.FailedCheck = "peer stayed until the end";
                return result;
            }
            result.Completed = true;
            return result;
        }

        static IFuture Publish(LabContext c, ITraceSink sink, TraceEvent e)
        {
            return AsyncProxy.Run(PublishBody(c, sink, e));
        }

        static IEnumerable<IFuture> PublishBody(LabContext c, ITraceSink sink, TraceEvent e)
        {
            yield return c.Gate.Pass(e);
            sink.Write(e);
        }

        static IEnumerable<IFuture> PadBody(LinkListener listener, PadSale sale)
        {
            IFuture<SocketLink> accepted = listener.Accept();
            yield return Futures.Observe(accepted);
            if (accepted.IsFaulted || accepted.IsCanceled) yield break;
            yield return Futures.Observe(FrameIo.WriteFrame(accepted.Result, sale.Envelope.Bytes));
            // The reply is advice for the pad's screen.
            yield return Futures.Observe(FrameIo.ReadFrame(accepted.Result));
            accepted.Result.Close();
        }

        static IEnumerable<IFuture> GatewayBody(LinkListener listener, HopServerOptions o, int nextPort, bool flip)
        {
            IFuture<SocketLink> accepted = listener.Accept();
            yield return Futures.Observe(accepted);
            if (accepted.IsFaulted || accepted.IsCanceled) yield break;
            yield return Futures.Observe(BridgeHopServers.ServeGateway(accepted.Result, o, nextPort, flip));
        }

        static IEnumerable<IFuture> ServerBody(LinkListener listener, HopServerOptions o, int bankPort)
        {
            IFuture<SocketLink> accepted = listener.Accept();
            yield return Futures.Observe(accepted);
            if (accepted.IsFaulted || accepted.IsCanceled) yield break;
            yield return Futures.Observe(BridgeHopServers.ServeServer(accepted.Result, o, bankPort));
        }

        static IEnumerable<IFuture> BankBody(LinkListener listener, LabContext c, ITraceSink sink, ITrainingKeySource keys, string traceId)
        {
            IFuture<SocketLink> accepted = listener.Accept();
            yield return Futures.Observe(accepted);
            if (accepted.IsFaulted || accepted.IsCanceled) yield break;

            byte[] bdk = keys.Find(KeyIds.DukptBdk128).CopyMaterial();
            KsnLedger ledger = new KsnLedger();
            TraceStream stream = Stream(c, traceId, "bank");
            while (true)
            {
                IFuture<byte[]> frame = FrameIo.ReadFrame(accepted.Result);
                yield return Futures.Observe(frame);
                if (frame.IsFaulted || frame.IsCanceled || frame.Result == null) break;
                BankDecision decision = BankHsmCore.Decide(bdk, ledger, frame.Result);
                TraceEvent[] events = BankTrace.Events(stream, decision);
                for (int i = 0; i < events.Length; i++) yield return Publish(c, sink, events[i]);
                yield return Futures.Observe(FrameIo.WriteFrame(accepted.Result, BankReply.Build(decision)));
            }
            accepted.Result.Close();
        }

        /// <summary>
        /// Passes each event on, and keeps the first failed check that names a cause. A peer that closed, or an alert received, follows from a catch on the
        /// other side, so it never names the catch.
        /// </summary>
        sealed class FailureWatch : ITraceSink
        {
            readonly ITraceSink _inner;
            readonly object _lock = new object();

            public FailureWatch(ITraceSink inner) { _inner = inner; }

            public string Code { get; private set; }
            public string Check { get; private set; }

            public void Write(TraceEvent e)
            {
                if (e.Check != null && !e.Check.Passed && LabPair.NamesACause(e.Check.Code))
                    lock (_lock)
                        if (Code == null) { Code = e.Check.Code; Check = e.Check.Name; }
                _inner.Write(e);
            }
        }
    }
}
