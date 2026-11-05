using System;
using System.Collections.Generic;
using System.Net;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Platform;
using NetSec.Trace;

namespace NetSec.Bridge
{
    /// <summary>How the CE reaches the gateway side. D7: glass SSH, glass TLS 1.1, or a plain socket that an external ssh.exe -L forwards.</summary>
    public interface IDeviceLink
    {
        string Kind { get; }
        IFuture Open();
        IFuture Send(byte[] frame);

        /// <summary>The next frame, or null when the peer closed.</summary>
        IFuture<byte[]> Receive();
        IFuture Close();
    }

    /// <summary>The CE speaks plain bytes to a local port. An external ssh.exe -L carries them, so this code does no SSH on this path.</summary>
    public sealed class ExternalForwardLink : IDeviceLink
    {
        const string Hop = "local";
        readonly IPEndPoint _endpoint;
        readonly ITraceSink _sink;
        readonly TraceStream _stream;
        SocketLink _link;

        public ExternalForwardLink(IPEndPoint endpoint, ITraceSink sink, string streamId, string traceId, IClock clock)
        {
            _endpoint = endpoint;
            _sink = sink;
            _stream = new TraceStream(streamId, traceId, traceId, Hop, "ce", clock);
        }

        public string Kind { get { return "external-forward"; } }

        public IFuture Open()
        {
            return AsyncProxy.Run(OpenBody());
        }

        IEnumerable<IFuture> OpenBody()
        {
            IFuture<SocketLink> connected = SocketLink.Connect(_endpoint);
            yield return connected;
            _link = connected.Result;
        }

        public IFuture Send(byte[] frame)
        {
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = "wire.sent";
            draft.From = "ce";
            draft.To = "gateway";
            draft.Message = "PinEnvelope";
            draft.Wire = frame;
            _sink.Write(_stream.Stamp(draft));
            return FrameIo.WriteFrame(_link, frame);
        }

        public IFuture<byte[]> Receive()
        {
            return FrameIo.ReadFrame(_link);
        }

        public IFuture Close()
        {
            _link.Close();
            return Futures.Completed;
        }
    }

    public sealed class CeRunOptions
    {
        public IPEndPoint PinPad, Gateway;
        public string LinkKind;
        public SshSuite Suite;
        public IRandomSource Random;
        public ITrainingKeySource Keys;
        public IStepGate Gate;
        public ITamperHook Tamper;

        /// <summary>Null means the envelope's trace id.</summary>
        public string SessionId;
        public ITraceSink Sink;
        public IClock Clock;
    }

    /// <summary>Ok repeats what the reply says. The CE holds no key that could check the reply, so a forged reply reads the same (lesson 9 teaches this).</summary>
    public sealed class CeRunResult
    {
        public bool Ok;
        public string Code, TraceId;
    }

    /// <summary>
    /// The CE's whole job in the bridge: take a sealed envelope from the PIN pad, relay it through a device link, and hand the bank's reply back.
    /// It can read the card number and the KSN. It holds no key that opens the PIN block.
    /// </summary>
    public static class CeDeviceFlow
    {
        public const string LinkExternalForward = "external-forward";

        public static IFuture<CeRunResult> Run(CeRunOptions o)
        {
            if (o == null) throw new ArgumentNullException("o");
            return AsyncProxy.Run<CeRunResult>(delegate(Return<CeRunResult> ret) { return Body(o, ret); });
        }

        static IEnumerable<IFuture> Body(CeRunOptions o, Return<CeRunResult> ret)
        {
            CeRunResult result = new CeRunResult();
            ret.Value = result;

            IFuture<SocketLink> padConnected = SocketLink.Connect(o.PinPad);
            yield return padConnected;
            SocketLink pad = padConnected.Result;
            IFuture<byte[]> envelopeRead = FrameIo.ReadFrame(pad);
            yield return envelopeRead;
            if (envelopeRead.Result == null)
            {
                result.Code = ErrorCodes.PeerClosedEarly;
                pad.Close();
                yield break;
            }
            PinEnvelope envelope = PinEnvelope.Parse(envelopeRead.Result);
            result.TraceId = envelope.TraceId;

            string session = o.SessionId ?? envelope.TraceId;
            TraceStream stream = new TraceStream(session + "/ce/bridge", session, envelope.TraceId, null, "ce", o.Clock);
            TraceEventDraft taken = new TraceEventDraft();
            taken.Type = "ce.envelope.taken";
            taken.Message = "PinEnvelope";
            taken.Plain = envelope.Bytes;
            o.Sink.Write(stream.Stamp(taken));

            IDeviceLink link = LinkFor(o, envelope.TraceId);
            if (link == null)
            {
                result.Code = ErrorCodes.CeLinkNotBuilt;
                pad.Close();
                yield break;
            }

            // A fault on the link ends the relay. The CE still closes both sides, and the result names what stopped it.
            IFuture opened = link.Open();
            yield return Futures.Observe(opened);
            if (opened.IsFaulted || opened.IsCanceled)
            {
                result.Code = CodeOf(opened);
                yield return Futures.Observe(link.Close());
                pad.Close();
                yield break;
            }
            IFuture sent = link.Send(envelope.Bytes);
            yield return Futures.Observe(sent);
            IFuture<byte[]> replyRead = link.Receive();
            yield return Futures.Observe(replyRead);
            if (replyRead.IsFaulted || replyRead.IsCanceled)
            {
                result.Code = CodeOf(replyRead);
            }
            else if (replyRead.Result == null)
            {
                result.Code = ErrorCodes.PeerClosedEarly;
            }
            else
            {
                string code;
                result.Ok = BankReply.Read(replyRead.Result, out code);
                result.Code = code;
                TraceEventDraft relayed = new TraceEventDraft();
                relayed.Type = "ce.reply.relayed";
                relayed.Message = result.Ok ? "accepted" : code;
                o.Sink.Write(stream.Stamp(relayed));
                yield return FrameIo.WriteFrame(pad, replyRead.Result);
            }
            yield return Futures.Observe(link.Close());
            pad.Close();
        }

        static string CodeOf(IFuture ended)
        {
            NetSecException named = FirstNamed(ended.Exception);
            return named != null ? named.Error.Code : ErrorCodes.LinkLost;
        }

        static NetSecException FirstNamed(Exception e)
        {
            for (Exception at = e; at != null; at = at.InnerException)
            {
                NetSecException named = at as NetSecException;
                if (named != null) return named;
            }
            return null;
        }

        static IDeviceLink LinkFor(CeRunOptions o, string traceId)
        {
            if (o.LinkKind == LinkExternalForward)
                return new ExternalForwardLink(o.Gateway, o.Sink, traceId + "/ce/forward", traceId, o.Clock);
            if (o.LinkKind == GlassSshLink.KindName)
                return new GlassSshLink(o.Gateway, o.Keys, o.Suite, o.Random, o.Sink, traceId, o.SessionId, o.Gate, o.Tamper);
            return null;
        }
    }

    /// <summary>The budget check, as a rule. It gates what transfers to a board. A desktop number stays a number.</summary>
    public sealed class BudgetSample
    {
        public int PoolWorkersGranted;
        public int DedicatedThreads;
        public long ManagedHeapBytes;
    }

    public sealed class BudgetVerdict
    {
        public bool Within;
        public string Detail;
    }

    public static class BudgetJudge
    {
        public static BudgetVerdict Judge(DeviceProfile p, BudgetSample s)
        {
            if (p == null) throw new ArgumentNullException("p");
            if (s == null) throw new ArgumentNullException("s");
            BudgetVerdict verdict = new BudgetVerdict();
            if (s.PoolWorkersGranted > p.PoolThreads) verdict.Detail = "pool " + s.PoolWorkersGranted + " is above the cap of " + p.PoolThreads;
            else if (s.DedicatedThreads > p.DedicatedThreads) verdict.Detail = "dedicated threads " + s.DedicatedThreads + " are above " + p.DedicatedThreads;
            else if (s.ManagedHeapBytes > p.RamBytes) verdict.Detail = "managed heap " + s.ManagedHeapBytes + " is above " + p.RamBytes;
            else verdict.Within = true;
            return verdict;
        }
    }
}
