using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Machine;
using NetSec.Platform;
using NetSec.Trace;

namespace NetSec.Labs
{
    public enum AttackOutcome { Rejected, Accepted, NoCheck }

    /// <summary>A tamper as data. It flips one byte of one message at one point, by message name or by stream address.</summary>
    public sealed class TamperPlan : ITamperHook
    {
        public string Kind = "flip-byte";
        public TamperPoint Point = TamperPoint.Wire;
        public string Message;
        public string StreamId;
        public long StreamSeq;
        public int Offset;
        public int Xor = 1;

        public TamperResult Apply(TamperPoint point, string streamId, long streamSeq, string message, byte[] bytes)
        {
            if (point != Point || !Matches(streamId, streamSeq, message)) return TamperResult.Unchanged;
            if (Offset < 0 || Offset >= bytes.Length) return TamperResult.Unchanged;
            byte[] changed = (byte[])bytes.Clone();
            changed[Offset] = (byte)(changed[Offset] ^ Xor);
            return TamperResult.Replace(changed);
        }

        bool Matches(string streamId, long streamSeq, string message)
        {
            if (StreamId != null) return StreamId == streamId && StreamSeq == streamSeq;
            return Message == message;
        }
    }

    public sealed class LabOption
    {
        public string Name;
        public string Value;
    }

    public sealed class AttackDefinition
    {
        public string AttackId;
        public int Lesson;
        public string Kind;
        public TamperPlan Plan;
        public LabOption[] Options;
        public AttackOutcome Expect;
        public string ExpectCode, ExpectCheck;
    }

    public sealed class LabContext
    {
        public int Seed;
        public string SessionId, TraceId;
        public ITransportFactory Transports;
        public IStepGate Gate;
        public ITraceSink Sink;
        public IClock Clock;
        public IRandomSource Random;
        public AttackDefinition Attack;
    }

    public sealed class LabResult
    {
        public bool Completed;
        public string FailedCode;
        public string FailedCheck;
    }

    public interface ILab
    {
        string LabId { get; }
        IFuture<LabResult> Run(LabContext context);
    }

    /// <summary>Lesson 0: a client and a server on loopback, each its own EnginePump. The pipe has no lock.</summary>
    public sealed class EchoLab : ILab
    {
        public const int DeadlineMs = 30000;
        static readonly byte[] Message = Encoding.UTF8.GetBytes("hello, pipe");

        public string LabId { get { return "lab-00-echo"; } }

        public IFuture<LabResult> Run(LabContext context)
        {
            if (context == null) throw new ArgumentNullException("context");
            return AsyncProxy.Run<LabResult>(delegate(Return<LabResult> ret) { return Body(context, ret); });
        }

        static IEnumerable<IFuture> Body(LabContext c, Return<LabResult> ret)
        {
            LinkListener listener = new LinkListener(new IPEndPoint(IPAddress.Loopback, 0));
            IFuture<SocketLink> accepted = listener.Accept();
            IFuture<SocketLink> connected = SocketLink.Connect(new IPEndPoint(IPAddress.Loopback, listener.Port));
            yield return accepted;
            yield return connected;
            listener.Close();

            int deadline = c.Gate is FreeRunGate ? DeadlineMs : 0;
            ITamperHook attack = c.Attack == null ? null : c.Attack.Plan;
            EchoEngine server = EchoEngine.Server(Stream(c, "server"), null);
            EchoEngine client = EchoEngine.Client(Message, Stream(c, "client"), attack);
            IFuture<PumpResult> serverRun = new EnginePump(server, accepted.Result, c.Sink, c.Gate, null, deadline, c.Clock).Run();
            IFuture<PumpResult> clientRun = new EnginePump(client, connected.Result, c.Sink, c.Gate, attack, deadline, c.Clock).Run();
            yield return clientRun;
            yield return serverRun;

            ret.Value = Result(clientRun.Result);
        }

        static TraceStream Stream(LabContext c, string actor)
        {
            return new TraceStream(c.SessionId + "/" + actor + "/echo", c.SessionId, c.TraceId, null, actor, c.Clock);
        }

        static LabResult Result(PumpResult run)
        {
            LabResult result = new LabResult();
            result.Completed = run.Error == null;
            if (run.Error != null)
            {
                result.FailedCode = run.Error.Code;
                result.FailedCheck = run.Error.CheckName;
            }
            return result;
        }
    }

    public static class LabCatalog
    {
        /// <summary>The lab for a lesson number, or null when the lesson is not built yet.</summary>
        public static ILab Find(int lesson)
        {
            return lesson == 0 ? new EchoLab() : null;
        }
    }

    public static class AttackCatalog
    {
        public static AttackDefinition[] All
        {
            get
            {
                TamperPlan flip = new TamperPlan();
                flip.Message = EchoEngine.HelloName;
                flip.Offset = 3;
                AttackDefinition toy = new AttackDefinition();
                toy.AttackId = "L0-flip-wire-byte";
                toy.Lesson = 0;
                toy.Kind = "flip-byte";
                toy.Plan = flip;
                toy.Options = new LabOption[0];
                toy.Expect = AttackOutcome.Rejected;
                toy.ExpectCode = ErrorCodes.EchoMismatch;
                toy.ExpectCheck = EchoEngine.CompareCheck;
                return new AttackDefinition[] { toy };
            }
        }
    }
}
