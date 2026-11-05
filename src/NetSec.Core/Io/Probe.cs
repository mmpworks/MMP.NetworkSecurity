using System;
using MMP.AsyncProxy;
using NetSec.Errors;
using NetSec.Machine;
using NetSec.Trace;

namespace NetSec.Io
{
    /// <summary>One socket, one engine, on both builds (design section 11). Tamper is the interface a TamperPlan fills, because Io sits below Labs.</summary>
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
        public ITamperHook Tamper;
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

    public static class Probe
    {
        public static IFuture<ProbeResult> Connect(ProbeRequest r)
        {
            if (r == null) throw new ArgumentNullException("r");
            switch (r.Protocol)
            {
                case WireProtocol.Ssh: return SshProbe.Connect(r);
                default: return Futures.FromResult<ProbeResult>(NotBuilt(r));
            }
        }

        public static ProbeListener Listen(ProbeRequest r)
        {
            if (r == null) throw new ArgumentNullException("r");
            switch (r.Protocol)
            {
                case WireProtocol.Ssh: return SshProbe.Listen(r);
                default:
                    ProbeListener listener = new ProbeListener();
                    listener.Result = Futures.FromResult<ProbeResult>(NotBuilt(r));
                    return listener;
            }
        }

        static ProbeResult NotBuilt(ProbeRequest r)
        {
            ProbeResult result = new ProbeResult();
            result.Code = ErrorCodes.TransportNotBuilt;
            result.CheckName = "the " + r.Protocol + " probe is not built yet";
            result.KeyLog = new string[0];
            result.Events = new TraceEvent[0];
            return result;
        }
    }
}
