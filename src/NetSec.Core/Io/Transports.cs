using System;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Trace;

namespace NetSec.Io
{
    public enum WireProtocol { Tls13, Tls11, Ssh }
    public enum EngineRole { Client, Server }
    public enum KexGroup { X25519, X25519MlKem768 }
    public enum SshSuite { Modern, Legacy }
    public enum Tls11Suite { RsaAes128CbcSha, EcdheRsaAes128CbcSha }

    public sealed class AppChunk
    {
        public int Channel;
        public byte[] Bytes;
    }

    public sealed class ChannelInfo
    {
        public string Protocol;
        public string Suite;
        public string Group;
        public string PeerName;
    }

    public interface ISecureChannel
    {
        ChannelInfo Info { get; }
        IFuture<AppChunk> Receive();
        IFuture Send(int channel, byte[] bytes);
        IFuture Close();
    }

    /// <summary>What the SSH channel adds. Data of a channel arrives in Receive with AppChunk.Channel set. Empty Bytes end the channel.</summary>
    public interface ISshChannel : ISecureChannel
    {
        IFuture<int> OpenExec(string command);
        IFuture<int> OpenTunnel(string host, int port);
    }

    /// <summary>Carries no key. A factory takes its key source at construction, so an IKeyHandle has no route into glass (D5).</summary>
    public sealed class TransportRequest
    {
        public WireProtocol Protocol;
        public EngineRole Role;
        public KexGroup Group;
        public SshSuite Suite;
        public Tls11Suite Tls11Suite;
        public IByteLink Link;
        public IRandomSource Random;
        public ITraceSink Sink;
        public IStepGate Gate;
        public ITamperHook Tamper;
        public string TraceId, Hop, PeerName;
        // The contract keeps DeviceProfile in NetSec.Bridge. tools/layer_check.py allows this one upward name.
        public NetSec.Bridge.DeviceProfile Profile;
    }

    public interface ITransportFactory
    {
        string Kind { get; }
        IFuture<ISecureChannel> Open(TransportRequest request);
    }

    public enum TransportDecision { Allowed, Refused }

    /// <summary>A rule. The factory applies the result.</summary>
    public static class TransportPolicy
    {
        public static TransportDecision Decide(NetSec.Bridge.DeviceProfile profile, string factoryKind, WireProtocol protocol)
        {
            if (profile == null) throw new ArgumentNullException("profile");
            return profile.Allows(protocol) ? TransportDecision.Allowed : TransportDecision.Refused;
        }
    }

    public sealed class GlassTransportFactory : ITransportFactory
    {
        readonly ITrainingKeySource _keys;

        public GlassTransportFactory(ITrainingKeySource keys)
        {
            if (keys == null) throw new ArgumentNullException("keys");
            _keys = keys;
        }

        public string Kind { get { return "glass"; } }

        /// <summary>S0 applies the policy. The TLS 1.3, TLS 1.1, and SSH engines arrive in S3 and S4.</summary>
        public IFuture<ISecureChannel> Open(TransportRequest request)
        {
            if (request == null) throw new ArgumentNullException("request");
            NetSec.Bridge.DeviceProfile profile = request.Profile ?? NetSec.Bridge.DeviceProfile.Modern;
            if (TransportPolicy.Decide(profile, Kind, request.Protocol) == TransportDecision.Refused)
                return Refuse(ErrorCodes.CeTransportUnavailable, profile.Name + " refuses " + request.Protocol);
            return Refuse(ErrorCodes.TransportNotBuilt, "the glass " + request.Protocol + " engine is not built yet");
        }

        static IFuture<ISecureChannel> Refuse(string code, string message)
        {
            return Futures.FromException<ISecureChannel>(new NetSecException(NetSecError.Of(code, message)));
        }
    }
}
