// CONTRACT STUB, Io, Keys, Trace, Machine, Pki, Errors and Bridge folders (program-design.md sections 1, 2.1, 2.2, 2.4, 2.5, 3).
// Namespace rule (ASSUMED, see CONTRACT.md): each Core folder is the namespace NetSec.<Folder>.
#pragma warning disable CS0169, CS0649, CS8618
using System;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Trace;

namespace NetSec.Errors
{
    public sealed class NetSecError
    {
        public string Code; public string Message; public string CheckName; public string Step; public bool Retryable; public string TraceId;
    }
}

namespace NetSec.Trace
{
    public sealed class TraceField
    {
        public string Name; public int Offset; public int Length; public string Kind; public bool VisibleToWire; public string Gloss;
    }

    public sealed class TraceSecret
    {
        public string Holder; public string Name; public byte[] Bytes; public string[] DerivedFrom;
    }

    public sealed class TraceCheck
    {
        public string Id; public string Name; public bool Passed; public string Code; public string Detail;
    }

    public sealed class TraceEvent
    {
        public readonly int Schema;
        public readonly string EventId;
        public readonly string StreamId;
        public readonly long StreamSeq;
        public readonly string SessionId, TraceId, Hop;
        public readonly string Actor, From, To;
        public readonly string Type, Message, Step;
        public readonly byte[] Wire, Plain;
        public readonly TraceField[] Fields;
        public readonly TraceSecret[] Secrets;
        public readonly TraceCheck Check;
        public readonly string WaitingFor;
        public readonly long AtMicros;
    }

    public interface ITraceSink { void Write(TraceEvent e); }

    public static class TraceJson { public static string ToLine(TraceEvent e) { throw new NotImplementedException(); } }
}

namespace NetSec.Keys
{
    public enum KeyAlgorithm { Ed25519, X25519, Rsa2048, Aes128, Aes256, Raw }          // ASSUMED members

    public interface ITrainingKey
    {
        string KeyId { get; }
        KeyAlgorithm Algorithm { get; }
        byte[] CopyMaterial();     // ASSUMED format: Ed25519 and X25519 = 32-byte seed, RSA = PKCS#8 PrivateKeyInfo DER, AES and DUKPT keys = raw bytes
        byte[] CopyPublic();       // ASSUMED format: Ed25519 and X25519 = 32 bytes, RSA = SubjectPublicKeyInfo DER
    }

    public interface IKeyHandle
    {
        string KeyId { get; }
        KeyAlgorithm Algorithm { get; }
        byte[] Public();
        byte[] Sign(byte[] message);
    }

    public interface ITrainingKeySource { ITrainingKey Find(string keyId); }
    public interface IKeyHandleSource { IKeyHandle Find(string keyId); }

    public sealed class TrainingKeySource : ITrainingKeySource
    {
        public TrainingKeySource() { throw new NotImplementedException(); }            // ASSUMED: parameterless
        public ITrainingKey Find(string keyId) { throw new NotImplementedException(); }
    }

    public static class KeyIds
    {
        public const string CaRoot = "ca-root", ServerTlsEd25519 = "server-tls-ed25519", ServerTls11Rsa = "server-tls11-rsa",
            SshHostEd25519 = "ssh-host-ed25519", SshHostRsa = "ssh-host-rsa", SshClient = "ssh-client",
            DukptBdk128 = "dukpt-bdk-128", DukptBdk256 = "dukpt-bdk-256", TokenIssuer = "token-issuer", AttackerEd25519 = "attacker-ed25519";   // ASSUMED values
    }
}

namespace NetSec.Pki
{
    public sealed class TrainingCa
    {
        public TrainingCa(ITrainingKeySource keys) { throw new NotImplementedException(); }       // ASSUMED
        public byte[] RootCertificateDer { get { throw new NotImplementedException(); } }          // ASSUMED
        /// <summary>ASSUMED: signs a leaf certificate for the given SubjectPublicKeyInfo (DER). The leaf carries dnsName as CN and as a dNSName SAN.</summary>
        public byte[] IssueServerCertificate(string dnsName, byte[] subjectPublicKeyInfoDer, DateTime notBefore, DateTime notAfter) { throw new NotImplementedException(); }
    }
}

namespace NetSec.Machine
{
    public enum TamperPoint { Plain, Wire }

    public sealed class TamperResult
    {
        public static readonly TamperResult Unchanged = null;                                     // ASSUMED
        public static TamperResult Replace(byte[] bytes) { throw new NotImplementedException(); }  // ASSUMED
    }

    public interface ITamperHook { TamperResult Apply(TamperPoint point, string streamId, long streamSeq, string message, byte[] bytes); }

    public interface IStepGate { IFuture Pass(TraceEvent e); }
}

namespace NetSec.Io
{
    public interface IByteLink
    {
        IFuture<int> Read(byte[] b, int off, int n);
        IFuture Write(byte[] b, int off, int n);
        void Close();
    }

    public enum WireProtocol { Tls13, Tls11, Ssh }
    public enum EngineRole { Client, Server }                         // ASSUMED members
    public enum KexGroup { X25519, X25519MlKem768 }                   // ASSUMED members
    public enum SshSuite { Modern, Legacy }                           // ASSUMED members
    public enum Tls11Suite { RsaAes128CbcSha, EcdheRsaAes128CbcSha }  // ASSUMED: the two named TLS 1.1 suites of the lab (TLS_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)

    public sealed class AppChunk { public int Channel; public byte[] Bytes; }           // ASSUMED

    public sealed class ChannelInfo { public string Protocol; public string Suite; public string Group; public string PeerName; }   // ASSUMED

    public interface ISecureChannel
    {
        ChannelInfo Info { get; }
        IFuture<AppChunk> Receive();
        IFuture Send(int channel, byte[] bytes);
        IFuture Close();
    }

    /// <summary>ASSUMED: what the SSH channel adds beyond ISecureChannel. Open a session that runs a command; open a direct-tcpip tunnel.</summary>
    public interface ISshChannel : ISecureChannel
    {
        IFuture<int> OpenExec(string command);
        IFuture<int> OpenTunnel(string host, int port);
    }

    public sealed class TransportRequest
    {
        public WireProtocol Protocol; public EngineRole Role; public KexGroup Group; public SshSuite Suite; public Tls11Suite Tls11Suite; public IByteLink Link;
        public IRandomSource Random; public ITraceSink Sink; public IStepGate Gate; public ITamperHook Tamper;
        public string TraceId, Hop, PeerName; public NetSec.Bridge.DeviceProfile Profile;
    }

    public interface ITransportFactory
    {
        string Kind { get; }
        IFuture<ISecureChannel> Open(TransportRequest request);
    }

    public sealed class GlassTransportFactory : ITransportFactory
    {
        public GlassTransportFactory(ITrainingKeySource keys) { throw new NotImplementedException(); }
        public string Kind { get { return "glass"; } }
        public IFuture<ISecureChannel> Open(TransportRequest request) { throw new NotImplementedException(); }
    }

    public enum TransportDecision { Allowed, Refused }                // ASSUMED shape
    public static class TransportPolicy
    {
        public static TransportDecision Decide(NetSec.Bridge.DeviceProfile profile, string factoryKind, WireProtocol protocol) { throw new NotImplementedException(); }
    }
}

namespace NetSec.Bridge
{
    public sealed class DeviceProfile
    {
        public static readonly DeviceProfile Ce = null;
        public static readonly DeviceProfile Modern = null;
    }
}
