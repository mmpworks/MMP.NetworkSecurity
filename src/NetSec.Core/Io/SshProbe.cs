using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Platform;
using NetSec.Ssh;
using NetSec.Trace;

namespace NetSec.Io
{
    /// <summary>Builds the glass SSH options from a key source. A factory, a probe and a lab all start here, so the key choice has one home.</summary>
    public static class SshSetup
    {
        public const string DefaultUser = "training";

        /// <summary>A silent peer ends in LINK_DEADLINE after this long. The pump restarts the clock while a learner holds an event at the gate (docs/learnings.md S3 item 1).</summary>
        public const int ReadDeadlineMs = 30000;

        public static SshAlgorithms AlgorithmsFor(SshSuite suite)
        {
            return suite == SshSuite.Legacy ? SshAlgorithms.Legacy : SshAlgorithms.Modern;
        }

        public static string HostKeyIdFor(SshSuite suite)
        {
            return suite == SshSuite.Legacy ? KeyIds.SshHostRsa : KeyIds.SshHostEd25519;
        }

        public static SshClientOptions Client(ITrainingKeySource keys, SshSuite suite, IRandomSource random, string host, int port, string knownHosts, bool trustFirstUse)
        {
            SshClientOptions o = new SshClientOptions();
            o.Algorithms = AlgorithmsFor(suite);
            o.Random = random;
            o.Host = host;
            o.Port = port;
            o.KnownHosts = knownHosts;
            o.TrustFirstUse = trustFirstUse;
            o.User = DefaultUser;
            o.UserKey = keys.Find(KeyIds.SshClient);
            return o;
        }

        /// <summary>The line a device holds for its gateway, so its first connect checks the host key. The suite picks which training key that is.</summary>
        public static string KnownHostLine(ITrainingKeySource keys, SshSuite suite, string host, int port)
        {
            string typeName;
            byte[] blob = SshKeyBlob.Of(keys.Find(HostKeyIdFor(suite)), out typeName);
            return SshKnownHosts.Line(host, port, typeName, blob);
        }

        public static SshServerOptions Server(ITrainingKeySource keys, SshSuite suite, IRandomSource random, Func<string, int, bool> allowTunnel)
        {
            SshServerOptions o = new SshServerOptions();
            o.Algorithms = AlgorithmsFor(suite);
            o.Random = random;
            o.HostKey = keys.Find(HostKeyIdFor(suite));
            o.AuthorizedKeys = new byte[][] { keys.Find(KeyIds.SshClient).CopyPublic() };
            o.AllowTunnel = allowTunnel;
            return o;
        }

        /// <summary>The factory's SSH route. The future completes when the user is authenticated, or faults with the named error.</summary>
        public static IFuture<ISecureChannel> Open(ITrainingKeySource keys, TransportRequest r)
        {
            return AsyncProxy.Run<ISecureChannel>(delegate(Return<ISecureChannel> ret) { return OpenBody(keys, r, ret); });
        }

        static IEnumerable<IFuture> OpenBody(ITrainingKeySource keys, TransportRequest r, Return<ISecureChannel> ret)
        {
            GlassSshSession session = NewSession(keys, r);
            session.Run();
            yield return session.Opened;
            ret.Value = session;
        }

        static GlassSshSession NewSession(ITrainingKeySource keys, TransportRequest r)
        {
            bool isClient = r.Role == EngineRole.Client;
            string actor = r.Actor ?? (isClient ? "client" : "server");
            string peer = r.PeerActor ?? (isClient ? "server" : "client");
            string session = r.SessionId ?? r.TraceId ?? "glass";
            TraceStream stream = new TraceStream(session + "/" + actor + "/ssh", session, r.TraceId, r.Hop, actor, r.Clock ?? new MonotonicClock());
            SshEngine engine = isClient
                ? SshEngine.Client(Client(keys, r.Suite, r.Random, r.PeerName, r.PeerPort, r.KnownHosts, r.TrustFirstUse), stream, r.Tamper, peer)
                : SshEngine.Server(Server(keys, r.Suite, r.Random, r.AllowTunnel), stream, r.Tamper, peer);
            return new GlassSshSession(engine, r.Link, r.Sink, r.Gate, r.Tamper, ReadDeadlineMs, r.Clock, r.OpenTarget ?? SocketTarget);
        }

        /// <summary>A socket to a target name. The server's allow list has already passed this target.</summary>
        public static IFuture<IByteLink> SocketTarget(string host, int port)
        {
            return AsyncProxy.Run<IByteLink>(delegate(Return<IByteLink> ret) { return SocketTargetBody(host, port, ret); });
        }

        static IEnumerable<IFuture> SocketTargetBody(string host, int port, Return<IByteLink> ret)
        {
            IFuture<SocketLink> connect = SocketLink.Connect(new IPEndPoint(AddressOf(host), port));
            yield return connect;
            ret.Value = connect.Result;
        }

        public static IPAddress AddressOf(string host)
        {
            return host == "localhost" ? IPAddress.Loopback : IPAddress.Parse(host);
        }
    }

    /// <summary>Probe's SSH half. It reads the known_hosts file, because the engine holds no file.</summary>
    internal static class SshProbe
    {
        /// <summary>The learner's set when the request carries one. Its missing types fall back to the training keys inside CredentialSet itself.</summary>
        static ITrainingKeySource KeysOf(ProbeRequest r) { return r.Credentials != null ? (ITrainingKeySource)r.Credentials : new TrainingKeySource(); }

        const int DeadlineMs = SshSetup.ReadDeadlineMs;

        public static IFuture<ProbeResult> Connect(ProbeRequest r)
        {
            return AsyncProxy.Run<ProbeResult>(delegate(Return<ProbeResult> ret) { return ConnectBody(r, ret); });
        }

        public static ProbeListener Listen(ProbeRequest r)
        {
            LinkListener socket = new LinkListener(new IPEndPoint(IPAddress.Loopback, r.Port));
            ProbeListener listener = new ProbeListener();
            listener.Port = socket.Port;
            listener.Result = AsyncProxy.Run<ProbeResult>(delegate(Return<ProbeResult> ret) { return ListenBody(r, socket, ret); });
            return listener;
        }

        static IRandomSource RandomOf(ProbeRequest r)
        {
            if (r.Seed == 0) return new OsRandom();
            return new SeededRandom(r.Seed);
        }

        static IEnumerable<IFuture> ConnectBody(ProbeRequest r, Return<ProbeResult> ret)
        {
            ListSink sink = new ListSink();
            IFuture<SocketLink> connect = SocketLink.Connect(new IPEndPoint(SshSetup.AddressOf(r.Host), r.Port));
            yield return Futures.Observe(connect);
            if (connect.IsFaulted || connect.IsCanceled)
            {
                ret.Value = Failed(ErrorCodes.LinkLost, "tcp connect", sink);
                yield break;
            }

            SshClientOptions options = SshSetup.Client(KeysOf(r), r.SshSuite, RandomOf(r), r.PeerName ?? r.Host, r.Port, ReadText(r.KnownHostsFile), false);
            if (r.ClientKeyId != null) options.UserKey = KeysOf(r).Find(r.ClientKeyId);
            TraceStream stream = new TraceStream("probe/client/ssh", "probe", "probe", null, "client", new MonotonicClock());
            GlassSshSession session = new GlassSshSession(SshEngine.Client(options, stream, r.Tamper, "server"), connect.Result, sink, new FreeRunGate(), r.Tamper, DeadlineMs, null, null);
            session.Run();
            yield return Futures.Observe(session.Opened);

            List<byte> received = new List<byte>();
            if (!session.Opened.IsFaulted)
            {
                if (r.ExecCommand != null)
                    foreach (IFuture step in SshScript.Exec(session, r.ExecCommand, received)) yield return step;
                if (r.TunnelTo != null)
                {
                    int colon = r.TunnelTo.LastIndexOf(':');
                    foreach (IFuture step in SshScript.Tunnel(session, r.TunnelTo.Substring(0, colon), int.Parse(r.TunnelTo.Substring(colon + 1)), r.Send, received)) yield return step;
                }
            }
            yield return session.Close();
            ret.Value = Result(session, sink, received.ToArray());
        }

        /// <summary>Answers one session. The contract's exec answer comes from the engine's fixed table.</summary>
        static IEnumerable<IFuture> ListenBody(ProbeRequest r, LinkListener socket, Return<ProbeResult> ret)
        {
            ListSink sink = new ListSink();
            IFuture<SocketLink> accepted = socket.Accept();
            yield return Futures.Observe(accepted);
            socket.Close();
            if (accepted.IsFaulted || accepted.IsCanceled)
            {
                ret.Value = Failed(ErrorCodes.LinkLost, "tcp accept", sink);
                yield break;
            }
            string allowed = r.TunnelTo;
            SshServerOptions options = SshSetup.Server(KeysOf(r), r.SshSuite, RandomOf(r), delegate(string host, int port) { return allowed != null && allowed == host + ":" + port; });
            TraceStream stream = new TraceStream("probe/server/ssh", "probe", "probe", null, "server", new MonotonicClock());
            GlassSshSession session = new GlassSshSession(SshEngine.Server(options, stream, r.Tamper, "client"), accepted.Result, sink, new FreeRunGate(), r.Tamper, DeadlineMs, null, SshSetup.SocketTarget);
            session.Run();
            yield return session.Finished;
            ret.Value = Result(session, sink, new byte[0]);
        }

        static ProbeResult Result(GlassSshSession session, ListSink sink, byte[] received)
        {
            PumpResult pump = session.Finished.Result;
            ProbeResult result = new ProbeResult();
            result.Completed = pump.Error == null && pump.Status == EngineStatus.Closed && !session.Opened.IsFaulted;
            if (pump.Error != null)
            {
                result.Code = pump.Error.Code;
                result.CheckName = pump.Error.CheckName;
            }
            result.Version = session.Info.Protocol;
            result.Suite = session.Info.Suite;
            result.Group = session.Info.Group;
            result.KeyLog = new string[0];
            result.Received = received;
            result.Events = sink.Events;
            return result;
        }

        static ProbeResult Failed(string code, string check, ListSink sink)
        {
            ProbeResult result = new ProbeResult();
            result.Code = code;
            result.CheckName = check;
            result.KeyLog = new string[0];
            result.Events = sink.Events;
            return result;
        }

        static string ReadText(string path)
        {
            if (path == null) return null;
            using (StreamReader reader = new StreamReader(path)) return reader.ReadToEnd();
        }
    }
}
