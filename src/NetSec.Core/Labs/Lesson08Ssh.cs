using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Ssh;
using NetSec.Trace;

namespace NetSec.Labs
{
    /// <summary>
    /// Lesson 8. Two SSH rounds on loopback. The modern round runs one command and one tunnel. The legacy round shows the suite an old device
    /// may be stuck with, and its ssh.weak.* events say what is weak about it. Built to show the parts. Do not copy.
    /// The CF build runs this same code on the desktop CLR. It has never run on CE.
    /// docs/lesson-ssh-names.md lists every name.
    /// </summary>
    public sealed class Lesson08Ssh : ILab
    {
        public const string OptionHostKey = "serverHostKey";
        public const string OptionZeroShare = "serverZeroShare";
        public const string OptionWrongUserKey = "clientWrongUserKey";
        public const string OptionRefusedTunnel = "clientRefusedTunnel";

        // The lab names its targets, so a same-seed rerun gives the same bytes. A loopback port changes on each run, and the names stay out of it.
        const string HostName = "ssh.lab";
        const int HostPort = 22;
        const string TunnelHost = "echo.lab", OffListHost = "bank.lab";
        const int TunnelPort = 7, OffListPort = 1433;
        const string ExecCommand = "echo hello";

        static readonly byte[] TunnelMessage = Encoding.UTF8.GetBytes("ping through the tunnel");

        public string LabId { get { return "lab-08-ssh"; } }

        public IFuture<LabResult> Run(LabContext c)
        {
            if (c == null) throw new ArgumentNullException("c");
            return AsyncProxy.Run<LabResult>(delegate(Return<LabResult> ret) { return Body(c, ret); });
        }

        static IEnumerable<IFuture> Body(LabContext c, Return<LabResult> ret)
        {
            // Each side's stream forks here, before any pump starts. An attack that stops round 1 leaves round 2 unrun.
            IRandomSource modernClient = LabPair.Fork(c), modernServer = LabPair.Fork(c), legacyClient = LabPair.Fork(c), legacyServer = LabPair.Fork(c);
            Return<LabResult> round = new Return<LabResult>();
            foreach (IFuture step in Round(c, SshSuite.Modern, "ssh", modernClient, modernServer, round)) yield return step;
            if (round.Value.Completed)
                foreach (IFuture step in Round(c, SshSuite.Legacy, "ssh-legacy", legacyClient, legacyServer, round)) yield return step;
            ret.Value = round.Value;
        }

        static IEnumerable<IFuture> Round(LabContext c, SshSuite suite, string protocol, IRandomSource clientRandom, IRandomSource serverRandom, Return<LabResult> outcome)
        {
            LinkListener listener = new LinkListener(new IPEndPoint(IPAddress.Loopback, 0));
            IFuture<SocketLink> accepted = listener.Accept();
            IFuture<SocketLink> connected = SocketLink.Connect(new IPEndPoint(IPAddress.Loopback, listener.Port));
            yield return accepted;
            yield return connected;
            listener.Close();

            ITamperHook plan = LabPair.Plan(c);
            int deadline = c.Gate is FreeRunGate ? LabPair.DeadlineMs : 0;
            EchoTarget target = new EchoTarget();
            GlassSshSession server = new GlassSshSession(
                SshEngine.Server(ServerOptions(c, suite, serverRandom), LabPair.Stream(c, "server", protocol), plan, "client"),
                accepted.Result, c.Sink, c.Gate, plan, deadline, c.Clock, target.Open);
            GlassSshSession client = new GlassSshSession(
                SshEngine.Client(ClientOptions(c, suite, clientRandom), LabPair.Stream(c, "client", protocol), plan, "server"),
                connected.Result, c.Sink, c.Gate, plan, deadline, c.Clock, null);
            server.Run();
            client.Run();

            yield return Futures.Observe(client.Opened);
            if (!client.Opened.IsFaulted)
            {
                foreach (IFuture step in SshScript.Exec(client, ExecCommand, new List<byte>())) yield return step;
                if (suite == SshSuite.Modern)
                {
                    bool offList = LabPair.Option(c, OptionRefusedTunnel) != null;
                    foreach (IFuture step in SshScript.Tunnel(client, offList ? OffListHost : TunnelHost, offList ? OffListPort : TunnelPort, TunnelMessage, new List<byte>())) yield return step;
                }
            }
            yield return client.Close();
            yield return server.Finished;
            target.Close();
            outcome.Value = LabPair.Result(client.Finished.Result, server.Finished.Result);
        }

        static SshClientOptions ClientOptions(LabContext c, SshSuite suite, IRandomSource random)
        {
            TrainingKeySource keys = new TrainingKeySource();
            SshClientOptions options = SshSetup.Client(keys, suite, random, HostName, HostPort, PinnedLine(keys, suite), false);
            if (LabPair.Option(c, OptionWrongUserKey) != null) options.SignWith = keys.Find(KeyIds.AttackerEd25519);
            return options;
        }

        /// <summary>The client pinned this key before the lab began. The first connect is the moment a real user must check it another way.</summary>
        static string PinnedLine(ITrainingKeySource keys, SshSuite suite)
        {
            string typeName;
            byte[] blob;
            OpenSshKeyFile.PublicBlobOf(keys.Find(SshSetup.HostKeyIdFor(suite)), out typeName, out blob);
            return SshKnownHosts.Line(HostName, HostPort, typeName, blob);
        }

        static SshServerOptions ServerOptions(LabContext c, SshSuite suite, IRandomSource random)
        {
            TrainingKeySource keys = new TrainingKeySource();
            SshServerOptions options = SshSetup.Server(keys, suite, random, IsAllowed);
            if (LabPair.Option(c, OptionHostKey) != null) options.HostKey = keys.Find(KeyIds.AttackerEd25519);
            if (LabPair.Option(c, OptionZeroShare) != null) options.SendZeroShare = true;
            return options;
        }

        static bool IsAllowed(string host, int port)
        {
            return host == TunnelHost && port == TunnelPort;
        }

        /// <summary>The far end of the lab's tunnel: a real socket on loopback that sends back what it reads.</summary>
        sealed class EchoTarget
        {
            readonly LinkListener _listener = new LinkListener(new IPEndPoint(IPAddress.Loopback, 0));

            public IFuture<IByteLink> Open(string host, int port)
            {
                AsyncProxy.Run(Serve());
                return SshSetup.SocketTarget("localhost", _listener.Port);
            }

            public void Close() { _listener.Close(); }

            IEnumerable<IFuture> Serve()
            {
                IFuture<SocketLink> accepted = _listener.Accept();
                yield return Futures.Observe(accepted);
                if (accepted.IsFaulted || accepted.IsCanceled) yield break;
                byte[] buffer = new byte[4096];
                while (true)
                {
                    IFuture<int> read = accepted.Result.Read(buffer, 0, buffer.Length);
                    yield return Futures.Observe(read);
                    if (read.IsFaulted || read.IsCanceled || read.Result == 0) break;
                    IFuture write = accepted.Result.Write(buffer, 0, read.Result);
                    yield return Futures.Observe(write);
                    if (write.IsFaulted) break;
                }
                accepted.Result.Close();
            }
        }
    }
}
