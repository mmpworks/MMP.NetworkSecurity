using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using MMP.AsyncProxy;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Platform;
using NetSec.Ssh;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// A rule-breaking peer, from Jared's review of the SSH engine. Forge seals a packet with an engine's own writer, through reflection, so the
    /// forger stands for a hostile peer that holds the session keys and for no other position.
    /// </summary>
    public class SshVerdictTests
    {
        static readonly TrainingKeySource Keys = new TrainingKeySource();
        const int Window = 2097152, QueueLimit = 4194304;

        static TraceStream Stream(string actor) => new TraceStream(actor, actor, actor, null, actor, new FixedClock(1));

        static SshClientOptions ClientOptions(SshAlgorithms a, bool trust = true, string pin = null, ITrainingKey userKey = null) =>
            new SshClientOptions { Algorithms = a, Random = new SeededRandom(2), Host = "h", Port = 22, KnownHosts = pin, TrustFirstUse = trust, User = "training", UserKey = userKey ?? Keys.Find(KeyIds.SshClient) };

        static SshServerOptions ServerOptions(SshAlgorithms a, ITrainingKey hostKey = null) =>
            new SshServerOptions { Algorithms = a, Random = new SeededRandom(1), HostKey = hostKey ?? Keys.Find(a.IsLegacy ? KeyIds.SshHostRsa : KeyIds.SshHostEd25519), AuthorizedKeys = new[] { Keys.Find(KeyIds.SshClient).CopyPublic() }, AllowTunnel = (h, p) => h == "allowed" };

        sealed class Duel
        {
            public SshEngine Client, Server;
            public readonly List<DeliveredChunk> ClientApp = new List<DeliveredChunk>(), ServerApp = new List<DeliveredChunk>();
            public readonly List<TraceEvent> ClientEvents = new List<TraceEvent>(), ServerEvents = new List<TraceEvent>();
            public NetSecError ClientError, ServerError;

            public int ClientData(int channel) => ClientApp.Where(a => a.Channel == channel).Sum(a => a.Bytes.Length);
            public int ServerSent(string message) => ServerEvents.Count(e => e.Type == "ssh.message.sent" && e.Message == message);
            public int ClientSent(string message) => ClientEvents.Count(e => e.Type == "ssh.message.sent" && e.Message == message);

            byte[] TakeClient(EngineOutput o)
            {
                ClientApp.AddRange(o.App); ClientEvents.AddRange(o.Events);
                if (o.Error != null) ClientError = o.Error;
                return o.Wire;
            }

            byte[] TakeServer(EngineOutput o)
            {
                ServerApp.AddRange(o.App); ServerEvents.AddRange(o.Events);
                if (o.Error != null) ServerError = o.Error;
                return o.Wire;
            }

            /// <summary>Passes bytes both ways until neither side has more to say.</summary>
            public void Run(byte[] toServer, byte[] toClient)
            {
                while (toServer.Length > 0 || toClient.Length > 0)
                {
                    byte[] fromServer = toServer.Length > 0 ? TakeServer(Server.Feed(toServer, 0, toServer.Length)) : new byte[0];
                    byte[] fromClient = toClient.Length > 0 ? TakeClient(Client.Feed(toClient, 0, toClient.Length)) : new byte[0];
                    toServer = fromClient;
                    toClient = fromServer;
                }
            }

            public void Start()
            {
                byte[] toClient = TakeServer(Server.Start());
                byte[] toServer = TakeClient(Client.Start());
                Run(toServer, toClient);
            }

            public void ClientCommand(EngineCommand c) => Run(TakeClient(Client.Command(c)), new byte[0]);
            public void ServerCommand(EngineCommand c) => Run(new byte[0], TakeServer(Server.Command(c)));
            public void ForgeToClient(byte[] payload) => Run(new byte[0], Forge(Server, payload));
            public void ForgeToServer(byte[] payload) => Run(Forge(Client, payload), new byte[0]);
        }

        static byte[] Forge(SshEngine from, byte[] payload)
        {
            SshSession session = (SshSession)typeof(SshEngine).GetField("_session", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(from);
            return session.Protect("forged", payload);
        }

        static Duel Open(SshAlgorithms a = null, SshClientOptions client = null)
        {
            a = a ?? SshAlgorithms.Modern;
            Duel d = new Duel { Client = SshEngine.Client(client ?? ClientOptions(a), Stream("client"), null, "server"), Server = SshEngine.Server(ServerOptions(a), Stream("server"), null, "client") };
            d.Start();
            return d;
        }

        static byte[] Filled(int size) => Enumerable.Repeat((byte)0x5a, size).ToArray();

        static byte[] Confirmation(int recipient, int sender) => new ByteWriter().U8(SshMsg.ChannelConfirmation).U32(recipient).U32(sender).U32(Window).U32(32768).ToArray();
        static byte[] DataTo(int recipient, int size) => new ByteWriter().U8(SshMsg.ChannelData).U32(recipient).Prefixed(Filled(size)).ToArray();
        static byte[] ExecOn(int recipient, string command) => new ByteWriter().U8(SshMsg.ChannelRequest).U32(recipient).Prefixed("exec").U8(1).Prefixed(command).ToArray();
        static byte[] OpenSession(int sender) => new ByteWriter().U8(SshMsg.ChannelOpen).Prefixed("session").U32(sender).U32(Window).U32(32768).ToArray();
        static byte[] OpenFailure(int recipient) => new ByteWriter().U8(SshMsg.ChannelOpenFailure).U32(recipient).U32(1).Prefixed("no").Prefixed("").ToArray();

        // ---------------------------------------------------------------- blocker 1: no pin

        [Fact]
        public void A_factory_client_with_no_pin_refuses_by_name()
        {
            MemoryLink[] links = MemoryLink.Pair();
            GlassTransportFactory factory = new GlassTransportFactory(Keys);
            factory.Open(new TransportRequest { Protocol = WireProtocol.Ssh, Role = EngineRole.Server, Suite = SshSuite.Modern, Link = links[1], Random = new SeededRandom(1) });
            IFuture<ISecureChannel> client = factory.Open(new TransportRequest { Protocol = WireProtocol.Ssh, Role = EngineRole.Client, Suite = SshSuite.Modern, Link = links[0], Random = new SeededRandom(2), PeerName = "h", PeerPort = 22 });
            Assert.True(client.Wait(30000));
            Assert.True(client.IsFaulted, "the client opened with no pin");
            Assert.Equal(SshCodes.HostKeyUnknown, ((NetSecException)client.Exception).Error.Code);
        }

        [Fact]
        public void A_probe_with_no_known_hosts_file_refuses_by_name()
        {
            ProbeListener listener = Probe.Listen(new ProbeRequest { Protocol = WireProtocol.Ssh, Host = "127.0.0.1", SshSuite = SshSuite.Modern, Seed = 3 });
            IFuture<ProbeResult> result = Probe.Connect(new ProbeRequest { Protocol = WireProtocol.Ssh, Host = "127.0.0.1", Port = listener.Port, SshSuite = SshSuite.Modern, ExecCommand = "echo hello", Seed = 4 });
            Assert.True(result.Wait(30000));
            Assert.False(result.Result.Completed);
            Assert.Equal(SshCodes.HostKeyUnknown, result.Result.Code);
        }

        static GlassSshSession Connect(SshClientOptions client, ITrainingKey hostKey)
        {
            MemoryLink[] links = MemoryLink.Pair();
            new GlassSshSession(SshEngine.Server(ServerOptions(SshAlgorithms.Modern, hostKey), Stream("server"), null, "client"), links[1], new ListSink(), new FreeRunGate(), null, 5000, new FixedClock(1), null).Run();
            GlassSshSession session = new GlassSshSession(SshEngine.Client(client, Stream("client"), null, "server"), links[0], new ListSink(), new FreeRunGate(), null, 5000, new FixedClock(1), null);
            session.Run();
            Assert.True(session.Opened.Wait(30000) || session.Opened.IsFaulted);
            return session;
        }

        [Fact]
        public void Trust_on_first_use_returns_the_key_to_store_and_the_next_connect_holds_to_it()
        {
            GlassSshSession first = Connect(ClientOptions(SshAlgorithms.Modern, true, null), Keys.Find(KeyIds.SshHostEd25519));
            Assert.False(first.Opened.IsFaulted);
            string line = first.LearnedKnownHostsLine;
            Assert.NotNull(line);
            Assert.StartsWith("h ssh-ed25519 ", line);

            GlassSshSession same = Connect(ClientOptions(SshAlgorithms.Modern, false, line), Keys.Find(KeyIds.SshHostEd25519));
            Assert.False(same.Opened.IsFaulted);
            Assert.Null(same.LearnedKnownHostsLine);

            GlassSshSession changed = Connect(ClientOptions(SshAlgorithms.Modern, false, line), Keys.Find(KeyIds.AttackerEd25519));
            Assert.True(changed.Finished.Wait(30000));
            Assert.Equal(SshCodes.HostKeyChanged, changed.Finished.Result.Error.Code);
        }

        [Fact]
        public void First_use_shows_in_the_trace()
        {
            Duel d = Open();
            Assert.Single(d.ClientEvents, e => e.Type == "ssh.hostkey.first-use");
        }

        // ---------------------------------------------------------------- should-fix 8: known_hosts forms

        static readonly byte[] Blob = { 1, 2, 3 };
        static readonly byte[] Other = { 4, 5, 6 };
        static string B64(byte[] b) => Convert.ToBase64String(b);

        [Fact]
        public void A_revoked_key_loses_to_a_plain_pin_for_the_same_key()
        {
            string text = "h ssh-ed25519 " + B64(Blob) + "\n@revoked h ssh-ed25519 " + B64(Blob) + "\n";
            Assert.Equal(HostKeyMatch.Revoked, SshKnownHosts.Check(text, "h", 22, Blob));
            Assert.Equal(HostKeyMatch.Revoked, SshKnownHosts.Check("@revoked h ssh-ed25519 " + B64(Blob) + "\n", "h", 22, Blob));
        }

        [Fact]
        public void A_tab_separated_line_is_read()
        {
            Assert.Equal(HostKeyMatch.Match, SshKnownHosts.Check("h\tssh-ed25519\t" + B64(Blob) + "\n", "h", 22, Blob));
            Assert.Equal(HostKeyMatch.Changed, SshKnownHosts.Check("h\tssh-ed25519\t" + B64(Blob) + "\n", "h", 22, Other));
        }

        [Fact]
        public void A_hashed_host_name_is_read()
        {
            byte[] salt = Filled(20);
            byte[] hash = Hmac.Compute(Hashes.Sha1, salt, Encoding.UTF8.GetBytes("h"));
            string line = "|1|" + B64(salt) + "|" + B64(hash) + " ssh-ed25519 " + B64(Blob) + "\n";
            Assert.Equal(HostKeyMatch.Match, SshKnownHosts.Check(line, "h", 22, Blob));
            Assert.Equal(HostKeyMatch.Changed, SshKnownHosts.Check(line, "h", 22, Other));
            Assert.Equal(HostKeyMatch.Unknown, SshKnownHosts.Check(line, "other", 22, Blob));
        }

        // ---------------------------------------------------------------- blocker 2: back-pressure

        static int TunnelFrom(Duel d)
        {
            d.ClientCommand(new EngineCommand(EngineCommandKind.OpenChannel, 0, null, "allowed:1"));
            return 0;
        }

        [Fact]
        public void A_stalled_reader_stops_the_sender_at_the_window_and_a_read_resumes_it()
        {
            Duel d = Open();
            int channel = TunnelFrom(d);
            d.ServerCommand(new EngineCommand(EngineCommandKind.Send, 0, Filled(3 * 1024 * 1024), null));
            Assert.Equal(Window, d.ClientData(channel));
            Assert.Equal(0, d.ClientSent(SshNames.ChannelWindowAdjust));

            d.ClientCommand(new EngineCommand(EngineCommandKind.Consumed, channel, new byte[Window], null));
            Assert.Equal(3 * 1024 * 1024, d.ClientData(channel));
        }

        [Fact]
        public void A_send_queue_past_its_limit_ends_in_a_named_failure()
        {
            Duel d = Open();
            TunnelFrom(d);
            d.ServerCommand(new EngineCommand(EngineCommandKind.Send, 0, Filled(Window + QueueLimit + 1), null));
            Assert.Equal(SshCodes.ChannelQueueFull, d.ServerError?.Code);
        }

        /// <summary>A target that always has bytes. It counts what the relay took.</summary>
        sealed class FloodLink : IByteLink
        {
            long _taken;
            public long Taken => Interlocked.Read(ref _taken);
            public IFuture<int> Read(byte[] b, int off, int n)
            {
                Interlocked.Add(ref _taken, n);
                return Futures.FromResult<int>(n);
            }
            public IFuture Write(byte[] b, int off, int n) => Futures.Completed;
            public void Close() { }
        }

        [Fact]
        public void A_client_that_does_not_read_stops_the_tunnel_target_and_reading_resumes_it()
        {
            FloodLink flood = new FloodLink();
            MemoryLink[] links = MemoryLink.Pair();
            GlassSshSession server = new GlassSshSession(SshEngine.Server(ServerOptions(SshAlgorithms.Modern), Stream("server"), null, "client"), links[1], new ListSink(), new FreeRunGate(), null, 30000, new FixedClock(1), (h, p) => Futures.FromResult<IByteLink>(flood));
            GlassSshSession client = new GlassSshSession(SshEngine.Client(ClientOptions(SshAlgorithms.Modern), Stream("client"), null, "server"), links[0], new ListSink(), new FreeRunGate(), null, 30000, new FixedClock(1), null);
            server.Run();
            client.Run();
            Assert.True(client.Opened.Wait(30000));
            IFuture<int> open = client.OpenTunnel("allowed", 1);
            Assert.True(open.Wait(30000));

            long limit = Window + QueueLimit + 16384;
            long seen = -1;
            for (int i = 0; i < 300 && seen != flood.Taken && flood.Taken <= limit; i++)
            {
                seen = flood.Taken;
                Thread.Sleep(200);
            }
            Assert.True(flood.Taken <= limit, "the relay took " + flood.Taken + " bytes with nobody reading");
            long stalled = flood.Taken;

            long read = 0;
            while (read < 4 * Window)
            {
                IFuture<AppChunk> next = client.Receive();
                Assert.True(next.Wait(30000), "the stream stopped after " + read + " bytes");
                read += next.Result.Bytes.Length;
            }
            Assert.True(flood.Taken > stalled, "reading did not resume the target");
        }

        // ---------------------------------------------------------------- should-fix 2 to 5: channel rules

        [Fact]
        public void A_refused_exec_channel_names_exec_and_not_the_tunnel()
        {
            Duel d = Open();
            d.Client.Command(new EngineCommand(EngineCommandKind.Exec, 5, null, "echo hello"));
            byte[] refused = Forge(d.Server, OpenFailure(5));
            d.ClientError = d.Client.Feed(refused, 0, refused.Length).Error;
            Assert.Equal(SshCodes.ExecRefused, d.ClientError?.Code);
            Assert.Equal(SshChecks.ExecAccepted, d.ClientError?.CheckName);
        }

        [Fact]
        public void A_refused_tunnel_still_names_the_tunnel()
        {
            Duel d = Open();
            d.ClientCommand(new EngineCommand(EngineCommandKind.OpenChannel, 5, null, "off:1"));
            Assert.Equal(SshCodes.TunnelRefused, d.ClientError?.Code);
            Assert.Equal(SshChecks.TunnelAccepted, d.ClientError?.CheckName);
        }

        [Fact]
        public void A_second_confirmation_is_refused_and_sends_no_second_exec()
        {
            Duel d = Open();
            d.Client.Command(new EngineCommand(EngineCommandKind.Exec, 0, null, "echo hello"));
            byte[] confirm = Forge(d.Server, Confirmation(0, 77));
            EngineOutput first = d.Client.Feed(confirm, 0, confirm.Length);
            Assert.Single(first.Events, e => e.Type == "ssh.message.sent" && e.Message == SshNames.ChannelRequestExec);
            byte[] again = Forge(d.Server, Confirmation(0, 78));
            EngineOutput second = d.Client.Feed(again, 0, again.Length);
            Assert.DoesNotContain(second.Events, e => e.Type == "ssh.message.sent" && e.Message == SshNames.ChannelRequestExec);
            Assert.Equal(SshCodes.ChannelUnknown, second.Error?.Code);
        }

        [Fact]
        public void Data_on_an_unconfirmed_channel_is_refused_and_not_delivered()
        {
            Duel d = new Duel { Client = SshEngine.Client(ClientOptions(SshAlgorithms.Modern), Stream("client"), null, "server"), Server = SshEngine.Server(ServerOptions(SshAlgorithms.Modern), Stream("server"), null, "client") };
            d.Start();
            byte[] open = d.Client.Command(new EngineCommand(EngineCommandKind.Exec, 0, null, "echo hello")).Wire;
            Assert.NotEmpty(open);
            d.ForgeToClient(DataTo(0, 100));
            Assert.Equal(0, d.ClientData(0));
            Assert.Equal(SshCodes.ChannelUnknown, d.ClientError?.Code);
        }

        [Fact]
        public void Data_above_our_largest_packet_is_refused_and_not_delivered()
        {
            Duel d = Open();
            TunnelFrom(d);
            d.ForgeToClient(DataTo(0, 34000));
            Assert.Equal(0, d.ClientData(0));
            Assert.Equal(SshCodes.ChannelWindow, d.ClientError?.Code);
        }

        [Fact]
        public void The_server_answers_one_exec_per_session_channel_and_none_on_a_tunnel()
        {
            Duel d = Open();
            d.ClientCommand(new EngineCommand(EngineCommandKind.Exec, 0, null, "echo hello"));
            int data = d.ServerSent(SshNames.ChannelData);
            Assert.Equal(1, data);
            d.ForgeToServer(ExecOn(0, "echo again"));
            Assert.Equal(1, d.ServerSent(SshNames.ChannelData));

            Duel t = Open();
            TunnelFrom(t);
            t.ForgeToServer(ExecOn(0, "echo hello"));
            Assert.Equal(0, t.ServerSent(SshNames.ChannelData));
            Assert.Equal(1, t.ServerSent(SshNames.ChannelFailure));
        }

        // ---------------------------------------------------------------- should-fix 6: caps

        [Fact]
        public void Refused_auth_tries_have_a_limit()
        {
            SshClientOptions stranger = ClientOptions(SshAlgorithms.Modern, true, null, Keys.Find(KeyIds.AttackerEd25519));
            Duel d = Open(null, stranger);
            byte[] query = new ByteWriter().U8(SshMsg.UserauthRequest).Prefixed("u").Prefixed("ssh-connection").Prefixed("publickey").U8(0).Prefixed("ssh-ed25519").Prefixed(SshKeyBlob.Ed25519(Keys.Find(KeyIds.AttackerEd25519).CopyPublic())).ToArray();
            for (int i = 0; i < 100 && d.ServerError == null; i++) d.ForgeToServer(query);
            Assert.Equal(SshCodes.AuthTries, d.ServerError?.Code);
            Assert.Equal(SshChecks.AuthTries, d.ServerError?.CheckName);
            Assert.True(d.ServerSent(SshNames.UserauthFailure) < 100);
        }

        [Fact]
        public void Queries_for_an_allowed_key_have_the_same_limit()
        {
            SshClientOptions stranger = ClientOptions(SshAlgorithms.Modern, true, null, Keys.Find(KeyIds.AttackerEd25519));
            Duel d = Open(null, stranger);
            byte[] query = new ByteWriter().U8(SshMsg.UserauthRequest).Prefixed("u").Prefixed("ssh-connection").Prefixed("publickey").U8(0).Prefixed("ssh-ed25519").Prefixed(SshKeyBlob.Ed25519(Keys.Find(KeyIds.SshClient).CopyPublic())).ToArray();
            for (int i = 0; i < 100 && d.ServerError == null; i++) d.ForgeToServer(query);
            Assert.Equal(SshCodes.AuthTries, d.ServerError?.Code);
        }

        [Fact]
        public void Open_channels_have_a_limit_and_the_session_stays_up()
        {
            Duel d = Open();
            for (int i = 0; i < 100; i++) d.ForgeToServer(OpenSession(100 + i));
            int confirmed = d.ServerSent(SshNames.ChannelOpenConfirmation);
            Assert.True(confirmed < 100, "the server confirmed " + confirmed + " channels");
            Assert.Equal(100 - confirmed, d.ServerSent(SshNames.ChannelOpenFailure));
            Assert.Null(d.ServerError);
            Assert.Contains(d.ServerEvents, e => e.Type == "check.result" && !e.Check.Passed && e.Message == SshChecks.ChannelLimit);
        }

        [Fact]
        public void A_client_refuses_to_open_past_the_same_limit()
        {
            Duel d = Open();
            for (int i = 0; i < 100 && d.ClientError == null; i++) d.ClientCommand(new EngineCommand(EngineCommandKind.OpenChannel, i, null, "allowed:1"));
            Assert.Equal(SshCodes.ChannelLimit, d.ClientError?.Code);
        }

        // ---------------------------------------------------------------- should-fix 7: sequence wrap

        [Fact]
        public void The_writer_refuses_to_wrap_its_sequence_number()
        {
            SshPacketWriter writer = new SshPacketWriter(uint.MaxValue);
            SeededRandom random = new SeededRandom(1);
            Assert.NotEmpty(writer.Seal(new byte[] { 2 }, random));
            Assert.Equal(SshCodes.SequenceExhausted, Assert.Throws<ParseFailure>(() => writer.Seal(new byte[] { 2 }, random)).Code);
        }

        [Fact]
        public void The_reader_refuses_to_wrap_its_sequence_number()
        {
            SshPacketReader reader = new SshPacketReader(uint.MaxValue);
            SshPacketWriter writer = new SshPacketWriter();
            SeededRandom random = new SeededRandom(1);
            byte[] one = writer.Seal(new byte[] { 2 }, random), two = writer.Seal(new byte[] { 2 }, random);
            reader.Append(one, 0, one.Length);
            Assert.NotNull(reader.TryNext());
            reader.Append(two, 0, two.Length);
            Assert.Equal(SshCodes.SequenceExhausted, Assert.Throws<ParseFailure>(() => reader.TryNext()).Code);
        }

        // ---------------------------------------------------------------- should-fix 1: strict KEX

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Two_glass_sides_turn_strict_kex_on(bool legacy)
        {
            Duel d = Open(legacy ? SshAlgorithms.Legacy : SshAlgorithms.Modern);
            Assert.Equal(EngineStatus.Open, d.Client.Status);
            Assert.Equal("on", d.ClientEvents.Single(e => e.Type == "ssh.kex.strict").Message);
            Assert.Equal("on", d.ServerEvents.Single(e => e.Type == "ssh.kex.strict").Message);
        }

        /// <summary>The Terrapin prefix: a clear Ignore before the peer's KexInit. Strict KEX requires KexInit to come first.</summary>
        [Fact]
        public void An_ignore_before_kexinit_ends_in_a_named_failure()
        {
            SshEngine client = SshEngine.Client(ClientOptions(SshAlgorithms.Modern), Stream("client"), null, "server");
            SshEngine server = SshEngine.Server(ServerOptions(SshAlgorithms.Modern), Stream("server"), null, "client");
            byte[] version = server.Start().Wire;
            byte[] ignore = Forge(server, new ByteWriter().U8(SshMsg.Ignore).Prefixed("x").ToArray());
            byte[] clientHello = client.Start().Wire;
            byte[] serverKexInit = server.Feed(clientHello, 0, clientHello.Length).Wire;
            byte[] toClient = new ByteWriter().Put(version).Put(ignore).Put(serverKexInit).ToArray();
            EngineOutput output = client.Feed(toClient, 0, toClient.Length);
            Assert.Equal(SshCodes.KexStrict, output.Error?.Code);
            Assert.Equal(SshChecks.StrictKex, output.Error?.CheckName);
        }

        [Fact]
        public void An_ignore_during_the_exchange_ends_in_a_named_failure()
        {
            SshEngine client = SshEngine.Client(ClientOptions(SshAlgorithms.Modern), Stream("client"), null, "server");
            SshEngine server = SshEngine.Server(ServerOptions(SshAlgorithms.Modern), Stream("server"), null, "client");
            byte[] version = server.Start().Wire;
            byte[] clientHello = client.Start().Wire;
            byte[] serverKexInit = server.Feed(clientHello, 0, clientHello.Length).Wire;
            byte[] ignore = Forge(server, new ByteWriter().U8(SshMsg.Ignore).Prefixed("x").ToArray());
            byte[] toClient = new ByteWriter().Put(version).Put(serverKexInit).Put(ignore).ToArray();
            EngineOutput output = client.Feed(toClient, 0, toClient.Length);
            Assert.Equal(SshCodes.KexStrict, output.Error?.Code);
        }

        /// <summary>A peer that does not offer it gets the old rules: an old device must still connect, and the trace says strict KEX stayed off.</summary>
        [Fact]
        public void A_peer_with_no_strict_marker_leaves_it_off()
        {
            SshEngine server = SshEngine.Server(ServerOptions(SshAlgorithms.Modern), Stream("server"), null, "client");
            server.Start();
            byte[] line = Encoding.UTF8.GetBytes("SSH-2.0-old\r\n");
            server.Feed(line, 0, line.Length);
            byte[] kexInit = new ByteWriter().U8(SshMsg.KexInit).Put(new byte[16]).Prefixed("curve25519-sha256").Prefixed("ssh-ed25519").Prefixed("aes128-ctr").Prefixed("aes128-ctr").Prefixed("hmac-sha2-256").Prefixed("hmac-sha2-256").Prefixed("none").Prefixed("none").Prefixed("").Prefixed("").U8(0).U32(0).ToArray();
            byte[] packet = new SshPacketWriter().Seal(kexInit, new SeededRandom(1));
            EngineOutput output = server.Feed(packet, 0, packet.Length);
            Assert.Null(output.Error);
            Assert.Equal("off", output.Events.Single(e => e.Type == "ssh.kex.strict").Message);
        }
    }
}
