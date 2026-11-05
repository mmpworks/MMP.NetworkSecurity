using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Labs;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Platform;
using NetSec.Tls13;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    static class TlsKit
    {
        public static readonly DateTime Now = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        public static readonly ITrainingKeySource Keys = new TrainingKeySource();

        public static TraceStream Stream(string actor) => new TraceStream("s1/" + actor + "/tls13", "s1", "t1", null, actor, new FixedClock(7));

        public static Tls13Options Common(string actor, string peer, Tls13Group group, int seed)
        {
            return new Tls13Options { Stream = Stream(actor), Peer = peer, Random = new SeededRandom(seed), Group = group, ServerName = "localhost", Now = Now };
        }

        public static Tls13Engine Client(Tls13Group group, int seed = 1)
        {
            Tls13Options o = Common("client", "server", group, seed);
            o.TrustAnchors = new[] { new TrainingCa(Keys).RootCertificateDer };
            return Tls13Engine.CreateClient(o);
        }

        public static Tls13Engine Server(Tls13Group group, int seed = 2, byte[] leaf = null)
        {
            Tls13Options o = Common("server", "client", group, seed);
            ITrainingKey key = Keys.Find(KeyIds.ServerTlsEd25519);
            o.CertificateChain = new[] { leaf ?? TrainingPki.ServerCertificate(new TrainingCa(Keys), key) };
            o.SigningSeed = key.CopyMaterial();
            return Tls13Engine.CreateServer(o);
        }

        public static byte[] Plain(byte[] handshake) => RecordProtection.PlainRecord(ContentType.Handshake, 0x0303, handshake, 0, handshake.Length);

        public static byte[] Bytes32(byte fill)
        {
            byte[] b = new byte[32];
            for (int i = 0; i < 32; i++) b[i] = fill;
            return b;
        }

        public static string RepoRoot()
        {
            DirectoryInfo dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (dir != null && !Directory.Exists(Path.Combine(dir.FullName, "acceptance"))) dir = dir.Parent;
            Assert.True(dir != null, "no acceptance folder above the test binaries");
            return dir.FullName;
        }
    }

    public class Tls13EngineTests
    {
        [Theory]
        [InlineData(Tls13Group.X25519)]
        [InlineData(Tls13Group.X25519MlKem768)]
        public void Two_engines_open_and_agree_on_every_key_log_line(Tls13Group group)
        {
            Tls13Engine client = TlsKit.Client(group), server = TlsKit.Server(group);
            EngineDuel.Run(client, server);
            Assert.Equal(EngineStatus.Open, client.Status);
            Assert.Equal(EngineStatus.Open, server.Status);
            Assert.Equal(5, client.KeyLogLines.Length);
            Assert.Equal(client.KeyLogLines, server.KeyLogLines);
            Assert.Equal(Tls13GroupInfo.Name(group), client.GroupName);
        }

        [Fact]
        public void One_byte_at_a_time_gives_the_same_handshake()
        {
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519MlKem768), server = TlsKit.Server(Tls13Group.X25519MlKem768);
            server.Start();
            byte[] toServer = client.Start().Wire, toClient = new byte[0];
            while (toServer.Length > 0 || toClient.Length > 0)
            {
                List<byte> nextToClient = new List<byte>(), nextToServer = new List<byte>();
                for (int i = 0; i < toServer.Length; i++) nextToClient.AddRange(server.Feed(toServer, i, 1).Wire);
                for (int i = 0; i < toClient.Length; i++) nextToServer.AddRange(client.Feed(toClient, i, 1).Wire);
                toServer = nextToServer.ToArray();
                toClient = nextToClient.ToArray();
            }
            Assert.Equal(EngineStatus.Open, client.Status);
            Assert.Equal(EngineStatus.Open, server.Status);
            Assert.Equal(client.KeyLogLines, server.KeyLogLines);
        }

        [Fact]
        public void The_hybrid_shares_have_the_sizes_rfc_10024_names()
        {
            KeyShareOffer offer = KeyExchange.Offer(Tls13Group.X25519MlKem768, new SeededRandom(3));
            KexOutcome server = KeyExchange.Respond(Tls13Group.X25519MlKem768, offer.Share, new SeededRandom(4));
            KexOutcome client = KeyExchange.Finish(Tls13Group.X25519MlKem768, offer, server.ServerShare);
            Assert.Equal(1216, offer.Share.Length);
            Assert.Equal(1120, server.ServerShare.Length);
            Assert.Equal(64, client.Shared.Length);
            Assert.Equal(server.Shared, client.Shared);
            Assert.Equal(server.MlKemPart, client.Shared.Take(32).ToArray());
        }

        [Fact]
        public void An_all_zero_x25519_result_is_refused_on_both_roles_beside_a_good_share()
        {
            byte[] smallOrder = new byte[32];

            Tls13Engine client = TlsKit.Client(Tls13Group.X25519);
            client.Start();
            byte[] hello = Tls13Messages.ServerHello(TlsKit.Bytes32(9), new byte[0], Tls13Suite.Aes128, Tls13Group.X25519, smallOrder);
            byte[] record = TlsKit.Plain(hello);
            EngineOutput refused = client.Feed(record, 0, record.Length);
            Assert.Equal(EngineStatus.Failed, refused.Status);
            Assert.Equal(Tls13Codes.X25519Zero, refused.Error.Code);
            Assert.Equal("X25519 result not zero", refused.Error.CheckName);
            Assert.Contains(refused.Events, e => e.Type == "tls.alert.sent");

            Tls13Engine server = TlsKit.Server(Tls13Group.X25519);
            server.Start();
            byte[] clientHello = TlsKit.Plain(Tls13Messages.ClientHello(TlsKit.Bytes32(8), "localhost", Tls13Group.X25519, smallOrder));
            Assert.Equal(Tls13Codes.X25519Zero, server.Feed(clientHello, 0, clientHello.Length).Error.Code);

            Tls13Engine good = TlsKit.Server(Tls13Group.X25519);
            good.Start();
            byte[] goodHello = TlsKit.Plain(Tls13Messages.ClientHello(TlsKit.Bytes32(8), "localhost", Tls13Group.X25519, X25519.MultBase(TlsKit.Bytes32(5))));
            Assert.Null(good.Feed(goodHello, 0, goodHello.Length).Error);
        }

        /// <summary>A TLS 1.1 ServerHello: version 0x0302, a suite, and no extensions.</summary>
        static byte[] LegacyServerHello(byte[] random)
        {
            byte[] body = new ByteWriter().U16(0x0302).Put(random).U8(0).U16(0x002F).U8(0).ToArray();
            return new ByteWriter().U8(HandshakeType.ServerHello).U24(body.Length).Put(body).ToArray();
        }

        [Fact]
        public void A_downgrade_sentinel_is_named_beside_a_plain_old_server()
        {
            byte[] sentinel = TlsKit.Bytes32(7);
            Encoding.UTF8.GetBytes("DOWNGRD").CopyTo(sentinel, 24);
            sentinel[31] = 0;

            Tls13Engine pushed = TlsKit.Client(Tls13Group.X25519);
            pushed.Start();
            byte[] withSentinel = TlsKit.Plain(LegacyServerHello(sentinel));
            Assert.Equal(Tls13Codes.DowngradeSentinel, pushed.Feed(withSentinel, 0, withSentinel.Length).Error.Code);

            Tls13Engine old = TlsKit.Client(Tls13Group.X25519);
            old.Start();
            byte[] noSentinel = TlsKit.Plain(LegacyServerHello(TlsKit.Bytes32(7)));
            Assert.Equal(Tls13Codes.VersionRefused, old.Feed(noSentinel, 0, noSentinel.Length).Error.Code);
        }

        [Fact]
        public void A_hello_retry_request_is_refused_by_name()
        {
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519);
            client.Start();
            byte[] record = TlsKit.Plain(Tls13Messages.ServerHello(Tls13Messages.HelloRetryRandom, new byte[0], Tls13Suite.Aes128, Tls13Group.X25519, new byte[32]));
            Assert.Equal(Tls13Codes.HrrUnsupported, client.Feed(record, 0, record.Length).Error.Code);
        }

        [Fact]
        public void A_message_with_no_row_names_the_state_and_a_record_length_past_the_limit_fails_now()
        {
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519);
            client.Start();
            byte[] finished = TlsKit.Plain(Tls13Messages.Finished(new byte[32]));
            EngineOutput output = client.Feed(finished, 0, finished.Length);
            Assert.Equal(ErrorCodes.UnexpectedMessage, output.Error.Code);
            Assert.Contains("WaitServerHello", output.Error.Message);

            Tls13Engine other = TlsKit.Client(Tls13Group.X25519);
            other.Start();
            byte[] tooLong = { 22, 3, 3, 0x7F, 0xFF };
            Assert.Equal(Tls13Codes.RecordOverflow, other.Feed(tooLong, 0, tooLong.Length).Error.Code);
        }

        [Fact]
        public void A_cut_short_hello_is_a_named_parse_failure_and_never_an_exception()
        {
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519);
            client.Start();
            byte[] record = TlsKit.Plain(new byte[] { HandshakeType.ServerHello, 0, 0, 3, 3, 3, 0 });
            EngineOutput output = client.Feed(record, 0, record.Length);
            Assert.Equal(EngineStatus.Failed, output.Status);
            Assert.Equal(ErrorCodes.ParseTruncated, output.Error.Code);
        }

        [Fact]
        public void Data_sent_early_waits_for_open_then_both_sides_close_cleanly()
        {
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519), server = TlsKit.Server(Tls13Group.X25519);
            byte[] data = Encoding.UTF8.GetBytes("early");
            client.Command(new EngineCommand(EngineCommandKind.Send, 0, data, null));

            server.Start();
            byte[] toServer = client.Start().Wire;
            List<byte> delivered = new List<byte>();
            byte[] toClient = new byte[0];
            while (toServer.Length > 0 || toClient.Length > 0)
            {
                EngineOutput fromServer = server.Feed(toServer, 0, toServer.Length);
                foreach (DeliveredChunk chunk in fromServer.App) delivered.AddRange(chunk.Bytes);
                byte[] fromClient = client.Feed(toClient, 0, toClient.Length).Wire;
                toClient = fromServer.Wire;
                toServer = fromClient;
            }
            Assert.Equal(data, delivered.ToArray());

            byte[] notify = client.Command(EngineCommand.Close).Wire;
            Assert.Equal(EngineStatus.Closed, client.Status);
            Assert.Equal(EngineStatus.Closed, server.Feed(notify, 0, notify.Length).Status);
            Assert.Equal(0, server.AlertReceived);
        }

        [Fact]
        public void Only_the_hello_fields_show_to_the_wire()
        {
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519), server = TlsKit.Server(Tls13Group.X25519);
            List<TraceEvent> events = new List<TraceEvent>();
            server.Start();
            EngineOutput first = client.Start();
            events.AddRange(first.Events);
            EngineOutput flight = server.Feed(first.Wire, 0, first.Wire.Length);
            events.AddRange(flight.Events);
            events.AddRange(client.Feed(flight.Wire, 0, flight.Wire.Length).Events);

            foreach (TraceEvent e in events.Where(e => e.Type == "tls.handshake.sent" || e.Type == "tls.handshake.received"))
            {
                bool clear = e.Message == "ClientHello" || e.Message == "ServerHello";
                Assert.All(e.Fields, f => Assert.Equal(clear, f.VisibleToWire));
            }
            Assert.Contains(events, e => e.Message == "Certificate" && e.Fields.Any(f => f.Name == "cert.issuer"));
        }
    }

    public class TrainingPkiTests
    {
        static readonly TrainingCa Ca = new TrainingCa(TlsKit.Keys);
        static readonly byte[] Spki = TrainingCa.Ed25519Spki(TlsKit.Keys.Find(KeyIds.ServerTlsEd25519).CopyPublic());

        static ChainVerdict Check(byte[] leaf, string name = "localhost", DateTime? now = null)
        {
            return ChainCheck.Run(new[] { Certificate.Parse(leaf) }, new[] { Certificate.Parse(Ca.RootCertificateDer) }, name, now ?? TlsKit.Now);
        }

        static byte[] GoodLeaf() => Ca.IssueServerCertificate("localhost", Spki, TrainingCa.DefaultNotBefore, TrainingCa.DefaultNotAfter);

        [Fact]
        public void The_root_parses_as_a_ca_and_the_leaf_reads_back()
        {
            Certificate root = Certificate.Parse(Ca.RootCertificateDer);
            Assert.True(root.IsCa);
            Assert.True(root.KeyIsEd25519);
            Assert.True(root.VerifySignedBy(root.PublicKey));

            Certificate leaf = Certificate.Parse(GoodLeaf());
            Assert.False(leaf.IsCa);
            Assert.Equal(new[] { "localhost" }, leaf.DnsNames);
            Assert.Equal(TrainingCa.DefaultNotAfter, leaf.NotAfter);
        }

        [Fact]
        public void Each_chain_failure_has_its_code_beside_a_passing_control()
        {
            Assert.True(Check(GoodLeaf()).Passed);
            Assert.Equal(ChainCheck.Name, Check(GoodLeaf(), "other.example").Code);
            Assert.Equal(ChainCheck.Validity, Check(GoodLeaf(), now: new DateTime(2060, 1, 1, 0, 0, 0, DateTimeKind.Utc)).Code);

            byte[] flipped = GoodLeaf();
            flipped[20] ^= 1;
            Assert.Equal(ChainCheck.BadSignature, Check(flipped).Code);

            TrainingCa rogue = new TrainingCa(TlsKit.Keys.Find(KeyIds.AttackerEd25519), "Attacker training root");
            byte[] rogueLeaf = rogue.IssueServerCertificate("localhost", Spki, TrainingCa.DefaultNotBefore, TrainingCa.DefaultNotAfter);
            Assert.Equal(ChainCheck.NoAnchor, Check(rogueLeaf).Code);

            TrainingCa sameName = new TrainingCa(TlsKit.Keys.Find(KeyIds.AttackerEd25519), TrainingCa.RootName);
            byte[] impostor = sameName.IssueServerCertificate("localhost", Spki, TrainingCa.DefaultNotBefore, TrainingCa.DefaultNotAfter);
            Assert.Equal(ChainCheck.BadSignature, Check(impostor).Code);
        }

        [Fact]
        public void A_leaf_cannot_act_as_an_issuer()
        {
            Certificate leaf = Certificate.Parse(GoodLeaf());
            Assert.Equal(ChainCheck.NoAnchor, ChainCheck.Run(new[] { leaf }, new[] { leaf }, "localhost", TlsKit.Now).Code);
        }

        [Fact]
        public void A_cut_certificate_throws_the_parse_code()
        {
            byte[] leaf = GoodLeaf();
            byte[] cut = new byte[leaf.Length / 2];
            Buffer.BlockCopy(leaf, 0, cut, 0, cut.Length);
            ParseFailure failure = Assert.Throws<ParseFailure>(() => Certificate.Parse(cut));
            Assert.Equal(DerReader.ParseCode, failure.Code);
        }

        [Fact]
        public void Times_cross_the_utc_time_and_generalized_time_line()
        {
            DateTime late = new DateTime(2051, 6, 2, 3, 4, 5, DateTimeKind.Utc);
            Certificate leaf = Certificate.Parse(Ca.IssueServerCertificate("localhost", Spki, TrainingCa.DefaultNotBefore, late));
            Assert.Equal(late, leaf.NotAfter);
            Assert.Equal(TrainingCa.DefaultNotBefore, leaf.NotBefore);
        }

        [Fact]
        public void Export_writes_every_file_the_referees_read_and_the_same_bytes_twice()
        {
            string[] names = { "root.pem", "srv.pem", "srv.key", "rsa.pem", "rsa.key", "host.key", "rsa-host.key", "user.pub", "user.key", "issuer.pub" };
            string a = Path.Combine(Path.GetTempPath(), "netsec-pki-" + Guid.NewGuid().ToString("N")), b = a + "-b";
            try
            {
                TrainingPki.Export(a);
                TrainingPki.Export(b);
                foreach (string name in names)
                    Assert.Equal(File.ReadAllBytes(Path.Combine(a, name)), File.ReadAllBytes(Path.Combine(b, name)));
                Assert.StartsWith("ssh-ed25519 ", File.ReadAllText(Path.Combine(a, "user.pub")));
                Assert.StartsWith("-----BEGIN OPENSSH PRIVATE KEY-----", File.ReadAllText(Path.Combine(a, "rsa-host.key")));
            }
            finally
            {
                if (Directory.Exists(a)) Directory.Delete(a, true);
                if (Directory.Exists(b)) Directory.Delete(b, true);
            }
        }
    }

    public class Tls13LabTests
    {
        static LabContext Context(int seed, AttackDefinition attack, IStepGate gate, int deadlineMs = 0)
        {
            return new LabContext { SessionId = "s1", TraceId = "s1", Seed = seed, Gate = gate ?? new FreeRunGate(), Sink = new ListSink(), Clock = new FixedClock(1), Random = new SeededRandom(seed), Attack = attack, DeadlineMs = deadlineMs };
        }

        static LabResult Run(int lesson, LabContext c)
        {
            IFuture<LabResult> run = LabCatalog.Find(lesson).Run(c);
            Assert.True(run.Wait(60000), "the lab did not finish in 60 s");
            return run.Result;
        }

        static AttackDefinition Attack(string id) => AttackCatalog.All.Single(a => a.AttackId == id);

        [Theory]
        [InlineData(4)]
        [InlineData(5)]
        public void Each_lesson_completes_and_only_socket_events_carry_wire(int lesson)
        {
            LabContext c = Context(7, null, null);
            LabResult result = Run(lesson, c);
            Assert.True(result.Completed, result.FailedCode + " " + result.FailedCheck);
            TraceEvent[] events = ((ListSink)c.Sink).Events;
            Assert.All(events.Where(e => e.Wire != null), e => Assert.StartsWith("wire.", e.Type));
            foreach (string message in new[] { "ClientHello", "ServerHello", "EncryptedExtensions", "Certificate", "CertificateVerify", "Finished", "ApplicationData" })
                Assert.Contains(events, e => e.Type == "wire.sent" && e.Message == message);
            foreach (string check in new[] { "chain to trust anchor", "signature verify", "validity window", "name match", "CertificateVerify signature", "Finished verify_data" })
                Assert.Contains(events, e => e.Check != null && e.Check.Passed && e.Check.Name == check);
        }

        [Fact]
        public void Lesson_4_shows_the_ca_and_lesson_5_shows_the_hybrid()
        {
            LabContext four = Context(7, null, null), five = Context(7, null, null);
            Run(4, four);
            Run(5, five);
            Assert.Equal(new[] { "RootCertificate", "ServerCertificate" }, ((ListSink)four.Sink).Events.Where(e => e.Type == "ca.certificate.issued").Select(e => e.Message).ToArray());
            TraceSecret[] secrets = ((ListSink)five.Sink).Events.Where(e => e.Secrets != null && e.Actor == "client").SelectMany(e => e.Secrets).ToArray();
            Assert.Equal(new[] { "mlkem_shared", "x25519_shared", "hybrid_shared", "early_secret", "handshake_secret", "c_hs_traffic", "s_hs_traffic", "master_secret", "c_ap_traffic", "s_ap_traffic", "exp_master" }, secrets.Select(s => s.Name).ToArray());
            Assert.Equal(64, secrets.Single(s => s.Name == "hybrid_shared").Bytes.Length);
        }

        [Theory]
        [InlineData(4)]
        [InlineData(5)]
        public void A_same_seed_rerun_gives_the_same_engine_bytes(int lesson)
        {
            string[] Lines(LabContext c)
            {
                Assert.True(Run(lesson, c).Completed);
                return ((ListSink)c.Sink).Events.Where(e => !e.StreamId.EndsWith("/wire")).OrderBy(e => e.EventId, StringComparer.Ordinal).Select(TraceJson.ToLine).ToArray();
            }
            Assert.Equal(Lines(Context(21, null, null)), Lines(Context(21, null, null)));
            Assert.NotEqual(Lines(Context(21, null, null)), Lines(Context(22, null, null)));
        }

        [Fact]
        public void The_tampered_ml_kem_ciphertext_gives_two_secrets_and_no_ml_kem_error()
        {
            LabContext c = Context(7, Attack("L5-flip-mlkem-ciphertext"), null);
            LabResult result = Run(5, c);
            Assert.Equal("AEAD tag", result.FailedCheck);
            TraceSecret[] all = ((ListSink)c.Sink).Events.Where(e => e.Secrets != null).SelectMany(e => e.Secrets).Where(s => s.Name == "mlkem_shared").ToArray();
            Assert.Equal(2, all.Length);
            Assert.NotEqual(all[0].Bytes, all[1].Bytes);
        }

        /// <summary>Learnings S0 item 11. The deadline counts only while the gate holds nothing, so a learner can read one event for much longer than the deadline.</summary>
        [Fact]
        public void In_step_mode_a_held_event_stops_the_clock_and_a_stuck_read_still_ends_by_name()
        {
            const int deadline = 600;
            StepGate gate = new StepGate();
            IFuture<LabResult> run = LabCatalog.Find(5).Run(Context(7, Attack("L5-flip-record-length"), gate, deadline));

            System.Threading.Thread.Sleep(deadline * 3);
            Assert.False(run.IsCompleted, "the deadline fired while the learner held an event");
            Assert.True(gate.IsHolding);

            Stopwatch clock = Stopwatch.StartNew();
            while (!run.IsCompleted && clock.ElapsedMilliseconds < 30000)
            {
                gate.Step();
                System.Threading.Thread.Sleep(2);
            }
            Assert.True(run.IsCompleted, "the stuck read never ended");
            Assert.Equal(ErrorCodes.LinkDeadline, run.Result.FailedCode);
            Assert.Equal("read deadline", run.Result.FailedCheck);
        }

        [Fact]
        public void In_step_mode_the_control_finishes_with_no_deadline_error()
        {
            StepGate gate = new StepGate();
            IFuture<LabResult> run = LabCatalog.Find(5).Run(Context(7, null, gate, 600));
            Stopwatch clock = Stopwatch.StartNew();
            while (!run.IsCompleted && clock.ElapsedMilliseconds < 30000)
            {
                gate.Step();
                System.Threading.Thread.Sleep(2);
            }
            Assert.True(run.IsCompleted);
            Assert.True(run.Result.Completed, run.Result.FailedCode);
        }

        [Fact]
        public void The_lesson_4_and_5_rows_keep_the_names_in_the_list()
        {
            string[] expected =
            {
                "L4-flip-cert-byte", "L4-flip-cert-verify", "L4-expired-cert", "L4-wrong-name", "L4-unknown-ca",
                "L5-flip-finished", "L5-flip-record-byte", "L5-replace-key-share", "L5-flip-mlkem-ciphertext", "L5-flip-record-length",
            };
            Assert.Equal(expected, AttackCatalog.All.Where(a => a.Lesson == 4 || a.Lesson == 5).Select(a => a.AttackId).ToArray());
        }
    }

    public class GlassChannelTests
    {
        sealed class Hop
        {
            public IFuture<ISecureChannel> Client, Server;
            public ListSink Sink = new ListSink();
        }

        static Hop Open(IByteLink clientLink, IByteLink serverLink, IRandomSource clientRandom, IRandomSource serverRandom)
        {
            GlassTransportFactory factory = new GlassTransportFactory(new TrainingKeySource());
            Hop hop = new Hop();
            hop.Server = factory.Open(new TransportRequest { Protocol = WireProtocol.Tls13, Role = EngineRole.Server, Group = KexGroup.X25519MlKem768, Link = serverLink, Random = serverRandom, Sink = hop.Sink, TraceId = "t1", Hop = "hop2", SessionId = "s1", Actor = "server" });
            hop.Client = factory.Open(new TransportRequest { Protocol = WireProtocol.Tls13, Role = EngineRole.Client, Group = KexGroup.X25519MlKem768, Link = clientLink, Random = clientRandom, Sink = hop.Sink, TraceId = "t1", Hop = "hop2", SessionId = "s1", Actor = "gateway", PeerName = "localhost" });
            Assert.True(hop.Client.Wait(5000));
            Assert.True(hop.Server.Wait(5000));
            return hop;
        }

        static byte[] Get(IFuture<AppChunk> chunk)
        {
            Assert.True(chunk.Wait(30000), "no data in 30 s");
            return chunk.Result.Bytes;
        }

        static void ExchangeAndClose(Hop hop)
        {
            hop.Client.Result.Send(0, Encoding.UTF8.GetBytes("up"));
            Assert.Equal("up", Encoding.UTF8.GetString(Get(hop.Server.Result.Receive())));
            hop.Server.Result.Send(0, Encoding.UTF8.GetBytes("down"));
            Assert.Equal("down", Encoding.UTF8.GetString(Get(hop.Client.Result.Receive())));
            hop.Client.Result.Close();
            Assert.Empty(Get(hop.Server.Result.Receive()));
        }

        static byte[] WireSent(Hop hop, string actor) =>
            hop.Sink.Events.Where(e => e.Type == "wire.sent" && e.Actor == actor).SelectMany(e => e.Wire).ToArray();

        [Fact]
        public void A_channel_carries_data_both_ways_and_every_event_names_its_hop_and_trace()
        {
            MemoryLink[] links = MemoryLink.Pair();
            Hop hop = Open(links[0], links[1], new SeededRandom(1), new SeededRandom(2));
            ExchangeAndClose(hop);
            Assert.Equal("X25519MLKEM768", hop.Client.Result.Info.Group);
            Assert.All(hop.Sink.Events, e => { Assert.Equal("hop2", e.Hop); Assert.Equal("t1", e.TraceId); });
            Assert.Contains(hop.Sink.Events, e => e.Actor == "gateway" && e.Type == "wire.sent");
        }

        [Fact]
        public void A_failed_handshake_faults_receive_with_the_named_error()
        {
            MemoryLink[] links = MemoryLink.Pair();
            GlassTransportFactory factory = new GlassTransportFactory(new TrainingKeySource());
            IFuture<ISecureChannel> server = factory.Open(new TransportRequest { Protocol = WireProtocol.Tls13, Role = EngineRole.Server, Group = KexGroup.X25519, Link = links[1], Random = new SeededRandom(2), Sink = new ListSink() });
            IFuture<ISecureChannel> client = factory.Open(new TransportRequest { Protocol = WireProtocol.Tls13, Role = EngineRole.Client, Group = KexGroup.X25519, Link = links[0], Random = new SeededRandom(1), Sink = new ListSink(), PeerName = "not-the-name.example" });
            IFuture<AppChunk> chunk = client.Result.Receive();
            Assert.True(chunk.Wait(30000));
            Assert.True(chunk.IsFaulted);
            NetSecException error = Assert.IsType<NetSecException>(chunk.Exception);
            Assert.Equal(ChainCheck.Name, error.Error.Code);
            Assert.NotNull(server.Result);
        }

        [Fact]
        public void Tls_1_3_stays_refused_under_the_ce_profile()
        {
            IFuture<ISecureChannel> refused = new GlassTransportFactory(new TrainingKeySource()).Open(new TransportRequest { Protocol = WireProtocol.Tls13, Profile = NetSec.Bridge.DeviceProfile.Ce });
            Assert.True(refused.IsFaulted);
            Assert.Equal(ErrorCodes.CeTransportUnavailable, Assert.IsType<NetSecException>(refused.Exception).Error.Code);
        }

        // ------------------------------------------------------------ A10a anchor for one hop: the Go tap sees the bytes the trace names

        static string TapExe()
        {
            string go = Path.Combine(TlsKit.RepoRoot(), "acceptance", "referees", "go");
            string exe = Path.Combine(go, "bin", "tap.exe");
            if (File.Exists(exe)) return exe;
            ProcessStartInfo build = new ProcessStartInfo("go", "build -o bin/ ./tap") { WorkingDirectory = go, UseShellExecute = false };
            using (Process p = Process.Start(build)) { p.WaitForExit(); Assert.Equal(0, p.ExitCode); }
            return exe;
        }

        sealed class TapRun : IDisposable
        {
            public readonly Process P;
            public readonly int Port;
            public readonly string Log;

            public TapRun(int toPort)
            {
                Log = Path.Combine(Path.GetTempPath(), "netsec-tap-" + Guid.NewGuid().ToString("N") + ".hex");
                P = Process.Start(new ProcessStartInfo(TapExe(), "-listen 127.0.0.1:0 -to 127.0.0.1:" + toPort + " -log \"" + Log + "\" -naccept 1") { UseShellExecute = false, RedirectStandardOutput = true });
                Port = int.Parse(P.StandardOutput.ReadLine().Trim());
            }

            public byte[] Bytes(string direction)
            {
                List<byte> bytes = new List<byte>();
                using (FileStream file = new FileStream(Log, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (StreamReader reader = new StreamReader(file))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        string[] parts = line.Split(' ');
                        if (parts.Length == 4 && parts[1] == direction) bytes.AddRange(Hex.Decode(parts[3]));
                    }
                }
                return bytes.ToArray();
            }

            public void Dispose()
            {
                // The tap ends by itself when its links close. Between HasExited and Kill, .NET Framework then reports access denied.
                try { if (!P.HasExited) P.Kill(); }
                catch (InvalidOperationException) { }
                catch (System.ComponentModel.Win32Exception) { }
                P.WaitForExit(5000);
                Assert.True(P.HasExited, "the tap is still running");
                P.Dispose();
                // The log is a temp file, and Windows can hold it for a moment after the process ends.
                try { File.Delete(Log); } catch (IOException) { }
            }
        }

        /// <summary>One TLS 1.3 hop through the Go tap, with OS randomness. Returns the client's first wire bytes, which hold its random.</summary>
        static byte[] RunThroughTap()
        {
            LinkListener listener = new LinkListener(new IPEndPoint(IPAddress.Loopback, 0));
            using (TapRun tap = new TapRun(listener.Port))
            {
                IFuture<SocketLink> accepted = listener.Accept();
                IFuture<SocketLink> connected = SocketLink.Connect(new IPEndPoint(IPAddress.Loopback, tap.Port));
                Assert.True(connected.Wait(5000) && accepted.Wait(5000));
                listener.Close();

                Hop hop = Open(connected.Result, accepted.Result, null, null);
                ExchangeAndClose(hop);

                Stopwatch clock = Stopwatch.StartNew();
                byte[] up = WireSent(hop, "gateway"), down = WireSent(hop, "server");
                while (clock.ElapsedMilliseconds < 5000 && (tap.Bytes("c2s").Length < up.Length || tap.Bytes("s2c").Length < down.Length))
                {
                    System.Threading.Thread.Sleep(20);
                    up = WireSent(hop, "gateway");
                    down = WireSent(hop, "server");
                }
                Assert.NotEmpty(up);
                Assert.NotEmpty(down);
                Assert.Equal(tap.Bytes("c2s"), up);
                Assert.Equal(tap.Bytes("s2c"), down);
                return hop.Sink.Events.First(e => e.Type == "wire.sent" && e.Actor == "gateway").Wire;
            }
        }

        [Fact]
        public void The_go_tap_sees_the_wire_sent_bytes_each_way_and_two_runs_draw_different_randoms()
        {
            byte[] first = RunThroughTap(), second = RunThroughTap();
            const int RandomStart = 5 + 4 + 2;
            Assert.NotEqual(first.Skip(RandomStart).Take(32).ToArray(), second.Skip(RandomStart).Take(32).ToArray());
        }
    }
}
