using System;
using System.Collections.Generic;
using System.Linq;
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
using Xunit.Abstractions;

namespace NetSec.Tests
{
    /// <summary>RFC 8446 sections 5, 5.1, 5.4 and 6.1: what a record may be, and when. Each case stands beside the control that a good peer gets through.</summary>
    public class Tls13RecordRuleTests
    {
        static byte[] Clear(int type, params byte[] content) => RecordProtection.PlainRecord(type, 0x0303, content, 0, content.Length);

        static Tls13Engine[] OpenPair()
        {
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519), server = TlsKit.Server(Tls13Group.X25519);
            EngineDuel.Run(client, server);
            Assert.Equal(EngineStatus.Open, client.Status);
            Assert.Equal(EngineStatus.Open, server.Status);
            return new[] { client, server };
        }

        static EngineOutput Feed(Tls13Engine engine, byte[] bytes) => engine.Feed(bytes, 0, bytes.Length);

        /// <summary>The client after ServerHello: keys exist, and the sealed flight has not come.</summary>
        static Tls13Engine ClientWithKeys(out byte[] sealedFlight)
        {
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519), server = TlsKit.Server(Tls13Group.X25519);
            server.Start();
            byte[] hello = client.Start().Wire;
            byte[] flight = server.Feed(hello, 0, hello.Length).Wire;
            int helloLength = 5 + ((flight[3] << 8) | flight[4]);
            Assert.Equal(EngineStatus.Handshaking, client.Feed(flight, 0, helloLength).Status);
            sealedFlight = flight.Skip(helloLength).ToArray();
            return client;
        }

        public static IEnumerable<object[]> ClearRecords()
        {
            yield return new object[] { "close_notify", Clear(ContentType.Alert, 1, 0) };
            yield return new object[] { "fatal alert", Clear(ContentType.Alert, 2, 40) };
            yield return new object[] { "KeyUpdate", Clear(ContentType.Handshake, HandshakeType.KeyUpdate, 0, 0, 1, 0) };
            yield return new object[] { "NewSessionTicket", Clear(ContentType.Handshake, HandshakeType.NewSessionTicket, 0, 0, 0) };
        }

        [Theory]
        [MemberData(nameof(ClearRecords))]
        public void A_clear_record_after_keys_is_refused_on_both_roles(string name, byte[] record)
        {
            Assert.NotNull(name);
            foreach (Tls13Engine engine in OpenPair())
            {
                EngineOutput output = Feed(engine, record);
                Assert.Equal(EngineStatus.Failed, output.Status);
                Assert.Equal(ErrorCodes.UnexpectedMessage, output.Error.Code);
                Assert.Equal(-1, engine.AlertReceived);
            }
        }

        [Fact]
        public void A_sealed_close_notify_still_closes_cleanly_as_the_control()
        {
            Tls13Engine[] pair = OpenPair();
            byte[] notify = pair[0].Command(EngineCommand.Close).Wire;
            Assert.Equal(EngineStatus.Closed, Feed(pair[1], notify).Status);
        }

        [Fact]
        public void A_clear_encrypted_extensions_after_keys_does_not_advance_the_state()
        {
            byte[] sealedFlight;
            Tls13Engine client = ClientWithKeys(out sealedFlight);
            EngineOutput output = Feed(client, Clear(ContentType.Handshake, Tls13Messages.EncryptedExtensions()));
            Assert.Equal(ErrorCodes.UnexpectedMessage, output.Error.Code);

            Tls13Engine control = ClientWithKeys(out sealedFlight);
            Assert.Null(Feed(control, sealedFlight).Error);
            Assert.Equal(EngineStatus.Open, control.Status);
        }

        [Fact]
        public void A_close_notify_before_open_is_a_failure_and_never_a_clean_close()
        {
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519);
            client.Start();
            EngineOutput clear = Feed(client, Clear(ContentType.Alert, 1, 0));
            Assert.Equal(EngineStatus.Failed, clear.Status);
            Assert.Equal(ErrorCodes.PeerClosedEarly, clear.Error.Code);
            Assert.False(client.ReachedOpen);
        }

        [Fact]
        public void A_clear_fatal_alert_before_keys_still_reads_as_the_peers_alert()
        {
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519);
            client.Start();
            EngineOutput output = Feed(client, Clear(ContentType.Alert, 2, 70));
            Assert.Equal(Tls13Codes.AlertReceived, output.Error.Code);
            Assert.Equal(70, client.AlertReceived);
        }

        [Fact]
        public void A_dummy_ccs_passes_only_as_one_byte_of_value_1_and_only_before_the_peers_finished()
        {
            byte[] sealedFlight;
            Tls13Engine client = ClientWithKeys(out sealedFlight);
            EngineOutput good = Feed(client, Clear(ContentType.ChangeCipherSpec, 1));
            Assert.Null(good.Error);
            Assert.Contains(good.Events, e => e.Type == "tls.ccs.ignored");

            Assert.Equal(ErrorCodes.UnexpectedMessage, Feed(ClientWithKeys(out sealedFlight), Clear(ContentType.ChangeCipherSpec, 2)).Error.Code);
            Assert.Equal(ErrorCodes.UnexpectedMessage, Feed(ClientWithKeys(out sealedFlight), Clear(ContentType.ChangeCipherSpec, 1, 1, 1, 1, 1)).Error.Code);
            Assert.Equal(ErrorCodes.UnexpectedMessage, Feed(OpenPair()[0], Clear(ContentType.ChangeCipherSpec, 1)).Error.Code);

            Tls13Engine server = TlsKit.Server(Tls13Group.X25519);
            server.Start();
            Assert.Equal(ErrorCodes.UnexpectedMessage, Feed(server, Clear(ContentType.ChangeCipherSpec, 1)).Error.Code);
        }

        static byte[] ServerHelloBytes()
        {
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519), server = TlsKit.Server(Tls13Group.X25519);
            server.Start();
            byte[] hello = client.Start().Wire;
            byte[] flight = server.Feed(hello, 0, hello.Length).Wire;
            int length = (flight[3] << 8) | flight[4];
            return flight.Skip(5).Take(length).ToArray();
        }

        [Fact]
        public void A_message_may_not_cross_a_key_change()
        {
            byte[] hello = ServerHelloBytes();

            Tls13Engine whole = TlsKit.Client(Tls13Group.X25519);
            whole.Start();
            byte[] extra = hello.Concat(Tls13Messages.EncryptedExtensions()).ToArray();
            Assert.Equal(Tls13Codes.KeyChangeBoundary, Feed(whole, Clear(ContentType.Handshake, extra)).Error.Code);

            Tls13Engine half = TlsKit.Client(Tls13Group.X25519);
            half.Start();
            byte[] part = hello.Concat(new byte[] { HandshakeType.EncryptedExtensions, 0 }).ToArray();
            Assert.Equal(Tls13Codes.KeyChangeBoundary, Feed(half, Clear(ContentType.Handshake, part)).Error.Code);
        }

        [Fact]
        public void Record_and_message_limits_are_named()
        {
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519);
            client.Start();
            byte[] empty = { 22, 3, 3, 0, 0 };
            Assert.Equal(ErrorCodes.UnexpectedMessage, Feed(client, empty).Error.Code);

            Tls13Engine big = TlsKit.Client(Tls13Group.X25519);
            big.Start();
            byte[] over = new ByteWriter().U8(ContentType.ChangeCipherSpec).U16(0x0303).U16(16385).Put(new byte[16385]).ToArray();
            Assert.Equal(Tls13Codes.RecordOverflow, Feed(big, over).Error.Code);

            Tls13Engine huge = TlsKit.Client(Tls13Group.X25519);
            huge.Start();
            Assert.Equal(Tls13Codes.MessageTooLong, Feed(huge, Clear(ContentType.Handshake, HandshakeType.ServerHello, 0xFF, 0, 0)).Error.Code);

            RecordProtection seal = new RecordProtection(new byte[16], new byte[12]), open = new RecordProtection(new byte[16], new byte[12]);
            byte[] record = seal.Seal(ContentType.ApplicationData, new byte[16385], 0, 16385);
            byte[] header = record.Take(5).ToArray(), payload = record.Skip(5).ToArray();
            int type;
            byte[] content;
            ParseFailure failure = Assert.Throws<ParseFailure>(() => open.TryOpen(header, payload, out type, out content));
            Assert.Equal(Tls13Codes.RecordOverflow, failure.Code);
        }

        [Fact]
        public void A_tcp_close_with_no_close_notify_is_named_truncation_on_both_roles()
        {
            foreach (Tls13Engine engine in OpenPair())
            {
                EngineOutput output = engine.Command(EngineCommand.PeerClosed);
                Assert.Equal(EngineStatus.Failed, output.Status);
                Assert.Equal(Tls13Codes.Truncated, output.Error.Code);
                Assert.Equal("close_notify before the close", output.Error.CheckName);
            }
        }
    }

    /// <summary>
    /// Each input here made Feed throw, so the pump reported LINK_LOST with no check name. Docs: ux-design.md moment 4 promises a named check for any byte.
    /// </summary>
    public class Tls13BadInputTests
    {
        static EngineOutput FeedServer(byte[] handshake)
        {
            Tls13Engine server = TlsKit.Server(Tls13Group.X25519);
            server.Start();
            byte[] record = TlsKit.Plain(handshake);
            return server.Feed(record, 0, record.Length);
        }

        static byte[] Hello() => Tls13Messages.ClientHello(TlsKit.Bytes32(8), "localhost", Tls13Group.X25519, X25519.MultBase(TlsKit.Bytes32(5)));

        const int ServerNameExtensionLengthOffset = 52;
        const int ServerNameHostLengthOffset = 57;

        [Fact]
        public void The_offsets_in_these_cases_point_at_the_server_name()
        {
            Assert.Null(FeedServer(Hello()).Error);
            byte[] hello = Hello();
            Assert.Equal(14, hello[ServerNameExtensionLengthOffset]);
            Assert.Equal(9, hello[ServerNameHostLengthOffset]);
        }

        [Fact]
        public void A_server_name_length_mismatch_is_a_named_parse_failure()
        {
            byte[] hello = Hello();
            hello[ServerNameHostLengthOffset] = 5;
            EngineOutput output = FeedServer(hello);
            Assert.Equal(EngineStatus.Failed, output.Status);
            Assert.Equal(ErrorCodes.ParseTruncated, output.Error.Code);
        }

        [Fact]
        public void A_short_server_name_extension_is_a_named_parse_failure()
        {
            byte[] hello = Hello();
            hello[ServerNameExtensionLengthOffset] = 2;
            EngineOutput output = FeedServer(hello);
            Assert.Equal(EngineStatus.Failed, output.Status);
            Assert.NotNull(output.Error.CheckName);
        }

        [Fact]
        public void A_tls_1_3_answer_to_a_tls_1_1_offer_is_named()
        {
            Tls13Options o = TlsKit.Common("client", "server", Tls13Group.X25519, 1);
            o.OfferOnlyTls11 = true;
            o.TrustAnchors = new[] { new TrainingCa(TlsKit.Keys).RootCertificateDer };
            Tls13Engine client = Tls13Engine.CreateClient(o);
            client.Start();
            byte[] record = TlsKit.Plain(Tls13Messages.ServerHello(TlsKit.Bytes32(9), new byte[0], Tls13Suite.Aes128, Tls13Group.X25519, X25519.MultBase(TlsKit.Bytes32(5))));
            EngineOutput output = client.Feed(record, 0, record.Length);
            Assert.Equal(EngineStatus.Failed, output.Status);
            Assert.Equal(Tls13Codes.IllegalParameter, output.Error.Code);
        }

        [Fact]
        public void A_certificate_with_an_invalid_month_is_the_parse_code_and_never_an_exception()
        {
            byte[] leaf = TrainingPki.ServerCertificate(new TrainingCa(TlsKit.Keys), TlsKit.Keys.Find(KeyIds.ServerTlsEd25519));
            FieldMark before = Certificate.Parse(leaf).Marks(0, true).Single(m => m.Name == "cert.not_before");
            byte[] bad = (byte[])leaf.Clone();
            bad[before.Offset + 4] = (byte)'9';
            ParseFailure failure = Assert.Throws<ParseFailure>(() => Certificate.Parse(bad));
            Assert.Equal(DerReader.ParseCode, failure.Code);
        }

        [Fact]
        public void A_server_hello_with_a_bad_legacy_version_or_compression_is_refused()
        {
            byte[] good = Tls13Messages.ServerHello(TlsKit.Bytes32(9), new byte[0], Tls13Suite.Aes128, Tls13Group.X25519, X25519.MultBase(TlsKit.Bytes32(5)));
            byte[] version = (byte[])good.Clone();
            version[5] = 2;
            byte[] compression = (byte[])good.Clone();
            compression[41] = 1;
            foreach (byte[] hello in new[] { version, compression })
            {
                Tls13Engine client = TlsKit.Client(Tls13Group.X25519);
                client.Start();
                byte[] record = TlsKit.Plain(hello);
                Assert.Equal(Tls13Codes.IllegalParameter, client.Feed(record, 0, record.Length).Error.Code);
            }
        }

        [Fact]
        public void A_downgrade_sentinel_in_a_tls_1_3_hello_is_refused_so_the_pass_is_a_real_read()
        {
            byte[] random = TlsKit.Bytes32(9);
            Encoding.UTF8.GetBytes("DOWNGRD").CopyTo(random, 24);
            random[31] = 1;
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519);
            client.Start();
            byte[] record = TlsKit.Plain(Tls13Messages.ServerHello(random, new byte[0], Tls13Suite.Aes128, Tls13Group.X25519, X25519.MultBase(TlsKit.Bytes32(5))));
            Assert.Equal(Tls13Codes.DowngradeSentinel, client.Feed(record, 0, record.Length).Error.Code);
        }
    }

    /// <summary>Certificate bytes no signature covers, and extensions no code here reads. RFC 5280 sections 4.1.1.2 and 4.2.</summary>
    public class CertificateStrictnessTests
    {
        const string Ed25519Oid = "2b6570";
        static readonly byte[] CaSeed = TlsKit.Keys.Find(KeyIds.CaRoot).CopyMaterial();

        static byte[] Name(string cn) => Der.Sequence(Der.Set(Der.Sequence(Der.Oid("550403"), Der.Utf8(cn))));

        static byte[] Build(string tbsAlgorithmOid, params byte[][] extensions)
        {
            byte[] spki = TrainingCa.Ed25519Spki(TlsKit.Keys.Find(KeyIds.ServerTlsEd25519).CopyPublic());
            byte[] san = Der.Sequence(Der.Oid("551d11"), Der.OctetString(Der.Sequence(Der.Tlv(0x82, Encoding.UTF8.GetBytes("localhost")))));
            byte[] tbs = Der.Sequence(
                Der.Tlv(0xA0, Der.Integer(new byte[] { 2 })),
                Der.Integer(new byte[] { 0x41, 1 }),
                Der.Sequence(Der.Oid(tbsAlgorithmOid)),
                Name(TrainingCa.RootName),
                Der.Sequence(Der.Time(TrainingCa.DefaultNotBefore), Der.Time(TrainingCa.DefaultNotAfter)),
                Name("localhost"),
                spki,
                Der.Tlv(0xA3, Der.Sequence(new[] { san }.Concat(extensions).ToArray())));
            return Der.Sequence(tbs, Der.Sequence(Der.Oid(Ed25519Oid)), Der.BitString(Ed25519.Sign(CaSeed, tbs)));
        }

        static ChainVerdict Check(byte[] leaf)
        {
            Certificate root = Certificate.Parse(new TrainingCa(TlsKit.Keys).RootCertificateDer);
            return ChainCheck.Run(new[] { Certificate.Parse(leaf) }, new[] { root }, "localhost", TlsKit.Now);
        }

        static byte[] Extension(string oid, bool critical) => critical
            ? Der.Sequence(Der.Oid(oid), Der.Boolean(true), Der.OctetString(Der.Sequence()))
            : Der.Sequence(Der.Oid(oid), Der.OctetString(Der.Sequence()));

        [Fact]
        public void A_built_certificate_passes_as_the_control()
        {
            Assert.True(Check(Build(Ed25519Oid)).Passed);
        }

        [Fact]
        public void An_unknown_critical_extension_is_refused_and_a_non_critical_one_is_read_past()
        {
            const string Unknown = "2a0304";
            Assert.Equal(ChainCheck.UnknownCritical, Check(Build(Ed25519Oid, Extension(Unknown, true))).Code);
            Assert.True(Check(Build(Ed25519Oid, Extension(Unknown, false))).Passed);
        }

        [Fact]
        public void Bytes_after_the_certificate_are_a_parse_failure()
        {
            byte[] trailing = Build(Ed25519Oid).Concat(new byte[] { 1, 2, 3 }).ToArray();
            Assert.Equal(DerReader.ParseCode, Assert.Throws<ParseFailure>(() => Certificate.Parse(trailing)).Code);
        }

        [Fact]
        public void A_tbs_algorithm_that_differs_from_the_outer_one_is_a_parse_failure()
        {
            byte[] mismatch = Build("2b6571");
            Assert.Equal(DerReader.ParseCode, Assert.Throws<ParseFailure>(() => Certificate.Parse(mismatch)).Code);
        }
    }

    /// <summary>The sweep runs thousands of handshakes. It runs alone, after the parallel tests, so it takes no CPU from a test that measures time.</summary>
    [CollectionDefinition(Name, DisableParallelization = true)]
    public sealed class SweepCollection
    {
        public const string Name = "CPU-heavy sweep";
    }

    /// <summary>
    /// ux-design.md moment 4: flip any byte, and the first check that fails has a name. This flips each byte of each message a handshake sends,
    /// before the seal and on the wire. No flip may throw. A flip that stalls must sit in a length field, and the pump's deadline names that one.
    /// </summary>
    [Collection(SweepCollection.Name)]
    public class Tls13FlipSweepTests
    {
        readonly ITestOutputHelper _output;
        public Tls13FlipSweepTests(ITestOutputHelper output) { _output = output; }

        const int MaxListed = 12;
        const int SealedStride = 7;

        sealed class Flip : ITamperHook
        {
            public int Send = -1, Offset, Seen;
            public TamperResult Apply(TamperPoint point, string streamId, long streamSeq, string message, byte[] bytes)
            {
                if (point != TamperPoint.Plain) return TamperResult.Unchanged;
                if (Seen++ != Send) return TamperResult.Unchanged;
                byte[] changed = (byte[])bytes.Clone();
                changed[Offset] ^= 1;
                return TamperResult.Replace(changed);
            }
        }

        sealed class Sent
        {
            public string Actor, Message;
            public int PlainLength, WireLength;
        }

        enum Outcome { Named, Completed, Stalled }

        sealed class Duel
        {
            public readonly List<Sent> Sends = new List<Sent>();
            public Tls13Engine Client, Server;
            public Outcome Outcome;
            public string Code;
            int _wireIndex;
            readonly int _wireSend, _wireOffset;

            public Duel(Tls13Group group, Flip plainFlip, int wireSend, int wireOffset, bool mutual = false)
            {
                _wireSend = wireSend; _wireOffset = wireOffset;
                Tls13Options c = TlsKit.Common("client", "server", group, 1);
                c.TrustAnchors = new[] { new TrainingCa(TlsKit.Keys).RootCertificateDer };
                c.Tamper = plainFlip;
                if (mutual)
                {
                    ITrainingKey clientKey = TlsKit.Keys.Find(KeyIds.SshClient);
                    c.CertificateChain = new[] { TrainingPki.ClientCertificate(new TrainingCa(TlsKit.Keys), clientKey) };
                    c.SigningSeed = clientKey.CopyMaterial();
                }
                Client = Tls13Engine.CreateClient(c);
                Tls13Options s = TlsKit.Common("server", "client", group, 2);
                ITrainingKey key = TlsKit.Keys.Find(KeyIds.ServerTlsEd25519);
                s.CertificateChain = new[] { TrainingPki.ServerCertificate(new TrainingCa(TlsKit.Keys), key) };
                s.SigningSeed = key.CopyMaterial();
                s.Tamper = plainFlip;
                if (mutual)
                {
                    s.RequireClientCertificate = true;
                    s.TrustAnchors = new[] { new TrainingCa(TlsKit.Keys).RootCertificateDer };
                }
                Server = Tls13Engine.CreateServer(s);
            }

            /// <summary>Collects wire bytes from an output one message at a time, so the wire flip addresses one send. Stops at the first alert: a real peer reads no further.</summary>
            byte[] Collect(EngineOutput output, string actor)
            {
                List<byte> wire = new List<byte>();
                foreach (OutputItem item in output.Items)
                {
                    if (item.Wire == null) continue;
                    byte[] bytes = (byte[])item.Wire.Clone();
                    if (_wireIndex == _wireSend) bytes[_wireOffset] ^= 1;
                    Sends.Add(new Sent { Actor = actor, Message = item.Event.Message, PlainLength = item.Event.Plain.Length, WireLength = bytes.Length });
                    _wireIndex++;
                    wire.AddRange(bytes);
                }
                return wire.ToArray();
            }

            public void Run()
            {
                Server.Start();
                byte[] toServer = Collect(Client.Start(), "client"), toClient = new byte[0];
                while (toServer.Length > 0 || toClient.Length > 0)
                {
                    byte[] fromServer = toServer.Length > 0 ? Collect(Server.Feed(toServer, 0, toServer.Length), "server") : new byte[0];
                    byte[] fromClient = toClient.Length > 0 ? Collect(Client.Feed(toClient, 0, toClient.Length), "client") : new byte[0];
                    toServer = fromClient;
                    toClient = fromServer;
                }
                Classify();
            }

            void Classify()
            {
                // The first side to name a failure is the catch. The other side then only read an alert.
                NetSecError first = First(Client) ?? First(Server);
                if (first != null)
                {
                    Outcome = Outcome.Named;
                    Code = first.Code;
                    CheckName = first.CheckName;
                    return;
                }
                Outcome = Client.Status == EngineStatus.Open && Server.Status == EngineStatus.Open ? Outcome.Completed : Outcome.Stalled;
            }

            public string CheckName;

            static NetSecError First(Tls13Engine engine)
            {
                NetSecError error = engine.Status == EngineStatus.Failed ? engine.LastError : null;
                return error != null && error.Code == Tls13Codes.AlertReceived ? null : error ?? null;
            }
        }

        static List<Sent> Baseline(Tls13Group group, bool mutual = false)
        {
            Duel duel = new Duel(group, null, -1, 0, mutual);
            duel.Run();
            Assert.Equal(Outcome.Completed, duel.Outcome);
            return duel.Sends;
        }

        /// <summary>Runs one flip, and writes one line for anything the sweep does not accept.</summary>
        static void Check(List<string> faults, Dictionary<string, int> tally, Tls13Group group, string what, Flip plain, int wireSend, int wireOffset, Func<bool> mayStallOrPass, bool mutual = false)
        {
            Duel duel = new Duel(group, plain, wireSend, wireOffset, mutual);
            try { duel.Run(); }
            catch (Exception e)
            {
                faults.Add(what + ": THROWS " + e.GetType().Name + ": " + e.Message);
                return;
            }
            string key = duel.Outcome == Outcome.Named ? duel.Code : duel.Outcome.ToString();
            int count;
            tally.TryGetValue(key, out count);
            tally[key] = count + 1;
            if (duel.Outcome == Outcome.Named && string.IsNullOrEmpty(duel.CheckName)) faults.Add(what + ": code " + duel.Code + " has no check name");
            if (duel.Outcome != Outcome.Named && !mayStallOrPass()) faults.Add(what + ": " + duel.Outcome);
        }

        /// <summary>A wire record: bytes 1 and 2 are the legacy version, which RFC 8446 section 5.1 says a receiver ignores. Bytes 3 and 4 are the length.</summary>
        static bool RecordHeaderMayPass(int offset) => offset >= 1 && offset <= 4;

        /// <summary>A clear hello's own length field sits right after the record header and the type byte.</summary>
        static bool ClearLengthMayStall(Sent sent, int offset) => (sent.Message == "ClientHello" || sent.Message == "ServerHello") && offset >= 6 && offset <= 8;

        /// <summary>Sealed bytes all take one path, the tag. A stride keeps the suite short. The header and the first bytes run in full.</summary>
        static bool SkipSealedByte(Sent sent, int offset) => sent.Message != "ClientHello" && sent.Message != "ServerHello" && offset >= 12 && offset % SealedStride != 0;

        static string Report(List<string> faults, Dictionary<string, int> tally) =>
            faults.Count + " faults. First: " + string.Join(" | ", faults.Take(MaxListed)) + ". Tally: " + string.Join(", ", tally.OrderBy(k => k.Key).Select(k => k.Key + "=" + k.Value));

        [Fact]
        public void Every_byte_of_an_x25519_handshake_gives_a_named_result_at_both_tamper_points()
        {
            List<Sent> sends = Baseline(Tls13Group.X25519);
            List<string> faults = new List<string>();
            Dictionary<string, int> tally = new Dictionary<string, int>();
            for (int k = 0; k < sends.Count; k++)
            {
                Sent sent = sends[k];
                for (int offset = 0; offset < sent.PlainLength; offset++)
                {
                    int at = offset;
                    // The message length field can promise more bytes than come. The pump's deadline names that wait.
                    Check(faults, tally, Tls13Group.X25519, sent.Actor + " " + sent.Message + " plain+" + at, new Flip { Send = k, Offset = at }, -1, 0, () => at >= 1 && at <= 3);
                }
                for (int offset = 0; offset < sent.WireLength; offset++)
                {
                    if (SkipSealedByte(sent, offset)) continue;
                    int at = offset;
                    Check(faults, tally, Tls13Group.X25519, sent.Actor + " " + sent.Message + " wire+" + at, new Flip(), k, at, () => RecordHeaderMayPass(at) || ClearLengthMayStall(sent, at));
                }
            }
            _output.WriteLine(Report(faults, tally));
            Assert.True(faults.Count == 0, Report(faults, tally));
            Assert.True(tally.ContainsKey(Tls13Codes.AeadTag) && tally.ContainsKey(Tls13Codes.FinishedMismatch) && tally.ContainsKey(Tls13Codes.CertVerifyBad) && tally.ContainsKey(ChainCheck.BadSignature), Report(faults, tally));
        }

        /// <summary>The client's flight in mutual TLS: a server reads these bytes before the client has proved anything, so a throw here is reachable by anyone who connects.</summary>
        [Fact]
        public void Every_byte_of_the_client_flight_in_mutual_tls_gives_a_named_result_at_the_server()
        {
            List<Sent> sends = Baseline(Tls13Group.X25519, true);
            List<string> faults = new List<string>();
            Dictionary<string, int> tally = new Dictionary<string, int>();
            int covered = 0;
            for (int k = 0; k < sends.Count; k++)
            {
                Sent sent = sends[k];
                if (sent.Actor != "client" || sent.Message == "ClientHello") continue;
                covered++;
                for (int offset = 0; offset < sent.PlainLength; offset++)
                {
                    int at = offset;
                    Check(faults, tally, Tls13Group.X25519, "mutual client " + sent.Message + " plain+" + at, new Flip { Send = k, Offset = at }, -1, 0, () => at >= 1 && at <= 3, true);
                }
                for (int offset = 0; offset < sent.WireLength; offset++)
                {
                    if (SkipSealedByte(sent, offset)) continue;
                    int at = offset;
                    Check(faults, tally, Tls13Group.X25519, "mutual client " + sent.Message + " wire+" + at, new Flip(), k, at, () => at == 3 || at == 4, true);
                }
            }
            _output.WriteLine(Report(faults, tally));
            Assert.True(faults.Count == 0, Report(faults, tally));
            Assert.Equal(3, covered);
            Assert.True(tally.ContainsKey(DerReader.ParseCode) && tally.ContainsKey(Tls13Codes.FinishedMismatch), Report(faults, tally));
        }

        [Fact]
        public void Every_byte_outside_the_ml_kem_values_of_a_hybrid_hello_gives_a_named_result_and_each_ml_kem_value_is_sampled()
        {
            const int Stride = 37;
            List<Sent> sends = Baseline(Tls13Group.X25519MlKem768);
            List<string> faults = new List<string>();
            Dictionary<string, int> tally = new Dictionary<string, int>();
            for (int k = 0; k < sends.Count; k++)
            {
                Sent sent = sends[k];
                if (sent.Message != "ClientHello" && sent.Message != "ServerHello") continue;
                int mlKemStart = sent.Message == "ClientHello" ? Tls13Lab.ClientX25519ShareOffset - 1184 : Tls13Lab.ServerMlKemCiphertextOffset - 10 + 0;
                int mlKemLength = sent.Message == "ClientHello" ? 1184 : 1088;
                for (int offset = 0; offset < sent.PlainLength; offset++)
                {
                    bool inside = offset >= mlKemStart + 8 && offset < mlKemStart + mlKemLength - 8;
                    if (inside && offset % Stride != 0) continue;
                    int at = offset;
                    Check(faults, tally, Tls13Group.X25519MlKem768, sent.Actor + " " + sent.Message + " plain+" + at, new Flip { Send = k, Offset = at }, -1, 0, () => at >= 1 && at <= 3);
                }
            }
            _output.WriteLine(Report(faults, tally));
            Assert.True(faults.Count == 0, Report(faults, tally));
            Assert.True(tally.ContainsKey(Tls13Codes.AeadTag), Report(faults, tally));
        }
    }

    /// <summary>Jared's verdict on PR 20: mutual TLS gives the record rules new reach on the server, before the client proves anything.</summary>
    public class Tls13MutualServerTests
    {
        static Tls13Engine ServerWaitingForClient(out byte[] clientHello)
        {
            Tls13Options s = TlsKit.Common("server", "client", Tls13Group.X25519, 2);
            ITrainingKey key = TlsKit.Keys.Find(KeyIds.ServerTlsEd25519);
            s.CertificateChain = new[] { TrainingPki.ServerCertificate(new TrainingCa(TlsKit.Keys), key) };
            s.SigningSeed = key.CopyMaterial();
            s.RequireClientCertificate = true;
            s.TrustAnchors = new[] { new TrainingCa(TlsKit.Keys).RootCertificateDer };
            Tls13Engine server = Tls13Engine.CreateServer(s);
            server.Start();
            clientHello = TlsKit.Client(Tls13Group.X25519).Start().Wire;
            Assert.Equal(EngineStatus.Handshaking, server.Feed(clientHello, 0, clientHello.Length).Status);
            return server;
        }

        public static IEnumerable<object[]> ClearRecords()
        {
            byte[] emptyCertificate = Tls13Messages.CertificateMessage(new byte[0][]);
            yield return new object[] { "empty Certificate", RecordProtection.PlainRecord(ContentType.Handshake, 0x0303, emptyCertificate, 0, emptyCertificate.Length) };
            yield return new object[] { "close_notify", RecordProtection.PlainRecord(ContentType.Alert, 0x0303, new byte[] { 1, 0 }, 0, 2) };
            byte[] finished = Tls13Messages.Finished(new byte[32]);
            yield return new object[] { "Finished", RecordProtection.PlainRecord(ContentType.Handshake, 0x0303, finished, 0, finished.Length) };
        }

        /// <summary>A forged empty Certificate must not read as a client with no certificate. The reason a learner sees must be the true one.</summary>
        [Theory]
        [MemberData(nameof(ClearRecords))]
        public void A_clear_record_gets_the_true_reason_while_the_server_waits_for_the_client(string name, byte[] record)
        {
            Assert.NotNull(name);
            byte[] hello;
            Tls13Engine server = ServerWaitingForClient(out hello);
            EngineOutput output = server.Feed(record, 0, record.Length);
            Assert.Equal(EngineStatus.Failed, output.Status);
            Assert.Equal(ErrorCodes.UnexpectedMessage, output.Error.Code);
        }

        [Fact]
        public void A_client_certificate_with_a_bad_date_is_named_at_the_server_and_never_a_throw()
        {
            ITrainingKey clientKey = TlsKit.Keys.Find(KeyIds.SshClient);
            byte[] good = TrainingPki.ClientCertificate(new TrainingCa(TlsKit.Keys), clientKey);
            FieldMark before = Certificate.Parse(good).Marks(0, true).Single(m => m.Name == "cert.not_before");
            byte[] bad = (byte[])good.Clone();
            bad[before.Offset + 4] = (byte)'9';
            Assert.Equal(DerReader.ParseCode, Assert.Throws<ParseFailure>(() => Certificate.Parse(bad)).Code);

            byte[] message = Tls13Messages.CertificateMessage(new[] { bad });
            TraceField[] fields = Tls13Messages.FieldsOf(HandshakeType.Certificate, message, false);
            Assert.NotEmpty(fields);
        }
    }

    /// <summary>Through real sockets, so a throw would show as LINK_LOST with no name. Jared's two cases from the verdict on PR 28.</summary>
    public class Tls13LabNamedFlipTests
    {
        static LabResult Run(int lesson, TamperPlan plan)
        {
            AttackDefinition attack = new AttackDefinition { AttackId = "test", Lesson = lesson, Kind = "flip-byte", Plan = plan, Options = new LabOption[0] };
            LabContext c = new LabContext { SessionId = "s1", TraceId = "s1", Seed = 7, Gate = new FreeRunGate(), Sink = new ListSink(), Clock = new FixedClock(1), Random = new SeededRandom(7), Attack = attack, DeadlineMs = 3000 };
            IFuture<LabResult> run = LabCatalog.Find(lesson).Run(c);
            Assert.True(run.Wait(30000));
            return run.Result;
        }

        [Fact]
        public void A_flipped_certificate_month_digit_names_certificate_parse()
        {
            byte[] leaf = TrainingPki.ServerCertificate(new TrainingCa(TlsKit.Keys), TlsKit.Keys.Find(KeyIds.ServerTlsEd25519));
            FieldMark before = Certificate.Parse(leaf).Marks(0, true).Single(m => m.Name == "cert.not_before");
            const int CertificateStart = 11;
            LabResult result = Run(4, new TamperPlan { Point = TamperPoint.Plain, Message = "Certificate", Offset = CertificateStart + before.Offset + 4, Xor = 9 });
            Assert.Equal(DerReader.ParseCode, result.FailedCode);
            Assert.Equal("certificate parse", result.FailedCheck);
        }

        [Fact]
        public void A_flipped_server_name_length_names_message_parse()
        {
            LabResult result = Run(4, new TamperPlan { Point = TamperPoint.Plain, Message = "ClientHello", Offset = 57, Xor = 4 });
            Assert.Equal(ErrorCodes.ParseTruncated, result.FailedCode);
            Assert.Equal("message parse", result.FailedCheck);
        }

        static TraceSecret[] Shared(LabContext c) =>
            ((ListSink)c.Sink).Events.Where(e => e.Secrets != null).SelectMany(e => e.Secrets).Where(s => s.Name == "x25519_shared").ToArray();

        /// <summary>
        /// The row proves less than its name. Any flip in a hello moves the transcript the keys come from, so a flip in the hello's random gives the same AEAD tag.
        /// Only the shared secret tells the two cases apart: it differs for the key share, and it matches for the random.
        /// </summary>
        [Fact]
        public void The_key_share_row_differs_from_a_random_flip_only_in_the_shared_secret()
        {
            LabContext shareRun = new LabContext { SessionId = "s1", TraceId = "s1", Seed = 7, Gate = new FreeRunGate(), Sink = new ListSink(), Clock = new FixedClock(1), Random = new SeededRandom(7), Attack = AttackCatalog.All.Single(a => a.AttackId == "L5-replace-key-share") };
            IFuture<LabResult> share = LabCatalog.Find(5).Run(shareRun);
            Assert.True(share.Wait(30000));
            Assert.Equal(Tls13Codes.AeadTag, share.Result.FailedCode);
            TraceSecret[] shareSecrets = Shared(shareRun);
            Assert.Equal(2, shareSecrets.Length);
            Assert.NotEqual(shareSecrets[0].Bytes, shareSecrets[1].Bytes);

            const int RandomOffset = 8;
            AttackDefinition randomFlip = new AttackDefinition { AttackId = "test", Lesson = 5, Kind = "flip-byte", Options = new LabOption[0], Plan = new TamperPlan { Point = TamperPoint.Plain, Message = "ClientHello", Offset = RandomOffset } };
            LabContext randomRun = new LabContext { SessionId = "s1", TraceId = "s1", Seed = 7, Gate = new FreeRunGate(), Sink = new ListSink(), Clock = new FixedClock(1), Random = new SeededRandom(7), Attack = randomFlip };
            IFuture<LabResult> random = LabCatalog.Find(5).Run(randomRun);
            Assert.True(random.Wait(30000));
            Assert.Equal(Tls13Codes.AeadTag, random.Result.FailedCode);
            TraceSecret[] randomSecrets = Shared(randomRun);
            Assert.Equal(2, randomSecrets.Length);
            Assert.Equal(randomSecrets[0].Bytes, randomSecrets[1].Bytes);
        }
    }
}
