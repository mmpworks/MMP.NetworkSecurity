using System;
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
using NetSec.Tls11;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>The TLS 1.1 engine with no socket, on both builds. OpenSSL judges it in acceptance clause A7. docs/lesson-tls11-names.md is the list these names come from.</summary>
    public class Tls11Tests
    {
        static readonly ITrainingKeySource Keys = new TrainingKeySource();
        static readonly DateTime Now = new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc);
        static readonly byte[] Label = Hex.Decode("74657374206c6162656c");

        static TraceStream Stream(string actor) =>
            new TraceStream("s/" + actor + "/tls11", "s", "s", null, actor, new FixedClock(0));

        static Tls11Options Options(string actor, Tls11CipherSuite suite, int seed) => new Tls11Options
        {
            Suite = suite,
            Random = new SeededRandom(seed),
            Stream = Stream(actor),
        };

        static Tls11Engine Client(Tls11CipherSuite suite, byte[] send = null, ITamperHook tamper = null, DateTime? now = null)
        {
            Tls11Options o = Options("client", suite, 11);
            Tls11Training.TrustTrainingRoot(o, Keys, now ?? Now);
            o.SendOnOpen = send;
            o.CloseAfterReply = true;
            o.Tamper = tamper;
            return Tls11Engine.CreateClient(o);
        }

        static Tls11Engine Server(Tls11CipherSuite suite, bool sentinel = false, ITamperHook tamper = null)
        {
            Tls11Options o = Options("server", suite, 22);
            Tls11Training.UseTrainingServerKey(o, Keys);
            o.WriteDowngradeTail = sentinel;
            o.EchoReceived = true;
            o.Tamper = tamper;
            return Tls11Engine.CreateServer(o);
        }

        // Known answers from OpenSSL 3.5.7: openssl kdf -keylen N -kdfopt digest:MD5-SHA1 -kdfopt hexsecret:S -kdfopt hexseed:(label + seed) TLS1-PRF
        [Fact]
        public void The_prf_gives_the_openssl_answer_for_an_even_secret()
        {
            byte[] output = Tls11Prf.Derive(Enumerable.Repeat((byte)0x0b, 48).ToArray(), "test label", Enumerable.Repeat((byte)0xa0, 32).ToArray(), 104);
            Assert.Equal(
                "439db4bbf37e4451e0747e4b8d408c2dce93f2b7733a5a1fe4342c952017f214fe47bae578b623848c41d46478aee230f2068c5718dd977dfbaa86629f3c85e821514b7b8d39216beabbd3559dad86c6909d30543548" + "29b4122b30d2126eef34fb4199916723" + "8136",
                Hex.Encode(output));
        }

        [Fact]
        public void The_prf_shares_the_middle_byte_of_an_odd_secret()
        {
            byte[] output = Tls11Prf.Derive(Enumerable.Repeat((byte)0x0c, 47).ToArray(), "test label", Enumerable.Repeat((byte)0xa0, 32).ToArray(), 72);
            Assert.Equal(
                "d7b64eab92628a03f8febc02538015a4739012eb47a06160fa7c37b86a9aef2cbbd4c753a81dc8ae0c633241f3962d2fc3fb7de3d2b21a7666a5fd1c9cec97de6d3c677b3147403c",
                Hex.Encode(output));
        }

        static Tls11RecordCipher Cipher() => new Tls11RecordCipher(new byte[16], new byte[20], new SeededRandom(5));

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(11)]
        [InlineData(12)]
        [InlineData(27)]
        [InlineData(28)]
        [InlineData(1000)]
        public void A_record_opens_to_its_content_and_its_size_matches_the_fields(int size)
        {
            byte[] content = new byte[size];
            byte[] record = Cipher().Seal(Tls11Content.ApplicationData, content);
            Assert.Equal(Tls11RecordCipher.HeaderSize + Tls11RecordCipher.IvSize + Tls11RecordCipher.CipherSize(size), record.Length);
            Assert.True(Open(Cipher(), record, out byte[] opened));
            Assert.Equal(content, opened);
        }

        static bool Open(Tls11RecordCipher cipher, byte[] record, out byte[] content)
        {
            byte[] payload = record.Skip(Tls11RecordCipher.HeaderSize).ToArray();
            return cipher.TryOpen(record[0], (record[1] << 8) | record[2], payload, out content);
        }

        [Theory]
        [InlineData(5)]   // IV
        [InlineData(21)]  // first cipher byte
        [InlineData(60)]  // last cipher byte, which holds the padding
        public void One_flipped_bit_fails_the_record(int offset)
        {
            byte[] record = Cipher().Seal(Tls11Content.ApplicationData, new byte[11]);
            Assert.True(Open(Cipher(), record, out _), "control");
            record[Math.Min(offset, record.Length - 1)] ^= 1;
            Assert.False(Open(Cipher(), record, out _));
        }

        [Fact]
        public void A_replayed_record_fails_because_the_mac_covers_the_count()
        {
            byte[] record = Cipher().Seal(Tls11Content.ApplicationData, new byte[5]);
            Tls11RecordCipher receiver = Cipher();
            Assert.True(Open(receiver, record, out _));
            Assert.False(Open(receiver, record, out _));
        }

        [Fact]
        public void A_record_too_short_for_a_mac_fails_with_no_exception()
        {
            Assert.False(Cipher().TryOpen(Tls11Content.ApplicationData, 0x0302, new byte[16], out _));
            Assert.False(Cipher().TryOpen(Tls11Content.ApplicationData, 0x0302, new byte[32 + 15], out _));
        }

        [Fact]
        public void Md5_sha1_signatures_round_trip_and_a_changed_digest_fails()
        {
            RsaPrivate key = Tls11RsaKeys.ReadPrivate(Keys.Find(KeyIds.ServerTls11Rsa).CopyMaterial());
            RsaPublic pub = PublicOf(Keys.Find(KeyIds.ServerTls11Rsa));
            byte[] digest = Tls11Prf.Md5Sha1(Encoding.UTF8.GetBytes("message"));
            byte[] signature = Pkcs1.SignMd5Sha1(key, digest);
            Assert.True(Pkcs1.VerifyMd5Sha1(pub, digest, signature));
            digest[0] ^= 1;
            Assert.False(Pkcs1.VerifyMd5Sha1(pub, digest, signature));
        }

        static RsaPublic PublicOf(ITrainingKey key)
        {
            byte[] spki = key.CopyPublic();
            DerReader outer = new DerReader(spki, 0, spki.Length).Read(Der.TagSequence).Inner;
            outer.Read(Der.TagSequence);
            byte[] bits = outer.Read(Der.TagBitString).Value;
            RsaPublic pub = Tls11RsaKeys.TryReadPublic(bits.Skip(1).ToArray(), out string problem);
            Assert.Null(problem);
            return pub;
        }

        static (Tls11Engine client, Tls11Engine server) Duel(Tls11CipherSuite suite, bool sentinel = false, ITamperHook tamper = null)
        {
            Tls11Engine client = Client(suite, Encoding.UTF8.GetBytes("ping"), tamper);
            Tls11Engine server = Server(suite, sentinel, tamper);
            EngineDuel.Run(client, server);
            return (client, server);
        }

        public static TheoryData<string> Suites => new TheoryData<string> { "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" };

        [Theory]
        [MemberData(nameof(Suites))]
        public void Client_and_server_finish_and_close_cleanly(string name)
        {
            (Tls11Engine client, Tls11Engine server) = Duel(Tls11CipherSuite.Find(name));
            Assert.True(client.Opened);
            Assert.True(server.Opened);
            Assert.Equal(EngineStatus.Closed, client.Status);
            Assert.Equal(EngineStatus.Closed, server.Status);
            Assert.Equal(server.KeyLog, client.KeyLog);
        }

        [Fact]
        public void A_tls11_client_has_nothing_to_check_in_the_downgrade_sentinel()
        {
            (Tls11Engine client, _) = Duel(Tls11CipherSuite.RsaAes128CbcSha, sentinel: true);
            Assert.True(client.Opened);
            Assert.Equal(EngineStatus.Closed, client.Status);
        }

        [Fact]
        public void The_server_writes_downgrd_in_its_random_on_request()
        {
            byte[] random = new byte[32];
            Tls11Messages.WriteDowngradeTail(random);
            Assert.Equal("444f574e47524400", Hex.Encode(random.Skip(24).ToArray()));
        }

        [Fact]
        public void A_flipped_finished_at_the_plain_point_fails_the_finished_compare()
        {
            TamperPlan plan = new TamperPlan { Point = TamperPoint.Plain, Message = Tls11Messages.FinishedName, Offset = 6 };
            Tls11Engine client = Client(Tls11CipherSuite.RsaAes128CbcSha, null, plan);
            Tls11Engine server = Server(Tls11CipherSuite.RsaAes128CbcSha);
            server.Start();
            byte[] toServer = client.Start().Wire;
            EngineOutput fromServer = null;
            while (toServer.Length > 0 && server.Status != EngineStatus.Failed)
            {
                fromServer = server.Feed(toServer, 0, toServer.Length);
                toServer = fromServer.Wire.Length == 0 ? new byte[0] : client.Feed(fromServer.Wire, 0, fromServer.Wire.Length).Wire;
            }
            Assert.Equal(EngineStatus.Failed, server.Status);
            Assert.Equal(Tls11Codes.FinishedMismatch, fromServer.Error.Code);
            Assert.Equal(Tls11Checks.FinishedCompare, fromServer.Error.CheckName);
        }

        static byte[] RsaSpki(byte[] modulus, byte[] exponent)
        {
            byte[] algorithm = Der.Sequence(Der.Oid("2a864886f70d010101"), Der.Tlv(5, new byte[0]));
            return Der.Sequence(algorithm, Der.BitString(Der.Sequence(Der.Integer(modulus), Der.Integer(exponent))));
        }

        static Tls11Engine ServerWithLeaf(byte[] spki)
        {
            Tls11Options o = Options("server", Tls11CipherSuite.RsaAes128CbcSha, 22);
            Tls11Training.UseTrainingServerKey(o, Keys);
            o.Chain = new[] { new TrainingCa(Keys).IssueServerCertificate(TrainingPki.ServerName, spki, TrainingCa.DefaultNotBefore, TrainingCa.DefaultNotAfter) };
            return Tls11Engine.CreateServer(o);
        }

        static NetSecError ErrorAfterDuel(Tls11Engine client, Tls11Engine server)
        {
            Tls11Engine c = client;
            server.Start();
            byte[] toServer = c.Start().Wire;
            EngineOutput last = null;
            while (toServer.Length > 0)
            {
                byte[] toClient = server.Feed(toServer, 0, toServer.Length).Wire;
                if (toClient.Length == 0) break;
                last = c.Feed(toClient, 0, toClient.Length);
                toServer = last.Wire;
            }
            return last?.Error;
        }

        public static TheoryData<string, string> BadKeys => new TheoryData<string, string>
        {
            // A modulus that is too short for the premaster, one that is even, an exponent that is even.
            { "c1" + new string('1', 60), "010001" },
            { "c1" + new string('1', 508) + "10", "010001" },
            { "c1" + new string('1', 510), "0100" },
        };

        [Theory]
        [MemberData(nameof(BadKeys))]
        public void A_bad_rsa_key_from_the_wire_gets_a_named_error(string modulus, string exponent)
        {
            NetSecError error = ErrorAfterDuel(Client(Tls11CipherSuite.RsaAes128CbcSha), ServerWithLeaf(RsaSpki(Hex.Decode(modulus), Hex.Decode(exponent))));
            Assert.NotNull(error);
            Assert.Equal(Tls11Codes.ServerKeyUnusable, error.Code);
        }

        [Fact]
        public void An_ed25519_leaf_gets_a_named_error()
        {
            byte[] spki = TrainingCa.Ed25519Spki(Keys.Find(KeyIds.ServerTlsEd25519).CopyPublic());
            NetSecError error = ErrorAfterDuel(Client(Tls11CipherSuite.RsaAes128CbcSha), ServerWithLeaf(spki));
            Assert.Equal(Tls11Codes.ServerKeyUnusable, error.Code);
        }

        [Fact]
        public void An_expired_chain_stops_the_client_with_the_chain_code()
        {
            NetSecError error = ErrorAfterDuel(Client(Tls11CipherSuite.RsaAes128CbcSha, now: new DateTime(2060, 1, 1, 0, 0, 0, DateTimeKind.Utc)), Server(Tls11CipherSuite.RsaAes128CbcSha));
            Assert.Equal(ChainCheck.Validity, error.Code);
        }

        [Fact]
        public void Alert_70_reaches_a_named_code_and_the_alert_number()
        {
            Tls11Engine client = Client(Tls11CipherSuite.RsaAes128CbcSha);
            client.Start();
            byte[] alert = Hex.Decode("150303000202" + "46");
            EngineOutput output = client.Feed(alert, 0, alert.Length);
            Assert.Equal(EngineStatus.Failed, output.Status);
            Assert.Equal(Tls11Codes.AlertProtocolVersion, output.Error.Code);
            Assert.Equal(Tls11Checks.ProtocolVersionAlert, output.Error.CheckName);
            Assert.Equal(70, client.AlertReceived);
        }

        [Fact]
        public void A_huge_record_length_fails_now_and_does_not_wait()
        {
            Tls11Engine client = Client(Tls11CipherSuite.RsaAes128CbcSha);
            client.Start();
            byte[] header = Hex.Decode("1603027fff");
            EngineOutput output = client.Feed(header, 0, header.Length);
            Assert.Equal(Tls11Codes.RecordOverflow, output.Error.Code);
        }

        [Fact]
        public void A_silent_peer_ends_in_the_pump_deadline()
        {
            MemoryLink[] pair = MemoryLink.Pair();
            IFuture<PumpResult> run = new EnginePump(Client(Tls11CipherSuite.RsaAes128CbcSha), pair[0], new NullSink(), new FreeRunGate(), null, 200).Run();
            Assert.True(run.Wait(10000), "the pump did not end");
            Assert.Equal(ErrorCodes.LinkDeadline, run.Result.Error.Code);
        }

        // ---------------------------------------------------------------- lesson 7

        static (LabResult result, TraceEvent[] events) RunLab(AttackDefinition attack = null)
        {
            ListSink sink = new ListSink();
            LabContext c = new LabContext { SessionId = "s7", TraceId = "s7", Seed = 7, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(0), Random = new SeededRandom(7), Attack = attack };
            IFuture<LabResult> future = LabCatalog.Find(7).Run(c);
            Assert.True(future.Wait(60000), "the lab did not finish in 60 s");
            return (future.Result, sink.Events);
        }

        [Fact]
        public void Lesson_7_control_sends_the_named_messages_in_order()
        {
            (LabResult result, TraceEvent[] events) = RunLab();
            Assert.True(result.Completed, result.FailedCode + " " + result.FailedCheck);
            string[] Sent(string actor) => events.Where(e => e.Type == "wire.sent" && e.Actor == actor).Select(e => e.Message).ToArray();
            Assert.Equal(new[] { "ClientHello", "ClientKeyExchange", "ChangeCipherSpec", "Finished", "ApplicationData", "Alert" }, Sent("client"));
            Assert.Equal(new[] { "ServerHello", "Certificate", "ServerHelloDone", "ChangeCipherSpec", "Finished", "ApplicationData" }, Sent("server"));
            Assert.Contains(events, e => e.Type == "check.result" && e.Message == "record HMAC" && e.Check.Passed);
            Assert.Contains(events, e => e.Type == "check.result" && e.Message == "certificate chain" && e.Check.Passed);
            Assert.Contains(events, e => e.Type == "keys.installed" && e.Message == "TLS_RSA_WITH_AES_128_CBC_SHA");
        }

        [Fact]
        public void Each_field_of_a_clear_message_points_inside_its_wire_bytes_and_cipher_is_hidden()
        {
            (_, TraceEvent[] events) = RunLab();
            foreach (TraceEvent e in events.Where(e => e.Type == "wire.sent"))
                foreach (TraceField f in e.Fields)
                    Assert.True(f.Offset + f.Length <= e.Wire.Length, e.Message + " " + f.Name);
            TraceEvent data = events.First(e => e.Type == "wire.sent" && e.Message == "ApplicationData");
            Assert.False(data.Fields.Single(f => f.Name == "cipher").VisibleToWire);
            Assert.True(data.Fields.Single(f => f.Name == "iv").VisibleToWire);
            Assert.Equal(data.Wire.Length, data.Fields.Sum(f => f.Length));
        }

        [Fact]
        public void Lesson_7_engine_events_repeat_on_a_same_seed_rerun()
        {
            static string Lines(TraceEvent[] events) => string.Join("\n", events.Where(e => !e.StreamId.EndsWith("/wire")).OrderBy(e => e.StreamId, StringComparer.Ordinal).ThenBy(e => e.StreamSeq).Select(TraceJson.ToLine));
            Assert.Equal(Lines(RunLab().events), Lines(RunLab().events));
        }

        [Fact]
        public void Attack_rows_of_lesson_7_give_their_code_and_check_beside_the_control()
        {
            Assert.True(RunLab().result.Completed);
            AttackDefinition[] rows = AttackCatalog.All.Where(a => a.Lesson == 7).ToArray();
            Assert.NotEmpty(rows);
            foreach (AttackDefinition row in rows)
            {
                (LabResult result, _) = RunLab(row);
                Assert.Equal(row.ExpectCode, result.FailedCode);
                Assert.Equal(row.ExpectCheck, result.FailedCheck);
            }
        }
    }
}
