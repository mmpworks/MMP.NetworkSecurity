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

        static Tls11Engine Client(Tls11CipherSuite suite, ITamperHook tamper = null, DateTime? now = null)
        {
            Tls11Options o = Options("client", suite, 11);
            Tls11Training.TrustTrainingRoot(o, Keys, now ?? Now);
            o.Tamper = tamper;
            return Tls11Engine.CreateClient(o);
        }

        static Tls11Engine Server(Tls11CipherSuite suite, bool sentinel = false, ITamperHook tamper = null)
        {
            Tls11Options o = Options("server", suite, 22);
            Tls11Training.UseTrainingServerKey(o, Keys);
            o.WriteDowngradeTail = sentinel;
            o.Tamper = tamper;
            return Tls11Engine.CreateServer(o);
        }

        /// <summary>The client sends one line, the server sends it back, and the client closes. No socket: bytes pass in a plain loop.</summary>
        static void EchoRun(Tls11Engine client, Tls11Engine server)
        {
            server.Start();
            client.Command(new EngineCommand(EngineCommandKind.Send, 0, Encoding.UTF8.GetBytes("ping"), null));
            byte[] toServer = client.Start().Wire;
            while (toServer.Length > 0)
            {
                EngineOutput fromServer = server.Feed(toServer, 0, toServer.Length);
                byte[] toClient = fromServer.Wire;
                foreach (DeliveredChunk chunk in fromServer.App)
                    toClient = toClient.Concat(server.Command(new EngineCommand(EngineCommandKind.Send, 0, chunk.Bytes, null)).Wire).ToArray();
                if (toClient.Length == 0) return;
                EngineOutput fromClient = client.Feed(toClient, 0, toClient.Length);
                toServer = fromClient.Wire;
                if (fromClient.App.Length > 0) toServer = toServer.Concat(client.Command(EngineCommand.Close).Wire).ToArray();
            }
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
            Tls11Engine client = Client(suite, tamper);
            Tls11Engine server = Server(suite, sentinel, tamper);
            EchoRun(client, server);
            return (client, server);
        }

        public static TheoryData<string> Suites => new TheoryData<string> { "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" };

        [Theory]
        [MemberData(nameof(Suites))]
        public void Client_and_server_finish_and_close_cleanly(string name)
        {
            (Tls11Engine client, Tls11Engine server) = Duel(Tls11CipherSuite.Find(name));
            Assert.True(client.ReachedOpen);
            Assert.True(server.ReachedOpen);
            Assert.Equal(EngineStatus.Closed, client.Status);
            Assert.Equal(EngineStatus.Closed, server.Status);
            Assert.Equal(server.KeyLogLines, client.KeyLogLines);
        }

        [Fact]
        public void A_tls11_client_has_nothing_to_check_in_the_downgrade_sentinel()
        {
            (Tls11Engine client, _) = Duel(Tls11CipherSuite.RsaAes128CbcSha, sentinel: true);
            Assert.True(client.ReachedOpen);
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
            Tls11Engine client = Client(Tls11CipherSuite.RsaAes128CbcSha, plan);
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
            // A modulus that is too short for the premaster, one of 512 and one of 1024 bits, one that is even, an exponent that is even.
            { "c1" + new string('1', 60), "010001" },
            { "c1" + new string('1', 126), "010001" },
            { "c1" + new string('1', 254), "010001" },
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

        // ---------------------------------------------------------------- review findings, PR 49

        const string OpenSsl = @"C:\Program Files\Git\mingw64\bin\openssl.exe";

        [Theory]
        [InlineData("TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA")]
        [InlineData("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE-RSA-AES128-SHA")]
        public void OpenSsl_default_client_verifies_the_glass_server_and_sends_data(string suite, string openSslName)
        {
            string dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "tls11-sclient-" + Guid.NewGuid().ToString("N"));
            TrainingPki.Export(dir);
            ProbeListener listener = Probe.Listen(new ProbeRequest { Protocol = WireProtocol.Tls11, Suite = suite, Seed = 9 });
            using (System.Diagnostics.Process client = new System.Diagnostics.Process())
            {
                client.StartInfo.FileName = OpenSsl;
                client.StartInfo.Arguments = "s_client -tls1_1 -cipher " + openSslName + ":@SECLEVEL=0 -CAfile \"" + System.IO.Path.Combine(dir, "root.pem") + "\" -verify_return_error -verify_hostname localhost -connect 127.0.0.1:" + listener.Port;
                client.StartInfo.UseShellExecute = false;
                client.StartInfo.RedirectStandardInput = true;
                client.StartInfo.RedirectStandardOutput = true;
                client.StartInfo.RedirectStandardError = true;
                StringBuilder lines = new StringBuilder();
                client.OutputDataReceived += (s, e) => { lock (lines) lines.AppendLine(e.Data); };
                client.ErrorDataReceived += (s, e) => { };
                client.Start();
                client.BeginOutputReadLine();
                client.BeginErrorReadLine();
                client.StandardInput.Write("hello\n");
                client.StandardInput.Flush();
                Assert.True(listener.Result.Wait(30000), "the glass server did not finish in 30 s");
                client.StandardInput.Close();
                Assert.True(client.WaitForExit(15000), "s_client did not exit in 15 s");
                client.WaitForExit();
                string text;
                lock (lines) text = lines.ToString();
                ProbeResult result = listener.Result.Result;
                Assert.True(result.Completed, result.Code + " " + result.CheckName);
                Assert.Equal("hello\n", Encoding.UTF8.GetString(result.Received));
                Assert.Contains("Protocol  : TLSv1.1", text);
                Assert.Contains("Cipher    : " + openSslName, text);
                Assert.Contains("Verify return code: 0 (ok)", text);
            }
        }

        [Fact]
        public void A_hello_with_no_renegotiation_signal_gets_no_extension_back()
        {
            byte[] random = new byte[32];
            byte[] bare = Tls11Messages.BuildServerHello(random, Tls11CipherSuite.RsaAes128CbcSha, false);
            byte[] answered = Tls11Messages.BuildServerHello(random, Tls11CipherSuite.RsaAes128CbcSha, true);
            Assert.Equal("0005ff01000100", Hex.Encode(answered.Skip(bare.Length).ToArray()));
            byte[] hello = Tls11Messages.BuildClientHello(random, Tls11CipherSuite.RsaAes128CbcSha);
            Assert.True(Tls11Messages.ReadClientHello(new ByteReader(hello, 0, hello.Length, true)).SignalsSecureRenegotiation);
        }

        /// <summary>Runs the handshake and hands the first server output after the client's flight.</summary>
        static EngineOutput ClientFlightAtServer(ITamperHook clientTamper)
        {
            Tls11Engine client = Client(Tls11CipherSuite.RsaAes128CbcSha, clientTamper);
            Tls11Engine server = Server(Tls11CipherSuite.RsaAes128CbcSha);
            server.Start();
            client.Command(new EngineCommand(EngineCommandKind.Send, 0, Encoding.UTF8.GetBytes("ping"), null));
            byte[] hello = client.Start().Wire;
            byte[] flight = server.Feed(hello, 0, hello.Length).Wire;
            EngineOutput fromClient = client.Feed(flight, 0, flight.Length);
            EngineOutput fromServer = server.Feed(fromClient.Wire, 0, fromClient.Wire.Length);
            if (server.Status == EngineStatus.Failed) return fromServer;
            EngineOutput data = client.Feed(fromServer.Wire, 0, fromServer.Wire.Length);
            return server.Feed(data.Wire, 0, data.Wire.Length);
        }

        [Fact]
        public void A_sealed_empty_record_delivers_nothing_and_the_session_stays_open()
        {
            EngineOutput control = ClientFlightAtServer(null);
            Assert.Single(control.App);
            EngineOutput output = ClientFlightAtServer(new TamperPlan { Point = TamperPoint.Plain, Message = Tls11Messages.ApplicationDataName, Replacement = new byte[0] });
            Assert.Empty(output.App);
            Assert.Equal(EngineStatus.Open, output.Status);
        }

        [Fact]
        public void A_sealed_record_above_the_limit_fails_by_name()
        {
            EngineOutput output = ClientFlightAtServer(new TamperPlan { Point = TamperPoint.Plain, Message = Tls11Messages.ApplicationDataName, Replacement = new byte[17000] });
            Assert.Equal(Tls11Codes.RecordOverflow, output.Error.Code);
        }

        [Theory]
        [InlineData(new byte[] { 2 })]
        [InlineData(new byte[] { 1, 1 })]
        public void A_bad_change_cipher_spec_body_fails_by_name(byte[] body)
        {
            EngineOutput output = ClientFlightAtServer(new TamperPlan { Point = TamperPoint.Plain, Message = Tls11Messages.ChangeCipherSpecName, Replacement = body });
            Assert.Equal(Tls11Codes.CcsBody, output.Error.Code);
        }

        [Fact]
        public void A_client_refuses_a_compression_it_did_not_offer()
        {
            // Handshake header 4, version 2, random 32, session id length 1, suite 2, then compression.
            ITamperHook plan = new TamperPlan { Point = TamperPoint.Plain, Message = Tls11Messages.ServerHelloName, Offset = 41 };
            NetSecError error = ErrorAfterDuel(Client(Tls11CipherSuite.RsaAes128CbcSha), Server(Tls11CipherSuite.RsaAes128CbcSha, false, plan));
            Assert.Equal(Tls11Codes.CompressionRefused, error.Code);
        }

        [Fact]
        public void A_server_refuses_a_hello_with_no_null_compression()
        {
            // Handshake header 4, version 2, random 32, session id length 1, suites length 2, suites 4, compression length 1, then compression.
            ITamperHook plan = new TamperPlan { Point = TamperPoint.Plain, Message = Tls11Messages.ClientHelloName, Offset = 46 };
            Tls11Engine client = Client(Tls11CipherSuite.RsaAes128CbcSha, plan);
            Tls11Engine server = Server(Tls11CipherSuite.RsaAes128CbcSha);
            server.Start();
            byte[] hello = client.Start().Wire;
            Assert.Equal(Tls11Codes.CompressionRefused, server.Feed(hello, 0, hello.Length).Error.Code);
        }

        [Fact]
        public void Half_a_handshake_message_before_the_change_cipher_spec_fails_now()
        {
            Tls11Engine client = Client(Tls11CipherSuite.RsaAes128CbcSha);
            Tls11Engine server = Server(Tls11CipherSuite.RsaAes128CbcSha);
            server.Start();
            byte[] hello = client.Start().Wire;
            byte[] flight = server.Feed(hello, 0, hello.Length).Wire;
            byte[] answer = client.Feed(flight, 0, flight.Length).Wire;
            int keyExchangeRecord = 5 + ((answer[3] << 8) | answer[4]);
            server.Feed(answer, 0, keyExchangeRecord);
            byte[] half = Hex.Decode("16030200021400");
            Assert.Null(server.Feed(half, 0, half.Length).Error);
            byte[] ccs = Hex.Decode("140302000101");
            Assert.Equal(ErrorCodes.UnexpectedMessage, server.Feed(ccs, 0, ccs.Length).Error.Code);
        }

        [Fact]
        public void A_failure_sends_one_fatal_alert_and_a_received_alert_sends_none()
        {
            Tls11Engine client = Client(Tls11CipherSuite.RsaAes128CbcSha);
            client.Start();
            byte[] huge = Hex.Decode("1603027fff");
            Assert.Equal("15030200020216", Hex.Encode(client.Feed(huge, 0, huge.Length).Wire));

            Tls11Engine second = Client(Tls11CipherSuite.RsaAes128CbcSha);
            second.Start();
            byte[] alert = Hex.Decode("15030300020246");
            Assert.Empty(second.Feed(alert, 0, alert.Length).Wire);
        }

        sealed class WriteFailsLink : IByteLink
        {
            readonly byte[] _toRead;
            int _writes;
            public WriteFailsLink(byte[] toRead) { _toRead = toRead; }
            public IFuture<int> Read(byte[] b, int off, int n) { Buffer.BlockCopy(_toRead, 0, b, off, _toRead.Length); return Futures.FromResult(_toRead.Length); }
            public IFuture Write(byte[] b, int off, int n) => ++_writes == 1 ? Futures.Completed : Futures.FromException(new InvalidOperationException("the peer is gone"));
            public void Close() { }
        }

        [Fact]
        public void A_lost_alert_write_leaves_the_engines_named_failure()
        {
            IFuture<PumpResult> run = new EnginePump(Client(Tls11CipherSuite.RsaAes128CbcSha), new WriteFailsLink(Hex.Decode("1603027fff")), new NullSink(), new FreeRunGate(), null, 5000).Run();
            Assert.True(run.Wait(10000), "the pump did not end");
            Assert.Equal(Tls11Codes.RecordOverflow, run.Result.Error.Code);
        }

        [Fact]
        public void A_reader_that_stops_reading_gets_a_named_error_past_the_queue_cap()
        {
            MemoryLink[] links = MemoryLink.Pair();
            GlassTransportFactory factory = new GlassTransportFactory(Keys);
            ISecureChannel server = factory.Open(new TransportRequest { Protocol = WireProtocol.Tls11, Role = EngineRole.Server, Link = links[1], Random = new SeededRandom(2), Sink = new NullSink(), Gate = new FreeRunGate() }).Result;
            ISecureChannel client = factory.Open(new TransportRequest { Protocol = WireProtocol.Tls11, Role = EngineRole.Client, Link = links[0], Random = new SeededRandom(1), Sink = new NullSink(), Gate = new FreeRunGate() }).Result;
            byte[] chunk = new byte[1 << 20];
            NetSecException caught = null;
            for (int i = 0; i < 40 && caught == null; i++)
            {
                IFuture sent = client.Send(0, chunk);
                Assert.True(sent.Wait(60000), "a send did not drain in 60 s");
                System.Threading.Thread.Sleep(i > 16 ? 200 : 0);
                if (i > 16) caught = Receive(server);
            }
            Assert.NotNull(caught);
            Assert.Equal(ErrorCodes.ChannelBufferFull, caught.Error.Code);
        }

        static NetSecException Receive(ISecureChannel channel)
        {
            IFuture<AppChunk> received = channel.Receive();
            if (!received.Wait(5000) || !received.IsFaulted) return null;
            return received.Exception as NetSecException ?? received.Exception.InnerException as NetSecException;
        }

        [Fact]
        public void A_silent_peer_ends_in_the_pump_deadline()
        {
            MemoryLink[] pair = MemoryLink.Pair();
            IFuture<PumpResult> run = new EnginePump(Client(Tls11CipherSuite.RsaAes128CbcSha), pair[0], new NullSink(), new FreeRunGate(), null, 200).Run();
            Assert.True(run.Wait(10000), "the pump did not end");
            Assert.Equal(ErrorCodes.LinkDeadline, run.Result.Error.Code);
        }

        [Fact]
        public void The_glass_factory_opens_tls11_under_the_ce_profile_and_carries_bytes()
        {
            MemoryLink[] links = MemoryLink.Pair();
            GlassTransportFactory factory = new GlassTransportFactory(Keys);
            IFuture<ISecureChannel> server = factory.Open(new TransportRequest { Protocol = WireProtocol.Tls11, Role = EngineRole.Server, Tls11Suite = Tls11Suite.RsaAes128CbcSha, Link = links[1], Random = new SeededRandom(2), Sink = new NullSink(), Gate = new FreeRunGate() });
            IFuture<ISecureChannel> client = factory.Open(new TransportRequest { Protocol = WireProtocol.Tls11, Role = EngineRole.Client, Tls11Suite = Tls11Suite.RsaAes128CbcSha, Link = links[0], Random = new SeededRandom(1), Sink = new NullSink(), Gate = new FreeRunGate(), Profile = NetSec.Bridge.DeviceProfile.Ce });
            client.Result.Send(0, Encoding.UTF8.GetBytes("ping"));
            IFuture<AppChunk> received = server.Result.Receive();
            Assert.True(received.Wait(20000), "the server received nothing in 20 s");
            Assert.Equal("ping", Encoding.UTF8.GetString(received.Result.Bytes));
            Assert.Equal("TLSv1.1", client.Result.Info.Protocol);
            Assert.Equal("TLS_RSA_WITH_AES_128_CBC_SHA", client.Result.Info.Suite);
            client.Result.Close();
        }

        // ---------------------------------------------------------------- lesson 7

        static (LabResult result, TraceEvent[] events) RunLab(AttackDefinition attack = null)
        {
            ListSink sink = new ListSink();
            LabContext c = new LabContext { SessionId = "s7", TraceId = "s7", Seed = 7, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(0), Random = new SeededRandom(7), Attack = attack, DeadlineMs = 20000 };
            IFuture<LabResult> future = LabCatalog.Find(7).Run(c);
            Assert.True(future.Wait(60000), "the lab did not finish in 60 s");
            return (future.Result, sink.Events);
        }

        [Fact]
        public void Lesson_7_control_sends_the_named_messages_in_order()
        {
            (LabResult result, TraceEvent[] events) = RunLab();
            Assert.True(result.Completed, result.FailedCode + " " + result.FailedCheck);
            string[] Sent(string actor) => events.Where(e => e.Type == "wire.sent" && e.Actor == actor && e.StreamId.Contains("/tls11")).Select(e => e.Message).ToArray();
            Assert.Equal(new[] { "ClientHello", "ClientKeyExchange", "ChangeCipherSpec", "Finished", "ApplicationData", "Alert" }, Sent("client"));
            Assert.Equal(new[] { "ServerHello", "Certificate", "ServerHelloDone", "ChangeCipherSpec", "Finished", "ApplicationData" }, Sent("server"));
            Assert.Contains(events, e => e.Type == "check.result" && e.Message == "record HMAC" && e.Check.Passed);
            Assert.Contains(events, e => e.Type == "check.result" && e.Message == "certificate chain" && e.Check.Passed);
            Assert.Contains(events, e => e.Type == "keys.installed" && e.Message == "TLS_RSA_WITH_AES_128_CBC_SHA");
            Assert.Contains(events, e => e.Type == "wire.sent" && e.StreamId.Contains("/tls13") && e.Message == "ClientHello");
        }

        [Fact]
        public void The_downgrade_attack_leaves_downgrd_on_the_wire_and_the_tls13_client_names_it()
        {
            (LabResult result, TraceEvent[] events) = RunLab(AttackCatalog.All.Single(a => a.AttackId == "L7-downgrade"));
            Assert.Equal("TLS13_DOWNGRADE_SENTINEL", result.FailedCode);
            Assert.Equal("downgrade sentinel", result.FailedCheck);
            TraceEvent hello = events.Single(e => e.Type == "wire.sent" && e.Actor == "server" && e.Message == "ServerHello");
            Assert.Equal("444f574e47524400", Hex.Encode(hello.Wire.Skip(5 + 4 + 2 + 24).Take(8).ToArray()));
            Assert.Contains(events, e => e.Type == "check.result" && e.Actor == "client" && e.StreamId.Contains("/tls13") && !e.Check.Passed && e.Message == "downgrade sentinel");
        }

        [Fact]
        public void The_modern_server_gives_the_old_client_alert_70()
        {
            (LabResult result, TraceEvent[] events) = RunLab(AttackCatalog.All.Single(a => a.AttackId == "L7-modern-server"));
            Assert.Equal(Tls11Codes.AlertProtocolVersion, result.FailedCode);
            Assert.Contains(events, e => e.Type == "check.result" && e.Actor == "client" && !e.Check.Passed && e.Message == "protocol_version alert");
        }

        [Fact]
        public void Each_field_of_a_clear_message_points_inside_its_wire_bytes_and_cipher_is_hidden()
        {
            (_, TraceEvent[] events) = RunLab();
            foreach (TraceEvent e in events.Where(e => e.Type == "wire.sent"))
                foreach (TraceField f in e.Fields)
                    Assert.True(f.Offset + f.Length <= e.Wire.Length, e.Message + " " + f.Name);
            // The race runs both versions, so which one sends first changes between runs. This test reads the TLS 1.1 record.
            TraceEvent data = events.First(e => e.Type == "wire.sent" && e.Message == "ApplicationData" && e.StreamId.Contains("/tls11"));
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
