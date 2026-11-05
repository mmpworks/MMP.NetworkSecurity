using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Labs;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Platform;
using NetSec.Ssh;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>The SSH engine with no referee, on both builds. docs/lesson-ssh-names.md is the list the names come from. A8 is the outside judge.</summary>
    public class SshTests
    {
        sealed class Run
        {
            public LabResult Result;
            public TraceEvent[] Events;
            public IEnumerable<TraceEvent> Of(string type) => Events.Where(e => e.Type == type);
            public string[] Sent(string actor) => Of("wire.sent").Where(e => e.Actor == actor).Select(e => e.Message).ToArray();
            public string[] PassedChecks => Of("check.result").Where(e => e.Check.Passed).Select(e => e.Message).Distinct().ToArray();
            public TraceEvent FirstFailure => Of("check.result").First(e => !e.Check.Passed);
        }

        static Run Go(AttackDefinition attack = null, int seed = 7)
        {
            ListSink sink = new ListSink();
            LabContext c = new LabContext { SessionId = "s8", TraceId = "s8", Seed = seed, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(1), Random = new SeededRandom(seed), Attack = attack };
            IFuture<LabResult> future = LabCatalog.Find(8).Run(c);
            Assert.True(future.Wait(120000), "the lab did not finish in 120 s");
            return new Run { Result = future.Result, Events = sink.Events };
        }

        static AttackDefinition Attack(string id) => AttackCatalog.All.Single(a => a.AttackId == id);

        static byte[] Hash(Func<IHash> h, byte[] input)
        {
            IHash hash = h();
            hash.Update(input, 0, input.Length);
            return hash.Finish();
        }

        static byte[] Filled(int size, byte first, byte rest)
        {
            byte[] bytes = Enumerable.Repeat(rest, size).ToArray();
            bytes[0] = first;
            return bytes;
        }

        // ---------------------------------------------------------------- mpint: Jared's handoff 1

        [Theory]
        [InlineData("00000000", "00000000")]              // zero is an empty mpint
        [InlineData("007f", "000000017f")]                // a leading zero goes
        [InlineData("000080", "000000020080")]            // a leading zero goes, and the top bit puts one back
        [InlineData("80", "000000020080")]                // RFC 4251 section 5 example shape
        public void An_mpint_strips_zeros_and_guards_the_top_bit(string value, string expected)
        {
            Assert.Equal(expected, Hex.Encode(new ByteWriter().Mpint(Hex.Decode(value)).ToArray()));
        }

        [Fact]
        public void The_rfc_4251_mpint_examples_hold()
        {
            Assert.Equal("00000008" + "09a378f9b2e332a7", Hex.Encode(new ByteWriter().Mpint(Hex.Decode("09a378f9b2e332a7")).ToArray()));
            Assert.Equal("00000002" + "0080", Hex.Encode(new ByteWriter().Mpint(Hex.Decode("80")).ToArray()));
            Assert.Equal("00000000", Hex.Encode(new ByteWriter().Mpint(new byte[0]).ToArray()));
        }

        /// <summary>DhGroup14 returns 256 bytes. The hash takes e, f and K as mpints, so a value with a leading zero and a value with its top bit set each take their own form.</summary>
        [Theory]
        [InlineData((byte)0x00, (byte)0x7f, 255)]        // leading zero stripped
        [InlineData((byte)0x80, (byte)0x7f, 257)]        // top bit set: a 00 added
        public void The_group14_exchange_hash_takes_each_value_as_an_mpint(byte first, byte second, int expectedBodySize)
        {
            byte[] value = Filled(256, first, second);
            byte[] one = Encoding.UTF8.GetBytes("v");
            byte[] h = SshExchange.Group14Hash(Hashes.Sha1, one, one, one, one, one, value, value, value);

            ByteWriter manual = new ByteWriter();
            for (int i = 0; i < 5; i++) manual.U32(1).Put(one);
            byte[] body = first == 0 ? value.Skip(1).ToArray() : new byte[] { 0 }.Concat(value).ToArray();
            Assert.Equal(expectedBodySize, body.Length);
            for (int i = 0; i < 3; i++) manual.U32(body.Length).Put(body);
            Assert.Equal(Hex.Encode(Hash(Hashes.Sha1, manual.ToArray())), Hex.Encode(h));
        }

        [Fact]
        public void The_keys_take_K_as_an_mpint_too()
        {
            byte[] k = Filled(32, 0x00, 0x11), h = Filled(32, 0x22, 0x22);
            SshKeyBlock block = SshExchange.DeriveKeys(Hashes.Sha256, k, h, h, 32);
            byte[] manual = new ByteWriter().U32(31).Put(k.Skip(1).ToArray()).Put(h).U8('C').Put(h).ToArray();
            Assert.Equal(Hex.Encode(Hash(Hashes.Sha256, manual).Take(16).ToArray()), Hex.Encode(block.KeyC2S));
        }

        [Fact]
        public void A_long_key_extends_by_hashing_again()
        {
            byte[] k = Filled(20, 0x11, 0x11), h = Filled(20, 0x22, 0x22);
            SshKeyBlock block = SshExchange.DeriveKeys(Hashes.Sha1, k, h, h, 32);
            byte[] kMp = new ByteWriter().Mpint(k).ToArray();
            byte[] k1 = Hash(Hashes.Sha1, new ByteWriter().Put(kMp).Put(h).U8('E').Put(h).ToArray());
            byte[] k2 = Hash(Hashes.Sha1, new ByteWriter().Put(kMp).Put(h).Put(k1).ToArray());
            Assert.Equal(Hex.Encode(k1.Concat(k2).Take(32).ToArray()), Hex.Encode(block.MacC2S));
        }

        // ---------------------------------------------------------------- host key from the wire: Jared's handoffs 2 and 3

        static byte[] RsaBlob(byte[] n, byte[] e) => SshKeyBlob.Rsa(n, e);

        [Fact]
        public void An_even_rsa_modulus_gets_a_named_error_at_the_parser()
        {
            byte[] even = Filled(256, 0xC0, 0x00);
            ParseFailure failure = Assert.Throws<ParseFailure>(() => SshHostKey.Parse(RsaBlob(even, new byte[] { 1, 0, 1 })));
            Assert.Equal(SshCodes.HostKeyBad, failure.Code);
        }

        [Fact]
        public void A_cut_short_host_key_gets_the_same_named_error()
        {
            ParseFailure failure = Assert.Throws<ParseFailure>(() => SshHostKey.Parse(new byte[] { 0, 0, 0, 7, 1 }));
            Assert.Equal(SshCodes.HostKeyBad, failure.Code);
        }

        [Fact]
        public void A_modulus_too_short_for_the_digest_is_one_more_bad_signature()
        {
            byte[] shortOdd = Filled(32, 0xC0, 0xFF);
            SshHostKey key = SshHostKey.Parse(RsaBlob(shortOdd, new byte[] { 3 }));
            byte[] signature = new ByteWriter().Prefixed("ssh-rsa").Prefixed(Filled(32, 0x01, 0x02)).ToArray();
            Assert.False(key.Verify(new byte[20], signature));
        }

        [Fact]
        public void A_good_rsa_and_ed25519_signature_verify_and_one_flipped_byte_fails()
        {
            TrainingKeySource keys = new TrainingKeySource();
            foreach (string id in new[] { KeyIds.SshHostRsa, KeyIds.SshHostEd25519 })
            {
                SshHostSigner signer = new SshHostSigner(keys.Find(id));
                SshHostKey key = SshHostKey.Parse(signer.Blob);
                byte[] message = Encoding.UTF8.GetBytes("exchange hash");
                byte[] signature = signer.Sign(message);
                Assert.True(key.Verify(message, signature));
                signature[signature.Length - 3] ^= 1;
                Assert.False(key.Verify(message, signature));
            }
        }

        // ---------------------------------------------------------------- known_hosts

        [Fact]
        public void Known_hosts_tells_a_match_a_change_and_an_unknown_host_apart()
        {
            byte[] blob = new byte[] { 1, 2, 3 }, other = new byte[] { 4, 5, 6 };
            string text = "# a comment\n" + SshKnownHosts.Line("127.0.0.1", 2222, "ssh-ed25519", blob);
            Assert.Equal(HostKeyMatch.Match, SshKnownHosts.Check(text, "127.0.0.1", 2222, blob));
            Assert.Equal(HostKeyMatch.Changed, SshKnownHosts.Check(text, "127.0.0.1", 2222, other));
            Assert.Equal(HostKeyMatch.Unknown, SshKnownHosts.Check(text, "127.0.0.1", 2223, blob));
            Assert.Equal(HostKeyMatch.Unknown, SshKnownHosts.Check("", "127.0.0.1", 2222, blob));
            Assert.Equal(HostKeyMatch.Unknown, SshKnownHosts.Check(null, "127.0.0.1", 2222, blob));
        }

        // ---------------------------------------------------------------- packets

        [Theory]
        [InlineData("aes128-ctr")]
        [InlineData("aes128-cbc")]
        public void A_sealed_packet_opens_across_any_chunking_and_a_flip_fails_the_mac(string cipher)
        {
            byte[] key = Filled(16, 0x10, 0x11), iv = Filled(16, 0x20, 0x21), mac = Filled(32, 0x30, 0x31);
            SshPacketWriter writer = new SshPacketWriter();
            writer.Arm(SshPacketForm.CipherFor(cipher, key, iv, true), mac, Hashes.Sha256);
            SshPacketReader reader = new SshPacketReader();
            reader.Arm(SshPacketForm.CipherFor(cipher, key, iv, false), mac, Hashes.Sha256, 32);
            SeededRandom random = new SeededRandom(1);

            for (int size = 1; size < 40; size++)
            {
                byte[] payload = Filled(size, (byte)size, 0x55);
                byte[] wire = writer.Seal(payload, random);
                for (int i = 0; i < wire.Length - 1; i++)
                {
                    reader.Append(wire, i, 1);
                    Assert.Null(reader.TryNext());
                }
                reader.Append(wire, wire.Length - 1, 1);
                Assert.Equal(Hex.Encode(payload), Hex.Encode(reader.TryNext().Payload));
                Assert.Null(reader.TryNext());
            }

            byte[] bad = writer.Seal(new byte[40], random);
            bad[bad.Length - 40] ^= 1;
            reader.Append(bad, 0, bad.Length);
            Assert.Equal(SshCodes.PacketMac, Assert.Throws<ParseFailure>(() => reader.TryNext()).Code);
        }

        /// <summary>
        /// aes128-ctr runs one counter through the whole session. Modes.Ctr returns no next counter, so a caller that restarts it on each packet
        /// reuses the keystream, and a sealed-then-opened round trip cannot see that, because both sides reuse it alike. One Modes.Ctr call over
        /// both packets, from the first counter, is the outside check.
        /// </summary>
        [Fact]
        public void Two_ctr_packets_continue_one_counter_and_share_no_keystream()
        {
            byte[] key = Filled(16, 0x10, 0x11), mac = Filled(32, 0x30, 0x31);
            byte[] iv = Filled(16, 0xff, 0xff);   // The counter must carry across all 16 bytes on the way.
            SshPacketWriter writer = new SshPacketWriter();
            writer.Arm(new AesCtrStream(key, iv), mac, Hashes.Sha256);
            SeededRandom random = new SeededRandom(1);
            byte[] payload = Filled(23, 0x55, 0x55);

            byte[] first = writer.Seal(payload, random), second = writer.Seal(payload, random);
            byte[] cipherFirst = first.Take(first.Length - 32).ToArray(), cipherSecond = second.Take(second.Length - 32).ToArray();
            Assert.Equal(32, cipherFirst.Length);
            Assert.NotEqual(Hex.Encode(cipherFirst.Take(5).ToArray()), Hex.Encode(cipherSecond.Take(5).ToArray()));

            byte[] plain = Modes.Ctr(new AesKey(key), iv, cipherFirst.Concat(cipherSecond).ToArray());
            byte[] expectedHeader = new ByteWriter().U32(28).U8(4).ToArray();
            Assert.Equal(Hex.Encode(expectedHeader), Hex.Encode(plain.Take(5).ToArray()));
            Assert.Equal(Hex.Encode(payload), Hex.Encode(plain.Skip(5).Take(23).ToArray()));
            Assert.Equal(Hex.Encode(expectedHeader), Hex.Encode(plain.Skip(32).Take(5).ToArray()));
            Assert.Equal(Hex.Encode(payload), Hex.Encode(plain.Skip(37).Take(23).ToArray()));
        }

        [Fact]
        public void A_length_no_packet_may_hold_gets_a_named_error()
        {
            SshPacketReader reader = new SshPacketReader();
            byte[] wire = new ByteWriter().U32(0x7fffffff).U32(0).ToArray();
            reader.Append(wire, 0, wire.Length);
            Assert.Equal(SshCodes.PacketLength, Assert.Throws<ParseFailure>(() => reader.TryNext()).Code);
        }

        [Theory]
        [InlineData("echo hello", "hello\n", 0)]
        [InlineData("echo", "\n", 0)]
        [InlineData("whoami", "training\n", 0)]
        [InlineData("rm -rf /", "", 127)]
        public void Exec_answers_only_from_the_fixed_table(string command, string output, int exit)
        {
            SshClientOptions options = new SshClientOptions { Algorithms = SshAlgorithms.Modern, Random = new SeededRandom(2), Host = "h", Port = 22, TrustFirstUse = true, User = "training", UserKey = new TrainingKeySource().Find(KeyIds.SshClient) };
            SshEngine client = SshEngine.Client(options, new TraceStream("c", "c", "c", null, "client", new FixedClock(1)), null, "server");
            SshServerOptions serverOptions = new SshServerOptions { Algorithms = SshAlgorithms.Modern, Random = new SeededRandom(1), HostKey = new TrainingKeySource().Find(KeyIds.SshHostEd25519), AuthorizedKeys = new[] { new TrainingKeySource().Find(KeyIds.SshClient).CopyPublic() } };
            SshEngine pair = SshEngine.Server(serverOptions, new TraceStream("s", "s", "s", null, "server", new FixedClock(1)), null, "client");
            EngineDuel.Run(client, pair);
            Assert.Equal(EngineStatus.Open, client.Status);
            EngineOutput request = client.Command(new EngineCommand(EngineCommandKind.Exec, 0, null, command));
            List<byte> got = new List<byte>();
            int? seenExit = null;
            byte[] toServer = request.Wire, toClient = new byte[0];
            while (toServer.Length > 0 || toClient.Length > 0)
            {
                EngineOutput fromServer = pair.Feed(toServer, 0, toServer.Length);
                EngineOutput fromClient = client.Feed(fromServer.Wire, 0, fromServer.Wire.Length);
                foreach (DeliveredChunk chunk in fromClient.App.Where(a => a.Channel == 0)) got.AddRange(chunk.Bytes);
                foreach (TraceEvent e in fromClient.Events.Where(e => e.Type == "ssh.exec.exit")) seenExit = int.Parse(e.Message);
                toServer = fromClient.Wire;
                toClient = new byte[0];
            }
            Assert.Equal(output, Encoding.UTF8.GetString(got.ToArray()));
            Assert.Equal(exit, seenExit);
        }

        // ---------------------------------------------------------------- the lab

        [Fact]
        public void The_lab_completes_both_rounds_with_the_names_the_tour_binds_to()
        {
            Run run = Go();
            Assert.True(run.Result.Completed, run.Result.FailedCode + " " + run.Result.FailedCheck);

            string[] client = run.Sent("client"), server = run.Sent("server");
            foreach (string name in new[] { "VersionLine", "KexInit", "KexEcdhInit", "KexdhInit", "NewKeys", "ServiceRequest", "UserauthQuery", "UserauthSigned", "ChannelOpenSession", "ChannelRequestExec", "ChannelOpenTunnel", "ChannelData", "ChannelEof", "ChannelClose", "Disconnect" })
                Assert.Contains(name, client);
            foreach (string name in new[] { "VersionLine", "KexInit", "KexEcdhReply", "KexdhReply", "NewKeys", "ServiceAccept", "UserauthPkOk", "UserauthSuccess", "ChannelOpenConfirmation", "ChannelSuccess", "ChannelData", "ChannelRequestExitStatus", "ChannelEof", "ChannelClose" })
                Assert.Contains(name, server);
            foreach (string check in new[] { SshChecks.Version, SshChecks.Algorithm, SshChecks.KnownHosts, SshChecks.ZeroSecret, SshChecks.ExchangeSignature, SshChecks.AuthAccepted, SshChecks.AuthSignature, SshChecks.ExecAccepted, SshChecks.TunnelAllowList, SshChecks.TunnelAccepted })
                Assert.Contains(check, run.PassedChecks);
            Assert.All(run.Of("check.result").Where(e => e.Message == SshChecks.TunnelAllowList), e => Assert.Equal("server", e.Actor));
            Assert.All(run.Of("check.result").Where(e => e.Message == SshChecks.TunnelAccepted), e => Assert.Equal("client", e.Actor));

            Assert.Contains(run.Of("ssh.message.received"), e => e.Actor == "client" && e.Message == "ChannelData" && Encoding.UTF8.GetString(e.Plain).Contains("hello"));
            Assert.Equal(2, run.Of("ssh.message.received").Count(e => e.Actor == "client" && e.Message == "ChannelData" && Encoding.UTF8.GetString(e.Plain).Contains("hello")));
            Assert.Contains(run.Of("ssh.message.received"), e => e.Actor == "client" && e.Message == "ChannelData" && Encoding.UTF8.GetString(e.Plain).Contains("ping through the tunnel"));
            Assert.All(new[] { "ssh.weak.exchange-hash", "ssh.weak.host-signature", "ssh.weak.cipher-mode" }, t => Assert.NotEmpty(run.Of(t)));
            Assert.All(run.Of("ssh.weak.cipher-mode"), e => Assert.EndsWith("/ssh-legacy", e.StreamId));
            Assert.Single(run.Of("ssh.hostkey.seen"), e => e.StreamId.EndsWith("/ssh"));
            Assert.StartsWith("SHA256:", run.Of("ssh.hostkey.seen").First().Message);
        }

        [Fact]
        public void Each_side_derives_the_same_keys_and_field_offsets_cover_the_wire()
        {
            Run run = Go();
            foreach (string name in new[] { "ssh.shared.K", "ssh.exchange.H", "ssh.key.c2s", "ssh.mac.s2c" })
            {
                string[] values = run.Of("secret.derived").Where(e => e.StreamId.EndsWith("/ssh")).SelectMany(e => e.Secrets).Where(s => s.Name == name).Select(s => Hex.Encode(s.Bytes)).ToArray();
                Assert.Equal(2, values.Length);
                Assert.Equal(values[0], values[1]);
            }
            foreach (TraceEvent e in run.Of("wire.sent"))
            {
                int at = 0;
                foreach (TraceField f in e.Fields)
                {
                    Assert.True(f.Offset >= at, e.Message + " field " + f.Name + " starts at " + f.Offset + " before " + at);
                    at = f.Offset + f.Length;
                }
                Assert.True(at <= e.Wire.Length, e.Message + " fields end at " + at + " past " + e.Wire.Length);
                if (e.Message != SshNames.VersionLine) Assert.Equal(e.Wire.Length, at);
            }
        }

        [Fact]
        public void The_lab_completes_through_a_step_gate_that_runs()
        {
            ListSink sink = new ListSink();
            StepGate gate = new StepGate();
            gate.Run();
            LabContext c = new LabContext { SessionId = "s8", TraceId = "s8", Seed = 3, Gate = gate, Sink = sink, Clock = new FixedClock(1), Random = new SeededRandom(3) };
            IFuture<LabResult> future = LabCatalog.Find(8).Run(c);
            Assert.True(future.Wait(120000), "the lab did not finish in 120 s");
            Assert.True(future.Result.Completed, future.Result.FailedCode);
        }

        // ---------------------------------------------------------------- the factory and the deadline

        [Theory]
        [InlineData(SshSuite.Modern)]
        [InlineData(SshSuite.Legacy)]
        public void The_factory_gives_an_ssh_channel_that_runs_a_command(SshSuite suite)
        {
            MemoryLink[] links = MemoryLink.Pair();
            GlassTransportFactory factory = new GlassTransportFactory(new TrainingKeySource());
            IFuture<ISecureChannel> server = factory.Open(new TransportRequest { Protocol = WireProtocol.Ssh, Role = EngineRole.Server, Suite = suite, Link = links[1], Random = new SeededRandom(1) });
            IFuture<ISecureChannel> client = factory.Open(new TransportRequest { Protocol = WireProtocol.Ssh, Role = EngineRole.Client, Suite = suite, Link = links[0], Random = new SeededRandom(2), PeerName = "h", PeerPort = 22, TrustFirstUse = true });
            Assert.True(client.Wait(60000), "the client did not open");
            ISshChannel channel = Assert.IsAssignableFrom<ISshChannel>(client.Result);
            Assert.Equal(suite == SshSuite.Legacy ? "diffie-hellman-group14-sha1" : "curve25519-sha256", channel.Info.Group);
            List<byte> output = new List<byte>();
            IFuture run = AsyncProxy.Run(SshScript.Exec(channel, "whoami", output));
            Assert.True(run.Wait(60000), "the command did not finish");
            Assert.Equal("training\n", Encoding.UTF8.GetString(output.ToArray()));
            Assert.True(channel.Close().Wait(60000), "the client did not close");
            Assert.True(server.Wait(60000), "the server did not open");
        }

        [Fact]
        public void The_ce_profile_may_open_ssh_and_a_silent_peer_ends_in_a_named_deadline()
        {
            MemoryLink[] links = MemoryLink.Pair();
            ListSink sink = new ListSink();
            SshClientOptions options = new SshClientOptions { Algorithms = SshAlgorithms.Legacy, Random = new SeededRandom(2), Host = "h", Port = 22, User = "training", UserKey = new TrainingKeySource().Find(KeyIds.SshClient) };
            GlassSshSession session = new GlassSshSession(SshEngine.Client(options, new TraceStream("c", "c", "c", null, "client", new FixedClock(1)), null, "server"), links[0], sink, new FreeRunGate(), null, 200, new FixedClock(1), null);
            session.Run();
            Assert.True(session.Finished.Wait(30000), "the deadline did not end the wait");
            Assert.Equal(NetSec.Errors.ErrorCodes.LinkDeadline, session.Finished.Result.Error.Code);
            Assert.True(session.Opened.IsFaulted);
        }

        [Fact]
        public void The_server_decides_a_refused_tunnel_and_stays_open_to_answer()
        {
            Run run = Go(Attack("L8-refused-tunnel"));
            TraceEvent refusal = run.Of("check.result").Single(e => !e.Check.Passed && e.Message == SshChecks.TunnelAllowList);
            Assert.Equal("server", refusal.Actor);
            Assert.Equal(SshCodes.TunnelRefused, refusal.Check.Code);
            Assert.Contains("bank.lab:1433", refusal.Check.Detail);
            Assert.Contains("ChannelOpenFailure", run.Sent("server"));
            Assert.Equal("client", run.Of("check.result").Single(e => !e.Check.Passed && e.Message == SshChecks.TunnelAccepted).Actor);
        }

        [Fact]
        public void A_silent_peer_ends_in_a_named_deadline_through_a_step_gate_too()
        {
            MemoryLink[] links = MemoryLink.Pair();
            StepGate gate = new StepGate();
            gate.Run();
            SshClientOptions options = new SshClientOptions { Algorithms = SshAlgorithms.Modern, Random = new SeededRandom(2), Host = "h", Port = 22, User = "training", UserKey = new TrainingKeySource().Find(KeyIds.SshClient) };
            GlassSshSession session = new GlassSshSession(SshEngine.Client(options, new TraceStream("c", "c", "c", null, "client", new FixedClock(1)), null, "server"), links[0], new ListSink(), gate, null, 200, new FixedClock(1), null);
            session.Run();
            Assert.True(session.Finished.Wait(30000), "the deadline did not end the wait");
            Assert.Equal(NetSec.Errors.ErrorCodes.LinkDeadline, session.Finished.Result.Error.Code);
        }

        /// <summary>An attack's control is the same lab with no attack: the test above. Each row differs from it in one thing.</summary>
        [Theory]
        [InlineData("L8-change-host-key")]
        [InlineData("L8-flip-exchange-signature")]
        [InlineData("L8-zero-share")]
        [InlineData("L8-flip-packet")]
        [InlineData("L8-wrong-user-key")]
        [InlineData("L8-refused-tunnel")]
        [InlineData("L8-legacy-flip-signature")]
        public void Each_attack_gets_its_named_check(string id)
        {
            AttackDefinition attack = Attack(id);
            Run run = Go(attack);
            Assert.False(run.Result.Completed, id + " completed");
            Assert.Equal(attack.ExpectCode, run.Result.FailedCode);
            Assert.Equal(attack.ExpectCheck, run.Result.FailedCheck);
            Assert.Equal(attack.ExpectCheck, run.FirstFailure.Message);
            Assert.Equal(attack.ExpectCode, run.FirstFailure.Check.Code);
        }

        [Fact]
        public void A_same_seed_rerun_gives_the_same_engine_bytes()
        {
            string[] Lines(Run r) => r.Events.Where(e => !e.StreamId.EndsWith("/wire")).OrderBy(e => e.EventId, StringComparer.Ordinal).Select(TraceJson.ToLine).ToArray();
            Assert.Equal(Lines(Go(null, 21)), Lines(Go(null, 21)));
            Assert.NotEqual(Lines(Go(null, 21)), Lines(Go(null, 22)));
        }

        /// <summary>A pinned digest of every engine event. Both builds run this test, so net10.0 and the CF binaries give the same bytes for a seed.</summary>
        [Fact]
        public void Both_builds_give_the_pinned_trace()
        {
            string[] lines = Go(null, 7).Events.Where(e => !e.StreamId.EndsWith("/wire")).OrderBy(e => e.EventId, StringComparer.Ordinal).Select(TraceJson.ToLine).ToArray();
            using (SHA1 sha = SHA1.Create())
                Assert.Equal("0242260d8ae2a3366256605cfdf2713c72ff34e3", Hex.Encode(sha.ComputeHash(Encoding.UTF8.GetBytes(string.Join("\n", lines)))));
        }
    }
}
