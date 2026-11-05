using System;
using System.Collections.Generic;
using System.Linq;
using MMP.AsyncProxy;
using NetSec.Io;
using NetSec.Labs;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>Lessons 1 to 3 over real loopback sockets, on both builds. docs/lessons-1-3-names.md is the list these names come from.</summary>
    public class LessonLabTests
    {
        sealed class Run
        {
            public LabResult Result;
            public TraceEvent[] Events;
            public IEnumerable<TraceEvent> Of(string type) => Events.Where(e => e.Type == type);
            public string[] Sent(string actor) => Of("wire.sent").Where(e => e.Actor == actor).Select(e => e.Message).ToArray();
            public string[] PassedChecks => Of("check.result").Where(e => e.Check.Passed).Select(e => e.Message).Distinct().ToArray();
            public TraceEvent Measure(string message) => Of("measure.result").Single(e => e.Message == message);
            public byte[] Secret(string actor, string name) => Of("kex.secret.computed").Where(e => e.Actor == actor).SelectMany(e => e.Secrets).Single(s => s.Name == name).Bytes;
        }

        static Run Go(int lesson, AttackDefinition attack = null, int seed = 7)
        {
            ListSink sink = new ListSink();
            LabContext c = new LabContext { SessionId = "s1", TraceId = "s1", Seed = seed, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(1), Random = new SeededRandom(seed), Attack = attack };
            IFuture<LabResult> future = LabCatalog.Find(lesson).Run(c);
            Assert.True(future.Wait(60000), "the lab did not finish in 60 s");
            return new Run { Result = future.Result, Events = sink.Events };
        }

        static AttackDefinition Attack(string id) => AttackCatalog.All.Single(a => a.AttackId == id);

        static int Number(string detail, string name) =>
            int.Parse(detail.Split(';').Single(p => p.StartsWith(name + "=")).Substring(name.Length + 1));

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        public void Each_lesson_completes_and_both_sides_send(int lesson)
        {
            Run run = Go(lesson);
            Assert.True(run.Result.Completed, run.Result.FailedCode + " " + run.Result.FailedCheck);
            Assert.NotEmpty(run.Sent("client"));
            Assert.NotEmpty(run.Sent("server"));
        }

        /// <summary>The engine streams give the same bytes on a same-seed rerun, so a fork matches its parent up to the tamper.</summary>
        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        public void A_same_seed_rerun_gives_the_same_engine_bytes(int lesson)
        {
            string[] Lines(Run r) => r.Events.Where(e => !e.StreamId.EndsWith("/wire")).OrderBy(e => e.EventId, StringComparer.Ordinal).Select(TraceJson.ToLine).ToArray();
            Assert.Equal(Lines(Go(lesson, null, 21)), Lines(Go(lesson, null, 21)));
            Assert.NotEqual(Lines(Go(lesson, null, 21)), Lines(Go(lesson, null, 22)));
        }

        /// <summary>
        /// A pinned digest of every engine event. Both builds run this test, so net10.0 and the CF binaries give the same bytes for a seed.
        /// A change to a message, a field, or an event name changes the pin. Update it on purpose, and only after both names and tours agree.
        /// </summary>
        [Theory]
        [InlineData(1, "96aedafa541b5c3eafc972f0b21534dbccd385a3")]
        [InlineData(2, "033931d977ab44f5268abf662084e0de6a75c0a0")]
        [InlineData(3, "7a6fcd9878e6188fcff35ef9e4684ce0e9250b4b")]
        public void The_engine_bytes_for_a_seed_are_the_same_on_both_builds(int lesson, string pin)
        {
            Run run = Go(lesson, null, 31);
            byte[] lines = System.Text.Encoding.UTF8.GetBytes(string.Join("\n", run.Events.Where(e => !e.StreamId.EndsWith("/wire")).OrderBy(e => e.EventId, StringComparer.Ordinal).Select(TraceJson.ToLine).ToArray()));
            NetSec.Crypto.IHash hash = NetSec.Crypto.Hashes.Sha256();
            hash.Update(lines, 0, lines.Length);
            Assert.Equal(pin, NetSec.Bytes.Hex.Encode(hash.Finish()).Substring(0, pin.Length));
        }

        [Fact]
        public void Lesson_1_sends_the_named_messages_in_order()
        {
            Run run = Go(1);
            Assert.Equal(new[] { "TextGcm1", "TextCbc", "PictureEcb", "PictureCbc", "PictureGcm", "TextGcm2" }, run.Sent("client"));
            Assert.Equal(new[] { "AesDone" }, run.Sent("server"));
            Assert.Equal(new[] { "GCM tag", "nonce reuse detector" }, run.PassedChecks);
            Assert.Equal(2, run.Of("keys.installed").Count());
        }

        [Fact]
        public void Lesson_1_ecb_shows_repeated_blocks_and_cbc_and_gcm_show_none()
        {
            Run run = Go(1);
            Assert.True(Number(run.Measure("PictureEcb").Detail, "repeats") > 100, run.Measure("PictureEcb").Detail);
            Assert.Equal(0, Number(run.Measure("PictureCbc").Detail, "repeats"));
            Assert.Equal(0, Number(run.Measure("PictureGcm").Detail, "repeats"));
            Assert.Equal(0, Number(run.Measure("TextCbc").Detail, "repeats"));
        }

        [Fact]
        public void Lesson_1_the_server_sees_the_clear_picture_and_the_wire_does_not_hold_it()
        {
            Run run = Go(1);
            TraceEvent sent = run.Of("wire.sent").Single(e => e.Message == "PictureGcm");
            TraceEvent got = run.Of("aes.message.received").Single(e => e.Message == "PictureGcm");
            Assert.Equal(64 * 64, got.Plain.Length);
            Assert.Equal(sent.Plain, got.Plain);
            TraceField cipher = sent.Fields.Single(f => f.Name == "cipher");
            Assert.False(cipher.VisibleToWire);
            Assert.Equal(64 * 64, cipher.Length);
            Assert.NotEqual(got.Plain, sent.Wire.Skip(cipher.Offset).Take(cipher.Length).ToArray());
            Assert.Equal(sent.Wire.Length, sent.Fields.Sum(f => f.Length));
        }

        [Fact]
        public void Lesson_1_use_ecb_leaks_in_the_text_and_no_check_fires()
        {
            Run run = Go(1, Attack("L1-use-ecb"));
            Assert.True(run.Result.Completed);
            Assert.Contains("TextEcb", run.Sent("client"));
            Assert.DoesNotContain("TextCbc", run.Sent("client"));
            Assert.Equal(3, Number(run.Measure("TextEcb").Detail, "repeats"));
        }

        [Fact]
        public void Lesson_1_cbc_flip_garbles_one_block_and_flips_one_bit_in_the_next_and_no_check_fires()
        {
            Run run = Go(1, Attack("L1-flip-cbc"));
            Assert.True(run.Result.Completed);
            byte[] clear = run.Of("wire.sent").Single(e => e.Message == "TextCbc").Plain;
            byte[] got = run.Of("aes.message.received").Single(e => e.Message == "TextCbc").Plain;
            Assert.NotEqual(clear.Take(16), got.Take(16));
            Assert.Equal(1, Enumerable.Range(16, 16).Count(i => clear[i] != got[i]));
            Assert.Equal(clear.Skip(32), got.Skip(32));
        }

        [Fact]
        public void Lesson_2_seals_pass_and_the_avalanche_changes_about_half_the_bits()
        {
            Run run = Go(2);
            Assert.Equal(new[] { "PlainHashSealed", "KeyedHashSealed", "HmacSealed", "CmacSealed" }, run.Sent("client"));
            Assert.Equal(new[] { "SealDone" }, run.Sent("server"));
            Assert.Equal(new[] { "hash compare", "keyed hash compare", "HMAC compare", "CMAC compare" }, run.PassedChecks);
            TraceEvent avalanche = run.Measure(Lesson02Seals.AvalancheName);
            Assert.Equal(64, avalanche.Plain.Length);
            Assert.Equal(256, Number(avalanche.Detail, "of"));
            int bits = Number(avalanche.Detail, "bits");
            Assert.InRange(bits, 90, 166);
        }

        [Fact]
        public void Lesson_2_length_extension_forges_the_keyed_hash_and_fails_on_hmac()
        {
            Run keyed = Go(2, Attack("L2-extend-keyed-hash"));
            Assert.True(keyed.Result.Completed, keyed.Result.FailedCode);
            byte[] forged = keyed.Of("seal.message.received").Single(e => e.Message == "KeyedHashSealed").Plain;
            Assert.True(forged.Length > Lesson02Seals.Message.Length, "the server did not read the longer forged message");
            Assert.Contains("keyed hash compare", keyed.PassedChecks);

            Run hmac = Go(2, Attack("L2-extend-hmac"));
            Assert.False(hmac.Result.Completed);
            Assert.Equal("HMAC compare", hmac.Result.FailedCheck);
        }

        [Fact]
        public void Lesson_3_each_round_gives_both_sides_the_same_secret_at_the_named_sizes()
        {
            Run run = Go(3);
            foreach ((string name, int size) in new[] { ("x25519.shared", 32), ("mlkem.shared", 32), ("hybrid.shared", 64) })
            {
                Assert.Equal(size, run.Secret("client", name).Length);
                Assert.Equal(run.Secret("client", name), run.Secret("server", name));
            }
            Assert.Equal(3, run.Of("check.result").Count(e => e.Check.Passed && e.Message == "key confirmation MAC"));
        }

        [Fact]
        public void Lesson_3_shares_have_the_named_sizes()
        {
            Run run = Go(3);
            int Size(string message) => run.Of("wire.sent").Single(e => e.Message == message).Wire.Length - Frame.HeaderSize;
            Assert.Equal(32, Size("X25519ClientShare"));
            Assert.Equal(32, Size("X25519ServerShare"));
            Assert.Equal(1184, Size("MlKemEncapsKey"));
            Assert.Equal(1088, Size("MlKemCiphertext"));
            Assert.Equal(1216, Size("HybridClientShare"));
            Assert.Equal(1120, Size("HybridServerShare"));
            Assert.Equal(new[] { "X25519ClientShare", "X25519Confirm", "MlKemEncapsKey", "MlKemConfirm", "HybridClientShare", "HybridConfirm" }, run.Sent("client"));
            Assert.Equal(new[] { "X25519ServerShare", "MlKemCiphertext", "HybridServerShare", "KexDone" }, run.Sent("server"));
        }

        [Fact]
        public void Lesson_3_a_flipped_ciphertext_gives_no_error_and_only_confirmation_catches_it()
        {
            Run run = Go(3, Attack("L3-flip-mlkem-ciphertext"));
            Assert.Equal("key confirmation MAC", run.Result.FailedCheck);
            Assert.NotEqual(run.Secret("client", "mlkem.shared"), run.Secret("server", "mlkem.shared"));
        }

        [Fact]
        public void Every_lesson_1_to_3_attack_has_a_control_and_the_names_in_the_list()
        {
            string[] expected =
            {
                "L1-use-ecb", "L1-flip-cbc", "L1-flip-gcm", "L1-reuse-nonce",
                "L2-flip-hash-message", "L2-flip-hmac-message", "L2-flip-hmac-tag", "L2-flip-cmac-message", "L2-flip-cmac-tag", "L2-extend-keyed-hash", "L2-extend-hmac",
                "L3-swap-server-share", "L3-flip-mlkem-ciphertext",
                "L6-replay-sale", "L6-flip-pin-block", "L6-ask-past-key",
                "L8-change-host-key", "L8-flip-exchange-signature", "L8-zero-share", "L8-flip-packet", "L8-wrong-user-key", "L8-refused-tunnel", "L8-legacy-flip-signature",
            };
            Assert.Equal(expected, AttackCatalog.All.Where(a => a.Lesson >= 1 && a.Lesson != 4 && a.Lesson != 5 && a.Lesson != 10).Select(a => a.AttackId).ToArray());
        }
    }
}
