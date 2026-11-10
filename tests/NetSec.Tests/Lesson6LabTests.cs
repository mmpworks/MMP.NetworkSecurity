using System;
using System.Linq;
using MMP.AsyncProxy;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Labs;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>Lesson 6 over real loopback sockets, on both builds. docs/lesson-6-names.md is the list these names come from.</summary>
    public class Lesson6LabTests
    {
        sealed class Run
        {
            public LabResult Result;
            public TraceEvent[] Events;
            public TraceEvent[] Of(string type, string actor) => Events.Where(e => e.Type == type && e.Actor == actor).ToArray();
            public byte[] Secret(string actor, string name) => Of("dukpt.key.derived", actor).SelectMany(e => e.Secrets).Single(s => s.Name == name).Bytes;
        }

        static async System.Threading.Tasks.Task<Run> Go(AttackDefinition attack = null, int seed = 7)
        {
            ListSink sink = new ListSink();
            LabContext c = new LabContext { SessionId = "s1", TraceId = "s1", Seed = seed, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(1), Random = new SeededRandom(seed), Attack = attack };
            IFuture<LabResult> future = LabCatalog.Find(6).Run(c);
            Assert.True(await FutureWaits.Within(future, TimeSpan.FromMilliseconds(60000)), "the lab did not finish in 60 s");
            return new Run { Result = future.Result, Events = sink.Events };
        }

        static AttackDefinition Attack(string id) => AttackCatalog.All.Single(a => a.AttackId == id);

        [Fact]
        public async System.Threading.Tasks.Task The_control_run_completes_with_four_sales()
        {
            Run run = await Go();
            Assert.True(run.Result.Completed, run.Result.FailedCode + " " + run.Result.FailedCheck);
            Assert.Equal(new[] { "Sale", "Sale", "Sale", "Sale" }, run.Of("wire.sent", "reader").Select(e => e.Message).ToArray());
            Assert.Equal(new[] { "SaleApproved", "SaleApproved", "SaleApproved", "SaleDone" }, run.Of("wire.sent", "bank").Select(e => e.Message).ToArray());
        }

        [Fact]
        public async System.Threading.Tasks.Task Both_sides_derive_the_same_key_for_each_sale_and_a_new_key_each_time()
        {
            Run run = await Go();
            Assert.Equal(run.Secret("reader", "dukpt.initial"), run.Secret("bank", "dukpt.initial"));
            byte[][] keys = new byte[4][];
            for (int c = 1; c <= 4; c++)
            {
                keys[c - 1] = run.Secret("reader", "dukpt.pinKey." + c);
                Assert.Equal(keys[c - 1], run.Secret("bank", "dukpt.pinKey." + c));
            }
            Assert.Equal(4, keys.Select(NetSec.Bytes.Hex.Encode).Distinct().Count());
        }

        [Fact]
        public async System.Threading.Tasks.Task The_base_key_stays_at_the_bank()
        {
            Run run = await Go();
            Assert.NotEmpty(run.Secret("bank", "dukpt.bdk"));
            Assert.DoesNotContain(run.Events.Where(e => e.Actor == "reader").SelectMany(e => e.Secrets ?? new TraceSecret[0]), s => s.Name == "dukpt.bdk");
        }

        [Fact]
        public async System.Threading.Tasks.Task The_reader_reports_each_erase_and_its_true_register_count()
        {
            Run run = await Go();
            Assert.Equal(
                new[] { "dukpt.initial", "dukpt.derivationKey.1", "dukpt.derivationKey.2", "dukpt.derivationKey.3", "dukpt.derivationKey.4" },
                run.Of("dukpt.key.erased", "reader").Select(e => e.Message).ToArray());
            Assert.Equal(
                new[] { "held=32;next=1", "held=31;next=2", "held=31;next=3", "held=30;next=4", "held=31;next=5" },
                run.Of("measure.result", "reader").Where(e => e.Message == "Reader registers").Select(e => e.Detail).ToArray());
        }

        [Fact]
        public async System.Threading.Tasks.Task The_bank_passes_both_checks_on_each_sale_and_opens_the_pin()
        {
            Run run = await Go();
            TraceEvent[] checks = run.Of("check.result", "bank");
            Assert.Equal(4, checks.Count(e => e.Check.Passed && e.Message == "KSN already seen"));
            Assert.Equal(4, checks.Count(e => e.Check.Passed && e.Message == "PIN block format check"));
            foreach (TraceEvent received in run.Of("dukpt.message.received", "bank"))
                Assert.Equal("1234", System.Text.Encoding.UTF8.GetString(received.Plain));
        }

        [Fact]
        public async System.Threading.Tasks.Task The_wire_shows_the_ksn_and_hides_the_pin_block()
        {
            TraceEvent sale = (await Go()).Of("wire.sent", "reader")[0];
            Assert.Equal(new[] { "type", "length", "ksn", "pinBlock" }, sale.Fields.Select(f => f.Name).ToArray());
            Assert.True(sale.Fields.Single(f => f.Name == "ksn").VisibleToWire);
            Assert.False(sale.Fields.Single(f => f.Name == "pinBlock").VisibleToWire);
            Assert.Equal(4 + 12 + 16, sale.Wire.Length);
            Assert.DoesNotContain("1234", System.Text.Encoding.ASCII.GetString(sale.Wire));
        }

        [Theory]
        [InlineData("L6-replay-sale", "bank")]
        [InlineData("L6-flip-pin-block", "bank")]
        [InlineData("L6-ask-past-key", "reader")]
        public async System.Threading.Tasks.Task An_attack_is_caught_by_its_named_check_on_the_named_side(string id, string catcher)
        {
            AttackDefinition attack = Attack(id);
            Assert.Equal(AttackOutcome.Rejected, attack.Expect);
            Run run = await Go(attack);
            Assert.False(run.Result.Completed);
            Assert.Equal(attack.ExpectCode, run.Result.FailedCode);
            Assert.Equal(attack.ExpectCheck, run.Result.FailedCheck);
            TraceEvent failed = run.Events.Single(e => e.Type == "check.result" && !e.Check.Passed && e.Check.Code == attack.ExpectCode);
            Assert.Equal(catcher, failed.Actor);
            Assert.Equal(attack.ExpectCheck, failed.Message);
        }

        [Fact]
        public void The_attack_rows_use_the_ux_check_names_and_stable_codes()
        {
            Assert.Equal(ErrorCodes.DukptKsnReplay, Attack("L6-replay-sale").ExpectCode);
            Assert.Equal("KSN already seen", Attack("L6-replay-sale").ExpectCheck);
            Assert.Equal(ErrorCodes.DukptPinBlockFormat, Attack("L6-flip-pin-block").ExpectCode);
            Assert.Equal("PIN block format check", Attack("L6-flip-pin-block").ExpectCheck);
            Assert.Equal(ErrorCodes.DukptKeyNotHeld, Attack("L6-ask-past-key").ExpectCode);
            Assert.Equal("key not in reader state", Attack("L6-ask-past-key").ExpectCheck);
        }

        [Fact]
        public async System.Threading.Tasks.Task A_refused_replay_shows_no_pin_in_the_received_event()
        {
            string[] plains = (await Go(Attack("L6-replay-sale"))).Of("dukpt.message.received", "bank").Select(e => System.Text.Encoding.UTF8.GetString(e.Plain ?? new byte[0])).ToArray();
            Assert.Equal(new[] { "1234", "" }, plains);
        }

        [Fact]
        public async System.Threading.Tasks.Task A_flip_matches_the_control_until_the_tamper()
        {
            TraceEvent control = (await Go(null, 9)).Of("dukpt.message.sent", "reader")[0];
            TraceEvent attacked = (await Go(Attack("L6-flip-pin-block"), 9)).Of("dukpt.message.sent", "reader")[0];
            Assert.Equal(TraceJson.ToLine(control), TraceJson.ToLine(attacked));
        }

        /// <summary>The same hash on both builds, because the engine code is shared. A difference is a fault in shared code.</summary>
        [Fact]
        public async System.Threading.Tasks.Task The_engine_bytes_for_a_seed_are_the_same_on_both_builds()
        {
            Run run = await Go(null, 31);
            byte[] lines = System.Text.Encoding.UTF8.GetBytes(string.Join("\n", run.Events.Where(e => !e.StreamId.EndsWith("/wire")).OrderBy(e => e.EventId, StringComparer.Ordinal).Select(TraceJson.ToLine).ToArray()));
            NetSec.Crypto.IHash hash = NetSec.Crypto.Hashes.Sha256();
            hash.Update(lines, 0, lines.Length);
            Assert.Equal("24e68efe891a8c549d7eccfcce274e3ffe4d3b2a", NetSec.Bytes.Hex.Encode(hash.Finish()).Substring(0, 40));
        }
    }
}
