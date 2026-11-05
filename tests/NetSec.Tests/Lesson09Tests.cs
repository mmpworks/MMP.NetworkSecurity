using System;
using System.Linq;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Bytes;
using NetSec.Io;
using NetSec.Labs;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    public class Lesson09Tests
    {
        sealed class Run
        {
            public LabResult Result;
            public TraceEvent[] Events;
        }

        static Run Go(AttackDefinition attack = null)
        {
            ListSink sink = new ListSink();
            LabContext c = new LabContext { SessionId = "s9", TraceId = "s9", Seed = 7, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(1), Random = new SeededRandom(7), Attack = attack };
            IFuture<LabResult> future = new Lesson09Bridge().Run(c);
            Assert.True(future.Wait(60000), "the lab did not finish in 60 s");
            return new Run { Result = future.Result, Events = sink.Events };
        }

        [Fact]
        public void Lesson_9_is_released_with_its_three_rows()
        {
            Assert.IsType<Lesson09Bridge>(LabCatalog.Find(9));
            Assert.Equal(3, AttackCatalog.All.Count(a => a.Lesson == 9));
        }

        [Fact]
        public void The_control_crosses_both_hops_and_the_bank_recovers_the_pin()
        {
            Run run = Go();
            Assert.True(run.Result.Completed, run.Result.FailedCode + " " + run.Result.FailedCheck);
            Assert.DoesNotContain(run.Events, e => e.Check != null && !e.Check.Passed);
            Assert.Contains(run.Events, e => e.Actor == "bank" && e.Type == "check.result" && e.Check.Passed && e.Check.Name == "PIN block MAC at bank");

            Assert.Contains(run.Events, e => e.Hop == "hop1" && e.Actor == "ce" && e.Type == "wire.sent");
            Assert.Contains(run.Events, e => e.Hop == "hop1" && e.Actor == "gateway" && e.Type == "wire.sent");
            Assert.Contains(run.Events, e => e.Hop == "hop2" && e.Actor == "gateway" && e.Type == "wire.sent");
            Assert.Contains(run.Events, e => e.Hop == "hop2" && e.Actor == "server" && e.Type == "wire.sent");
            Assert.Equal(new[] { "s9" }, run.Events.Select(e => e.TraceId).Distinct().ToArray());
        }

        [Fact]
        public void A_context_with_no_ids_still_runs_under_one_trace_id()
        {
            ListSink sink = new ListSink();
            LabContext c = new LabContext { Seed = 7, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(1), Random = new SeededRandom(7) };
            IFuture<LabResult> future = new Lesson09Bridge().Run(c);
            Assert.True(future.Wait(60000), "the lab did not finish in 60 s");
            Assert.False(future.IsFaulted, "the lab faulted");
            Assert.True(future.Result.Completed, future.Result.FailedCode);
            Assert.Single(sink.Events.Select(e => e.TraceId).Distinct());
        }

        [Fact]
        public void Arrows_on_each_hop_name_the_lanes_of_that_hop()
        {
            Run run = Go();
            Assert.All(run.Events.Where(e => e.Hop == "hop1" && e.Type == "wire.sent"), e => Assert.Contains(e.To, new[] { "ce", "gateway" }));
            Assert.All(run.Events.Where(e => e.Hop == "hop2" && e.Type == "wire.sent"), e => Assert.Contains(e.To, new[] { "gateway", "server" }));
        }

        [Fact]
        public void The_gateway_says_it_cannot_open_the_pin_block_and_holds_no_clear_field()
        {
            Run run = Go();
            Assert.Contains(run.Events, e => e.Actor == "gateway" && e.Type == "gateway.envelope.relayed" && e.Detail == "PIN block: gateway cannot open this");
            TraceEvent bankKey = run.Events.Single(e => e.Actor == "bank" && e.Type == "secret.derived");
            string gatewayText = string.Concat(run.Events.Where(e => e.Actor == "gateway" || e.Actor == "ce").Select(TraceJson.ToLine)).ToLowerInvariant();
            Assert.DoesNotContain(Hex.Encode(bankKey.Secrets[0].Bytes), gatewayText);
        }

        [Theory]
        [InlineData("L9-tamper-hop1", "SSH_PACKET_MAC", "packet MAC")]
        [InlineData("L9-tamper-hop2", "TLS13_AEAD_TAG", "AEAD tag")]
        [InlineData("L9-flip-pin-block", "DUKPT_MAC_MISMATCH", "PIN block MAC at bank")]
        public void Each_row_changes_one_thing_and_stops_at_its_named_check(string id, string code, string check)
        {
            AttackDefinition row = AttackCatalog.All.Single(a => a.AttackId == id);
            Assert.Equal(1, (row.Plan != null ? 1 : 0) + (row.Options == null ? 0 : row.Options.Length));
            Assert.Equal(code, row.ExpectCode);
            Assert.Equal(check, row.ExpectCheck);
            Run run = Go(row);
            Assert.False(run.Result.Completed, id + " ran to the end");
            Assert.Equal(code, run.Result.FailedCode);
            Assert.Equal(check, run.Result.FailedCheck);
        }

        [Fact]
        public void A_flipped_pin_block_passes_both_hops_and_only_the_bank_sees_it()
        {
            Run run = Go(AttackCatalog.All.Single(a => a.AttackId == "L9-flip-pin-block"));
            TraceEvent[] failed = run.Events.Where(e => e.Check != null && !e.Check.Passed).ToArray();
            Assert.Equal(new[] { "bank" }, failed.Select(e => e.Actor).Distinct().ToArray());
            Assert.Contains(run.Events, e => e.Actor == "server" && e.Hop == "hop2" && e.Type == "wire.sent" && e.Message == "ApplicationData");
        }

        [Fact]
        public void A_tampered_hop_1_never_reaches_the_bank()
        {
            Run run = Go(AttackCatalog.All.Single(a => a.AttackId == "L9-tamper-hop1"));
            Assert.DoesNotContain(run.Events, e => e.Actor == "bank");
        }
    }
}
