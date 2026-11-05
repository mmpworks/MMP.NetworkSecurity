using System.Linq;
using MMP.AsyncProxy;
using NetSec.Io;
using NetSec.Labs;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>A same-seed rerun must give the same bytes, so every event a lab emits takes its time from the lab's clock. Lesson 11 measures real time, so it stays out.</summary>
    public class LabClockTests
    {
        const long Stamp = 1234;

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        [InlineData(6)]
        [InlineData(7)]
        [InlineData(8)]
        [InlineData(9)]
        [InlineData(10)]
        public void Every_event_takes_its_time_from_the_labs_clock(int lesson)
        {
            ListSink sink = new ListSink();
            LabContext c = new LabContext { SessionId = "clock", TraceId = "clock", Seed = 7, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(Stamp), Random = new SeededRandom(7) };
            IFuture<LabResult> run = LabCatalog.Find(lesson).Run(c);
            Assert.True(run.Wait(60000), "the lab did not finish in 60 s");

            TraceEvent[] events = sink.Events;
            Assert.NotEmpty(events);
            string[] wrong = events.Where(e => e.AtMicros != Stamp).Select(e => e.StreamId).Distinct().OrderBy(s => s, System.StringComparer.Ordinal).ToArray();
            Assert.True(wrong.Length == 0, "these streams took another clock: " + string.Join(", ", wrong));
        }
    }
}
