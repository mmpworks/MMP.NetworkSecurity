using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using MMP.AsyncProxy;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Labs;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;
using Xunit.Abstractions;

namespace NetSec.Tests
{
    /// <summary>
    /// SPIKE, never merged. The falsifier for the step-mode red Echo saw (Tls13Tests.In_step_mode_a_held_event_stops_the_clock_and_a_stuck_read_still_ends_by_name,
    /// LINK_IDLE in place of LINK_DEADLINE). It runs that test's scenario 20 times beside a CPU burner and, for every run where the server's idle
    /// limit wins, asks when the client received the tampered Finished: never (a starved client: test margin), or more than 900 ms before the
    /// server's idle limit (the client's 600 ms read deadline should have won: a product bug).
    /// </summary>
    public class StepModeFalsifierSpike
    {
        readonly ITestOutputHelper _out;
        public StepModeFalsifierSpike(ITestOutputHelper output) { _out = output; }

        /// <summary>Stamps the wall time of each event as it reaches the sink. In step mode that is the time the gate let it out.</summary>
        sealed class StampSink : ITraceSink
        {
            readonly Stopwatch _clock = Stopwatch.StartNew();
            readonly List<(long Ms, TraceEvent E)> _events = new();
            public void Write(TraceEvent e) { lock (_events) _events.Add((_clock.ElapsedMilliseconds, e)); }
            public (long Ms, TraceEvent E)[] Events { get { lock (_events) return _events.ToArray(); } }
        }

        const int Deadline = 600;
        const long Slack = 300;

        [Fact]
        public void Spike_step_mode_idle_wins_only_when_the_client_never_had_the_tampered_bytes_in_time()
        {
            int runs = 20, idleWins = 0, starved = 0, late = 0, suspicious = 0, deadlineWins = 0, other = 0;
            for (int run = 1; run <= runs; run++)
            {
                StampSink sink = new();
                StepGate gate = new();
                LabContext c = new LabContext { SessionId = "s1", TraceId = "s1", Seed = 7, Gate = gate, Sink = sink, Clock = new FixedClock(1), Random = new SeededRandom(7),
                    Attack = AttackCatalog.All.Single(a => a.AttackId == "L5-flip-record-length"), DeadlineMs = Deadline };
                LabResult result = null;
                BurnWhile(() =>
                {
                    IFuture<LabResult> lab = LabCatalog.Find(5).Run(c);
                    System.Threading.Thread.Sleep(Deadline * 3);
                    Stopwatch clock = Stopwatch.StartNew();
                    while (!lab.IsCompleted && clock.ElapsedMilliseconds < 60000) { gate.Step(); System.Threading.Thread.Sleep(2); }
                    result = lab.IsCompleted ? lab.Result : null;
                });
                if (result == null) { other++; _out.WriteLine($"run {run}: did not finish in 60 s"); continue; }
                if (result.FailedCode == ErrorCodes.LinkDeadline) { deadlineWins++; _out.WriteLine($"run {run}: LINK_DEADLINE (as designed)"); continue; }
                if (result.FailedCode != ErrorCodes.LinkIdle) { other++; _out.WriteLine($"run {run}: {result.FailedCode} ({result.FailedCheck})"); continue; }

                idleWins++;
                var events = sink.Events;
                var idle = events.First(x => x.E.Type == "check.result" && x.E.Actor == "server" && x.E.Message == "idle limit");
                var tampered = events.Where(x => x.E.Type == "wire.sent" && x.E.Actor == "server" && x.Ms <= idle.Ms && x.E.Wire != null).LastOrDefault();
                byte[] want = tampered.E?.Wire ?? Array.Empty<byte>();
                // The client has the tampered bytes once its received chunks, joined, end with them.
                long? had = null;
                List<byte> got = new();
                foreach (var x in events.Where(x => x.E.Type == "wire.received" && x.E.Actor == "client" && x.E.Wire != null))
                {
                    got.AddRange(x.E.Wire);
                    if (had == null && want.Length > 0 && got.Count >= want.Length && got.Skip(got.Count - want.Length).SequenceEqual(want)) had = x.Ms;
                }
                string line;
                if (had == null || had > idle.Ms) { starved++; line = $"client never had the tampered bytes before the idle limit (idle at {idle.Ms} ms)"; }
                else if (idle.Ms - had.Value > Deadline + Slack) { suspicious++; line = $"SUSPICIOUS: client had them at {had} ms, idle at {idle.Ms} ms, gap {idle.Ms - had.Value} ms"; }
                else { late++; line = $"client had them at {had} ms, idle at {idle.Ms} ms, gap {idle.Ms - had.Value} ms (within the 600 ms deadline plus {Slack} ms)"; }
                _out.WriteLine($"run {run}: LINK_IDLE: {line}");
            }
            _out.WriteLine($"SUMMARY runs {runs}: LINK_DEADLINE {deadlineWins}, LINK_IDLE {idleWins} (starved {starved}, late {late}, suspicious {suspicious}), other {other}");
            Assert.True(suspicious == 0, $"{suspicious} idle wins came with the client holding the tampered bytes for longer than its deadline");
        }

        static void BurnWhile(Action work)
        {
            using System.Threading.CancellationTokenSource stop = new();
            System.Threading.Tasks.Task[] burners = Enumerable.Range(0, Environment.ProcessorCount).Select(_ => System.Threading.Tasks.Task.Factory.StartNew(() =>
            {
                double x = 1;
                while (!stop.IsCancellationRequested) x = Math.Sqrt(x + 1.5);
            }, System.Threading.Tasks.TaskCreationOptions.LongRunning)).ToArray();
            try { work(); }
            finally { stop.Cancel(); System.Threading.Tasks.Task.WaitAll(burners); }
        }
    }
}
