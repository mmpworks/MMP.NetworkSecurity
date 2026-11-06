using System.Linq;
using MMP.AsyncProxy;
using NetSec.Io;
using NetSec.Labs;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// Lesson 10 sends three values in the clear on purpose: the issuer's challenge, the client's signed answer, and the last API call. They are
    /// public protocol values, so the trace must not list them as secrets (Jared's ruling, V3). Each side still keeps them, and says so in a
    /// state.kept note at the place the secret event stood, so every later event keeps its stream number.
    /// </summary>
    public class Lesson10PublicValuesTests
    {
        static readonly string[] PublicValues = { "auth.issued-challenge", "auth.challenge", "auth.last-call" };

        static TraceEvent[] Run()
        {
            ListSink sink = new ListSink();
            LabContext c = new LabContext { SessionId = "s1", TraceId = "s1", Seed = 7, Gate = new FreeRunGate(), Sink = sink, Clock = new FixedClock(1), Random = new SeededRandom(7) };
            IFuture<LabResult> run = new Lesson10Auth().Run(c);
            Assert.True(run.Wait(60000), "the lab did not finish in 60 s");
            Assert.True(run.Result.Completed, "lesson 10 did not complete: " + run.Result.FailedCode);
            return sink.Events;
        }

        [Fact]
        public void The_three_public_values_are_not_listed_as_secrets()
        {
            string[] secretNames = Run().Where(e => e.Secrets != null).SelectMany(e => e.Secrets).Select(s => s.Name).Distinct().ToArray();
            foreach (string name in PublicValues) Assert.DoesNotContain(name, secretNames);
            // A credential stays a secret, even when the lab sends it in the clear on purpose.
            Assert.Contains("auth.token", secretNames);
            Assert.Contains("auth.device-key", secretNames);
        }

        [Fact]
        public void Each_side_says_it_keeps_the_value_at_the_place_the_secret_event_stood()
        {
            TraceEvent[] events = Run();
            TraceEvent[] kept = events.Where(e => e.Type == "state.kept").ToArray();
            foreach (string name in PublicValues)
                Assert.Contains(kept, e => e.Message != null && e.Message.Contains(name));
            Assert.All(kept, e => Assert.True(e.Secrets == null || e.Secrets.Length == 0));
            Assert.Equal(0, events.Count(e => e.Type == "secret.derived" && e.Secrets.Any(s => PublicValues.Contains(s.Name))));
        }
    }
}
