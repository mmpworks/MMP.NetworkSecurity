using MMP.AsyncProxy;
using NetSec.Io;
using Xunit;

namespace NetSec.Tests
{
    public class StepGateTests
    {
        /// <summary>A lab can do slow work before its first event, so a learner's step can arrive while no event waits. That step must still count.</summary>
        [Fact]
        public void A_step_before_the_first_event_releases_that_event()
        {
            StepGate gate = new StepGate();
            gate.Step();
            Assert.True(gate.Pass(null).IsCompleted);
        }

        /// <summary>The app sends a step again while it waits, so early steps must not add up and skip events.</summary>
        [Fact]
        public void Several_early_steps_release_one_event()
        {
            StepGate gate = new StepGate();
            gate.Step();
            gate.Step();
            Assert.True(gate.Pass(null).IsCompleted);
            Assert.False(gate.Pass(null).IsCompleted);
        }

        [Fact]
        public async System.Threading.Tasks.Task A_step_that_releases_a_waiting_event_leaves_nothing_for_the_next_event()
        {
            StepGate gate = new StepGate();
            IFuture first = gate.Pass(null);
            gate.Step();
            Assert.True(await FutureWaits.Within(first, System.TimeSpan.FromMilliseconds(5000)));
            Assert.False(gate.Pass(null).IsCompleted);
        }

        [Fact]
        public async System.Threading.Tasks.Task Events_wait_in_order_and_each_step_releases_the_oldest()
        {
            StepGate gate = new StepGate();
            IFuture first = gate.Pass(null), second = gate.Pass(null);
            gate.Step();
            Assert.True(await FutureWaits.Within(first, System.TimeSpan.FromMilliseconds(5000)));
            Assert.False(second.IsCompleted);
            gate.Step();
            Assert.True(await FutureWaits.Within(second, System.TimeSpan.FromMilliseconds(5000)));
        }

        [Fact]
        public void Pause_forgets_an_early_step()
        {
            StepGate gate = new StepGate();
            gate.Step();
            gate.Pause();
            Assert.False(gate.Pass(null).IsCompleted);
        }

        [Fact]
        public void Run_then_pause_forgets_an_early_step()
        {
            StepGate gate = new StepGate();
            gate.Step();
            gate.Run();
            Assert.True(gate.Pass(null).IsCompleted);
            gate.Pause();
            Assert.False(gate.Pass(null).IsCompleted);
        }
    }
}
