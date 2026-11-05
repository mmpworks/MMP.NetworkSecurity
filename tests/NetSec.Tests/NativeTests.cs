using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Labs;
using NetSec.Native;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>Timing tests run alone, so a sibling test cannot add load to a measurement.</summary>
    [CollectionDefinition(Name, DisableParallelization = true)]
    public class TimingCollection
    {
        public const string Name = "timing";
    }

    /// <summary>Loads the built library by full path, so the DllImport by name finds it. A missing DLL gets built here. A build failure fails the test.</summary>
    public static class NativeLib
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr LoadLibraryW(string path);

        static readonly object Gate = new object();
        static bool _loaded;

        public static void Ensure()
        {
            lock (Gate)
            {
                if (_loaded) return;
                string arch = IntPtr.Size == 8 ? "x64" : "x86";
                string root = RepoRoot();
                string dll = Path.Combine(root, "native", "bin", arch, "netsec_ct.dll");
                if (!File.Exists(dll)) Build(root, arch);
                Assert.NotEqual(IntPtr.Zero, LoadLibraryW(dll));
                _loaded = true;
            }
        }

        static void Build(string root, string arch)
        {
            ProcessStartInfo start = new ProcessStartInfo("cmd.exe", "/c native\\build.cmd " + arch) { WorkingDirectory = root, UseShellExecute = false };
            using (Process build = Process.Start(start))
            {
                build.WaitForExit();
                Assert.Equal(0, build.ExitCode);
            }
        }

        static string RepoRoot()
        {
            string dir = AppDomain.CurrentDomain.BaseDirectory;
            while (dir != null && !File.Exists(Path.Combine(dir, "native", "netsec_ct.c"))) dir = Path.GetDirectoryName(dir);
            Assert.NotNull(dir);
            return dir;
        }
    }

    public class TimingJudgeTests
    {
        static TimingCase Case(params double[] ticks) { return new TimingCase("x", 1, 0, 10000000, ticks); }

        [Fact]
        public void Welch_t_matches_a_hand_worked_answer()
        {
            // Means 2 and 3, variances 1 and 1: t = -1 / sqrt(1/3 + 1/3) = -1.2247.
            Assert.Equal(-1.2247, TimingJudge.Welch(new double[] { 1, 2, 3 }, new double[] { 2, 3, 4 }), 4);
        }

        [Fact]
        public void Welch_crop_removes_a_pause_above_the_99th_percentile()
        {
            double[] x = new double[1000], y = new double[1000];
            for (int i = 0; i < x.Length; i++) { x[i] = 10 + i % 3; y[i] = 10 + i % 3; }
            x[5] = 1000000;
            x[6] = 1000000;
            Assert.True(Math.Abs(TimingJudge.Welch(x, y)) < 1);
        }

        [Fact]
        public void Welch_with_no_spread_is_zero_on_equal_sets_and_infinite_on_different_sets()
        {
            Assert.Equal(0, TimingJudge.Welch(new double[] { 5, 5 }, new double[] { 5, 5 }));
            double[] low = new double[200], high = new double[200];
            for (int i = 0; i < low.Length; i++) { low[i] = 5; high[i] = 7; }
            Assert.True(double.IsPositiveInfinity(TimingJudge.Welch(low, high)));
        }

        [Fact]
        public void Judge_passes_only_above_the_stated_threshold()
        {
            Assert.True(TimingJudge.Judge(Case(1, 2, 1, 2, 1, 2, 1, 2), Case(9, 10, 9, 10, 9, 10, 9, 8)).Separates);
            Assert.False(TimingJudge.Judge(Case(1, 2, 1, 2), Case(1, 2, 1, 2)).Separates);
        }

        [Theory]
        [InlineData(100.0, 20.0, true)]
        [InlineData(100.0, 40.0, false)]
        [InlineData(4.0, 0.1, false)]
        public void Separated_needs_the_minimum_and_three_times_the_constant_time_t(double leaky, double constant, bool expected)
        {
            TimingVerdict l = new TimingVerdict(leaky, leaky > TimingJudge.MinT), c = new TimingVerdict(constant, constant > TimingJudge.MinT);
            Assert.Equal(expected, TimingJudge.Separated(l, c));
        }

        [Fact]
        public void Report_writes_nanoseconds_from_ticks_and_counts_the_slow_tail()
        {
            double[] ticks = new double[100];
            for (int i = 0; i < 100; i++) ticks[i] = i < 99 ? 10 : 5000;
            string json = TimingReport.Case(new TimingCase(TimingLab.LeakyName, 8, 0, 10000000, ticks));
            Assert.Contains("\"medianNs\":1000", json);
            Assert.Contains("{\"ns\":1000,\"count\":99}", json);
            Assert.Contains("\"histogram\":[{\"ns\":1000,\"count\":99},{\"ns\":500000,\"count\":1}]", json);
            Assert.Contains("\"aboveP99\":0", json);
        }

        [Fact]
        public void Best_guess_is_the_slowest_and_the_lowest_index_wins_a_tie()
        {
            Assert.Equal(2, TimingGuess.BestGuess(new double[] { 1, 3, 9, 3 }));
            Assert.Equal(0, TimingGuess.BestGuess(new double[] { 4, 4, 4 }));
        }

        [Fact]
        public void Score_ignores_the_slow_tail()
        {
            double[] ticks = new double[10];
            for (int i = 0; i < 9; i++) ticks[i] = 7;
            ticks[9] = 100000;
            Assert.Equal(7, TimingGuess.Score(ticks));
        }

        [Fact]
        public void Stretch_repeats_each_secret_byte_for_one_block()
        {
            byte[] target = TimingGuess.Stretch(new byte[] { 0x11, 0x22 });
            Assert.Equal(2 * TimingGuess.BlockBytes, target.Length);
            Assert.Equal(0x11, target[TimingGuess.BlockBytes - 1]);
            Assert.Equal(0x22, target[TimingGuess.BlockBytes]);
        }

        [Fact]
        public void Managed_compare_answers_by_content()
        {
            byte[] a = LabBytes.Fill(64, 3), same = (byte[])a.Clone(), last = (byte[])a.Clone();
            last[63] ^= 1;
            Assert.True(ManagedCompare.FixedShape(a, same));
            Assert.False(ManagedCompare.FixedShape(a, last));
            Assert.False(ManagedCompare.FixedShape(a, new byte[63]));
        }
    }

    public class NativeLoadTests
    {
        [Fact]
        public void A_library_that_will_not_load_maps_to_the_named_code()
        {
            NetSecException e = Assert.Throws<NetSecException>(() => NativeLoad.Run<int>(delegate { throw new DllNotFoundException("netsec_ct.dll"); }));
            Assert.Equal(ErrorCodes.NativeLibMissing, e.Error.Code);
            Assert.Equal(NativeLoad.CheckName, e.Error.CheckName);
            Assert.Equal(ErrorCodes.NativeLibMissing, Assert.Throws<NetSecException>(() => NativeLoad.Run<int>(delegate { throw new MissingMethodException(); })).Error.Code);
            Assert.Equal(ErrorCodes.NativeLibMissing, Assert.Throws<NetSecException>(() => NativeLoad.Run<int>(delegate { throw new BadImageFormatException(); })).Error.Code);
        }

        [Fact]
        public void Any_other_failure_keeps_its_own_type()
        {
            Assert.Throws<InvalidOperationException>(() => NativeLoad.Run<int>(delegate { throw new InvalidOperationException(); }));
        }
    }

    [Collection(TimingCollection.Name)]
    public class NativeLiveTests
    {
        public NativeLiveTests() { NativeLib.Ensure(); }

        [Fact]
        public void Abi_version_is_one()
        {
            Assert.Equal(1u, NativeCompare.AbiVersion());
        }

        [Theory]
        [InlineData(0)]
        [InlineData(31)]
        [InlineData(63)]
        public void Both_compares_find_a_difference_at_any_position(int position)
        {
            byte[] a = LabBytes.Fill(64, 12), same = (byte[])a.Clone(), diff = (byte[])a.Clone();
            diff[position] ^= 0x80;
            Assert.True(NativeCompare.Leaky(a, same));
            Assert.True(NativeCompare.ConstantTime(a, same));
            Assert.False(NativeCompare.Leaky(a, diff));
            Assert.False(NativeCompare.ConstantTime(a, diff));
        }

        [Fact]
        public void A_length_difference_and_empty_buffers_answer_without_a_fault()
        {
            Assert.False(NativeCompare.Leaky(new byte[3], new byte[4]));
            Assert.False(NativeCompare.ConstantTime(new byte[3], new byte[4]));
            Assert.True(NativeCompare.Leaky(new byte[0], new byte[0]));
            Assert.True(NativeCompare.ConstantTime(new byte[0], new byte[0]));
        }

        [Fact]
        public void Interleaved_turns_show_the_leak_and_keep_the_stated_rule()
        {
            TimingCase[] leaky = TimingLab.Interleaved(CompareKind.Leaky, 4096, 20000, 0, 4095);
            TimingCase[] constant = TimingLab.Interleaved(CompareKind.ConstantTime, 4096, 20000, 0, 4095);
            Assert.Equal(20000, leaky[1].Ticks.Length);
            Assert.Equal(4095, leaky[1].DiffPosition);
            Assert.True(TimingJudge.Separated(TimingJudge.Judge(leaky[0], leaky[1]), TimingJudge.Judge(constant[0], constant[1])));
            Assert.True(TimingJudge.Mean(leaky[1].Ticks) > TimingJudge.Mean(leaky[0].Ticks));
        }

        [Fact]
        public void Interleaved_managed_times_every_sample()
        {
            TimingCase[] managed = TimingLab.InterleavedManaged(256, 250, 0, 255);
            Assert.Equal(TimingLab.ManagedName, managed[0].Compare);
            Assert.Equal(250, managed[0].Ticks.Length);
            Assert.Equal(250, managed[1].Ticks.Length);
            Assert.True(managed[0].TickFrequency > 0);
        }

        [Fact]
        public void A_sample_reports_a_clock_and_one_value_per_sample()
        {
            TimingCase c = TimingLab.Sample(CompareKind.ConstantTime, 256, 50, 0);
            Assert.Equal(50, c.Ticks.Length);
            Assert.True(c.TickFrequency > 0);
            Assert.Equal(TimingLab.ConstantTimeName, c.Compare);
        }
    }

    [Collection(TimingCollection.Name)]
    public class TimingLabRunTests
    {
        public TimingLabRunTests() { NativeLib.Ensure(); }

        static LabContext Context(AttackDefinition attack) => new LabContext
        {
            SessionId = "s11", TraceId = "s11", Seed = 11, Gate = new FreeRunGate(), Sink = new ListSink(), Clock = new FixedClock(1), Attack = attack,
        };

        static AttackDefinition Row(string id)
        {
            foreach (AttackDefinition a in AttackCatalog.All) if (a.AttackId == id) return a;
            throw new InvalidOperationException(id);
        }

        static string Plain(TraceEvent e) => Encoding.UTF8.GetString(e.Plain, 0, e.Plain.Length);

        [Fact]
        public void Control_run_shows_both_histograms_the_verdict_the_guess_and_the_managed_statement()
        {
            LabContext c = Context(null);
            IFuture<LabResult> run = LabCatalog.Find(11).Run(c);
            Make.Done(run);
            TraceEvent[] events = ((ListSink)c.Sink).Events;
            Assert.True(run.Result.Completed, run.Result.FailedCode + " " + run.Result.FailedCheck);
            Assert.DoesNotContain(events, e => e.Check != null && !e.Check.Passed);
            Assert.Equal(4, Array.FindAll(events, e => e.Type == "timing.samples").Length);
            Assert.Contains(events, e => e.Type == "timing.samples" && Plain(e).Contains("\"samples\":100000"));
            TraceEvent verdict = Array.Find(events, e => e.Type == "timing.verdict");
            Assert.Equal(TimingAttackLab.SeparationCheck, verdict.Check.Name);
            Assert.Contains(events, e => e.Type == "timing.managed" && e.Message.Contains("Managed code has no constant-time guarantee"));
            Assert.Equal(2, Array.FindAll(events, e => e.Type == "timing.guess.finished").Length);
            Assert.Contains(events, e => e.Type == "timing.lab.started" && e.Secrets[0].Name == "lab-secret");
        }

        [Fact]
        public void Guess_against_the_leaky_compare_recovers_the_secret_and_fails_no_check()
        {
            LabContext c = Context(Row("L11-guess-leaky"));
            IFuture<LabResult> run = LabCatalog.Find(11).Run(c);
            Make.Done(run);
            Assert.True(run.Result.Completed, run.Result.FailedCode + " " + run.Result.FailedCheck);
            TraceEvent[] events = ((ListSink)c.Sink).Events;
            Assert.DoesNotContain(events, e => e.Check != null && !e.Check.Passed);
            TraceEvent finished = Array.Find(events, e => e.Type == "timing.guess.finished");
            Assert.Contains("\"correctBytes\":4", Plain(finished));
        }

        [Fact]
        public void Guess_against_the_constant_time_compare_is_stopped_by_the_named_check()
        {
            LabContext c = Context(Row("L11-guess-constant-time"));
            IFuture<LabResult> run = LabCatalog.Find(11).Run(c);
            Make.Done(run);
            Assert.False(run.Result.Completed);
            Assert.Equal(ErrorCodes.TimingGuessStopped, run.Result.FailedCode);
            Assert.Equal(TimingAttackLab.ConstantTimeCheck, run.Result.FailedCheck);
            TraceEvent failed = Array.Find(((ListSink)c.Sink).Events, e => e.Check != null && !e.Check.Passed);
            Assert.Equal(ErrorCodes.TimingGuessStopped, failed.Check.Code);
        }

        [Fact]
        public void An_unknown_option_on_lesson_11_is_refused_by_name()
        {
            AttackDefinition bad = new AttackDefinition { AttackId = "L11-nonsense", Lesson = 11, Options = new LabOption[0] };
            IFuture<LabResult> run = LabCatalog.Find(11).Run(Context(bad));
            Make.Done(run);
            Assert.True(run.IsFaulted);
            Assert.Contains("L11-nonsense", run.Exception.Message);
        }
    }
}
