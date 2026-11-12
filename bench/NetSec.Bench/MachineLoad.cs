using System;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace NetSec.Bench;

/// <summary>
/// CPU work on the machine outside this process, as a share of all logical processors. Pinning puts the paired rounds on one core,
/// but other processes can still run on that core, and work that starts during a measurement puts uneven load on the two copies. On
/// 2026-11-11 a dotnet test from another worktree started one minute into an S0 run and pushed one same-code ratio to 1.187.
/// A developer desktop is never idle (a browser and editors held 30 to 45% of all processors in the same hour, per the Windows
/// processor counter), so the rule is about NEW load: each timing host first waits for a steady baseline, and a pair fails the run when
/// its outside load rose more than <see cref="Rise"/> above that baseline (the baseline is never taken below <see cref="Floor"/>).
/// </summary>
static class MachineLoad
{
    // shortcut: Rise and CoreCeiling are tuned to this desktop (lead decisions, 2026-11-11 and 2026-11-12 Job T data). The core gate
    // decides: interference on the timing core read 29.6 to 43.4% there, desktop-only rows up to 20.6%. The whole-machine limit is a
    // backstop only, at max(baseline, Floor) + 25 points: desktop-only rows reached 57.9% machine (browser at 1.7 cores) with the core
    // clean, so a 15-point rise refused clean rows; 25 points still refuses a full outside build (75.3% at 12 rustc cores).
    // A pair fails above max(baseline, Floor) + Rise, or above CoreCeiling on the pinned core pair. Upgrade with Floor.
    public const double Rise = 0.25, Steady = 0.05, CoreCeiling = 0.25;

    // shortcut: a fixed floor under the baseline, from this desktop's measured normal (2026-11-11 Job T: clean rows 12 to 32%,
    // a Chrome-only row 30.3%, rustc rows 41 to 57%), so a quiet dip at settle cannot set a limit that ordinary desktop use breaks.
    // Upgrade when the bench runs on another machine: measure its normal and set the floor from it.
    public const double Floor = 0.25;
    public const int BusyExit = 8;
    static readonly TimeSpan SettleLimit = TimeSpan.FromMinutes(2), Window = TimeSpan.FromSeconds(1);
    const int BaselineWindows = 3;

    /// <summary>The outside load a pair may reach: max(settle baseline, <see cref="Floor"/>) plus <see cref="Rise"/>. NaN until <see cref="Settle"/> succeeds.</summary>
    public static double Limit = double.NaN;

    // GetSystemTimes gives FILETIME values (100 ns ticks summed over all logical processors); kernel time includes idle time.
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetSystemTimes(out long idle, out long kernel, out long user);

    // SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (class 8), one per logical processor: IdleTime, KernelTime, UserTime, DpcTime,
    // InterruptTime as 64-bit values, then a 32-bit InterruptCount padded to 8: 6 longs. KernelTime includes IdleTime.
    [DllImport("ntdll.dll")]
    static extern int NtQuerySystemInformation(int infoClass, [Out] long[] info, int length, out int returned);
    const int ProcessorPerformanceClass = 8, LongsPerProcessor = 6;

    /// <summary>The pinned logical processor and its hyper-thread sibling (set by <see cref="Measure.RaisePriority"/>); empty when not pinned.</summary>
    public static int[] CorePair = new int[0];

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetThreadTimes(IntPtr thread, out long creation, out long exit, out long kernel, out long user);

    public struct Sample
    {
        // Own: this process (all threads), for the machine figure. OwnThread: the calling (timing) thread, the only thread pinned to the
        // core pair, for the core figure. Runtime threads on the pair count as outside work there, which they are for the timed rounds.
        public long Idle, Total, Own, OwnThread, CoreIdle, CoreTotal;
    }

    public static Sample Now()
    {
        GetSystemTimes(out long idle, out long kernel, out long user);
        Sample s;
        using (Process self = Process.GetCurrentProcess())
            s = new Sample { Idle = idle, Total = kernel + user, Own = self.TotalProcessorTime.Ticks };
        if (GetThreadTimes(GetCurrentThread(), out long _, out long _, out long threadKernel, out long threadUser)) s.OwnThread = threadKernel + threadUser;
        long[] info = new long[LongsPerProcessor * Environment.ProcessorCount];
        if (CorePair.Length == 0 || NtQuerySystemInformation(ProcessorPerformanceClass, info, info.Length * 8, out int _) != 0) return s;
        foreach (int lp in CorePair)
        {
            s.CoreIdle += info[LongsPerProcessor * lp];
            s.CoreTotal += info[LongsPerProcessor * lp + 1] + info[LongsPerProcessor * lp + 2];
        }
        return s;
    }

    /// <summary>The busy share of the pinned core pair between two samples, less the timing thread (pinned there). NaN when the pair was
    /// not read.</summary>
    public static double CoreBusy(Sample from, Sample to)
    {
        long total = to.CoreTotal - from.CoreTotal;
        if (total <= 0) return double.NaN;
        long busy = total - (to.CoreIdle - from.CoreIdle) - (to.OwnThread - from.OwnThread);
        return Math.Max(0, (double)busy / total);
    }

    /// <summary>The busy share of all processors between two samples, less the time this process used.</summary>
    public static double OtherBusy(Sample from, Sample to)
    {
        long total = to.Total - from.Total;
        if (total <= 0) return 0;
        long busy = total - (to.Idle - from.Idle) - (to.Own - from.Own);
        return Math.Max(0, (double)busy / total);
    }

    public static double Read(TimeSpan window)
    {
        Sample from = Now();
        Thread.Sleep(window);
        return OtherBusy(from, Now());
    }

    /// <summary>
    /// Waits, for up to two minutes, until three one-second readings of outside load lie within <see cref="Steady"/> of each other, and
    /// sets <see cref="Limit"/> from their mean. Prints BENCH_SETTLE and returns true; prints BENCH_MACHINE_BUSY and returns false when
    /// the load never held steady.
    /// </summary>
    public static bool Settle()
    {
        Stopwatch waited = Stopwatch.StartNew();
        double[] last = new double[BaselineWindows];
        int filled = 0;
        do
        {
            Array.Copy(last, 1, last, 0, BaselineWindows - 1);
            last[BaselineWindows - 1] = Read(Window);
            filled++;
            if (filled >= BaselineWindows && last.Max() - last.Min() <= Steady)
            {
                Limit = Math.Max(last.Average(), Floor) + Rise;
                Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
                    "BENCH_SETTLE outside load {0:P1} (steady {1:P1} to {2:P1}) after {3:F0} s; a pair fails above {4:P1}",
                    last.Average(), last.Min(), last.Max(), waited.Elapsed.TotalSeconds, Limit));
                return true;
            }
        } while (waited.Elapsed < SettleLimit);
        Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
            "BENCH_MACHINE_BUSY outside load never steady: last {0:P1} to {1:P1} after {2:F0} s; no timing ran", last.Min(), last.Max(), waited.Elapsed.TotalSeconds));
        return false;
    }

    public static string Describe(double[] busy) => string.Format(CultureInfo.InvariantCulture,
        "outside load per row: max {0:P1} over {1} rows; limit {2:P1}; rows over the limit: {3}",
        busy.Max(), busy.Length, Limit, busy.Count(b => !(b <= Limit)));

    /// <summary>
    /// Prints the load line; returns 0 when every row stayed at or under the limit, else prints BENCH_MACHINE_BUSY, then one line per row
    /// over the limit with <paramref name="detail"/> for that row (its id and the top outside processes), and returns 8.
    /// A NaN limit (no settle ran) fails every row, so a host that skips the settle cannot pass.
    /// </summary>
    public static int Exit(double[] busy, string[] detail = null, double[] core = null)
    {
        Console.WriteLine("BENCH_LOAD " + Describe(busy));
        if (core != null)
            Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "BENCH_CORE_LOAD core-pair load per row: max {0:P1} over {1} rows; ceiling {2:P0}; rows over the ceiling: {3}",
                core.Max(), core.Length, CoreCeiling, core.Count(c => !(c <= CoreCeiling))));
        // A NaN core figure (pair not read) fails closed, like a NaN limit.
        Func<int, bool> over = i => !(busy[i] <= Limit) || (core != null && !(core[i] <= CoreCeiling));
        if (!Enumerable.Range(0, busy.Length).Any(over)) return 0;
        Console.WriteLine("BENCH_MACHINE_BUSY: other work ran during timed rounds (machine or timing-core load), so their ratios are not evidence");
        for (int i = 0; i < busy.Length; i++)
            if (over(i)) Console.WriteLine(string.Format(CultureInfo.InvariantCulture, "  over the limit: {0} (machine {1:P1}, core {2:P1})",
                detail != null ? detail[i] : "row " + i, busy[i], core != null ? core[i] : double.NaN));
        return BusyExit;
    }

    /// <summary>CPU time per process at one moment, for naming the processes behind a busy pair.</summary>
    public sealed class ProcessTimes
    {
        public readonly System.Collections.Generic.Dictionary<int, long> Ticks = new System.Collections.Generic.Dictionary<int, long>();
        public readonly System.Collections.Generic.Dictionary<int, string> Names = new System.Collections.Generic.Dictionary<int, string>();
        public long Taken;
    }

    /// <summary>Reads every process this user can read (protected processes are skipped), outside the timed rounds.</summary>
    public static ProcessTimes Snapshot()
    {
        ProcessTimes t = new ProcessTimes { Taken = Stopwatch.GetTimestamp() };
        int self;
        using (Process me = Process.GetCurrentProcess()) self = me.Id;
        foreach (Process p in Process.GetProcesses())
        {
            using (p)
            {
                if (p.Id == self || p.Id == 0) continue;
                try { t.Ticks[p.Id] = p.TotalProcessorTime.Ticks; t.Names[p.Id] = p.ProcessName; }
                catch (Exception) { }   // a protected or exited process: nothing to read
            }
        }
        return t;
    }

    /// <summary>The top <paramref name="count"/> processes by CPU between two snapshots, as "name (pid) N.NN cores".</summary>
    public static string Top(ProcessTimes from, ProcessTimes to, int count)
    {
        double seconds = (double)(to.Taken - from.Taken) / Stopwatch.Frequency;
        if (seconds <= 0) return "no process sample";
        // A process that started during the pair (the intruder case) counts from zero.
        var used = to.Ticks
            .Select(kv => new { Id = kv.Key, Cores = (kv.Value - (from.Ticks.TryGetValue(kv.Key, out long before) ? before : 0)) / 1e7 / seconds })
            .OrderByDescending(x => x.Cores).Take(count);
        return string.Join("; ", used.Select(x => string.Format(CultureInfo.InvariantCulture, "{0} ({1}) {2:F2} cores", to.Names[x.Id], x.Id, x.Cores)).ToArray());
    }
}
