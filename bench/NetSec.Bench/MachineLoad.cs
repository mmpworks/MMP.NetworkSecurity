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
/// its outside load rose more than <see cref="Rise"/> above that baseline.
/// </summary>
static class MachineLoad
{
    // 10 points of 24 logical processors is about 2.4 busy cores: a browser drifts less, a dotnet build or test adds more.
    public const double Rise = 0.10, Steady = 0.05;
    public const int BusyExit = 8;
    static readonly TimeSpan SettleLimit = TimeSpan.FromMinutes(2), Window = TimeSpan.FromSeconds(1);
    const int BaselineWindows = 3;

    /// <summary>The outside load a pair may reach: the settle baseline plus <see cref="Rise"/>. NaN until <see cref="Settle"/> succeeds.</summary>
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

    public struct Sample
    {
        public long Idle, Total, Own, CoreIdle, CoreTotal;
    }

    public static Sample Now()
    {
        GetSystemTimes(out long idle, out long kernel, out long user);
        Sample s;
        using (Process self = Process.GetCurrentProcess())
            s = new Sample { Idle = idle, Total = kernel + user, Own = self.TotalProcessorTime.Ticks };
        long[] info = new long[LongsPerProcessor * Environment.ProcessorCount];
        if (CorePair.Length == 0 || NtQuerySystemInformation(ProcessorPerformanceClass, info, info.Length * 8, out int _) != 0) return s;
        foreach (int lp in CorePair)
        {
            s.CoreIdle += info[LongsPerProcessor * lp];
            s.CoreTotal += info[LongsPerProcessor * lp + 1] + info[LongsPerProcessor * lp + 2];
        }
        return s;
    }

    /// <summary>The busy share of the pinned core pair between two samples, less this process (which runs only on the pinned processor
    /// while timing). NaN when the pair was not read.</summary>
    public static double CoreBusy(Sample from, Sample to)
    {
        long total = to.CoreTotal - from.CoreTotal;
        if (total <= 0) return double.NaN;
        long busy = total - (to.CoreIdle - from.CoreIdle) - (to.Own - from.Own);
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
                Limit = last.Average() + Rise;
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

    /// <summary>Prints the load line; returns 0 when every row stayed at or under the limit, else prints BENCH_MACHINE_BUSY and returns 8.
    /// A NaN limit (no settle ran) fails every row, so a host that skips the settle cannot pass.</summary>
    public static int Exit(double[] busy)
    {
        Console.WriteLine("BENCH_LOAD " + Describe(busy));
        if (busy.All(b => b <= Limit)) return 0;
        Console.WriteLine("BENCH_MACHINE_BUSY: other work started during timed rounds, so their ratios are not evidence");
        return BusyExit;
    }
}
