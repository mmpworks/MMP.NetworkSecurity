using System;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace NetSec.Bench;

/// <summary>One copy's numbers in a paired measurement: ns per call in each round, and what its timed rounds allocated and collected.</summary>
sealed class Side
{
    public double[] NsPerCall;
    public double BytesPerCall;
    public int Gen0, Gen1, Gen2;

    public double MedianNs => Measure.Median(NsPerCall);
}

/// <summary>
/// A paired measurement of the same work on two copies of the code. <see cref="Ratios"/> holds one ratio for each round pair
/// (original ns over new ns, so above 1 means the new code is faster); the reported ratio is their median.
/// </summary>
sealed class Pair
{
    public Side Original, New;
    public double[] Ratios;
    public long CallsPerRound;
    public long PeakWorkingSet;

    public double MedianRatio => Measure.Median(Ratios);
}

/// <summary>
/// The timing engine of both the block cases and the AO-9 file rows. It times the two copies in alternating rounds
/// (original, new, then new, original, and so on), so drift on the machine falls on both copies alike, and it takes the ratio from each
/// round pair. Before each timed round it forces a full collection, so one copy never pays for the garbage of the other.
/// Both copies run the same call count in a round, set during warm-up so the slower copy's round lasts at least the round target.
/// Allocated bytes and collection counts cover the timed rounds only. Peak working set is the process peak after the measurement.
/// </summary>
static class Measure
{
    public const int Rounds = 31;   // the default round pairs; the file rows pass their own count (FileBench.Pairs)
    public static readonly TimeSpan WarmTarget = TimeSpan.FromMilliseconds(300);

    public static Pair Run(Action original, Action current, TimeSpan roundTarget) => Run(original, current, roundTarget, Rounds);

    public static Pair Run(Action original, Action current, TimeSpan roundTarget, int rounds)
    {
        long calls = Math.Max(CallsFor(original, roundTarget), CallsFor(current, roundTarget));
        Side o = NewSide(rounds), n = NewSide(rounds);
        for (int r = 0; r < rounds; r++)
        {
            bool originalFirst = r % 2 == 0;
            TimeRound(originalFirst ? original : current, calls, originalFirst ? o : n, r);
            TimeRound(originalFirst ? current : original, calls, originalFirst ? n : o, r);
        }
        o.BytesPerCall /= calls * rounds;
        n.BytesPerCall /= calls * rounds;
        return new Pair
        {
            Original = o, New = n, CallsPerRound = calls, PeakWorkingSet = PeakWorkingSet(),
            Ratios = Enumerable.Range(0, rounds).Select(r => o.NsPerCall[r] / n.NsPerCall[r]).ToArray(),
        };
    }

    /// <summary>
    /// The process warm-up, run once over every case before the first measurement. The tiered JIT moves a method to optimized code
    /// after enough calls, and dynamic PGO rewrites it once more, so a case measured before both copies settle reads a ratio far from 1
    /// (0.22 in the first pair of the first case of a smoke run). Each call runs for <paramref name="each"/> on both copies.
    /// </summary>
    public static void PreWarm(System.Collections.Generic.IEnumerable<Action[]> calls, TimeSpan each)
    {
        foreach (var pair in calls)
        {
            RunFor(pair[0], each);
            RunFor(pair[1], each);
        }
    }

    static void RunFor(Action call, TimeSpan time)
    {
        Stopwatch sw = Stopwatch.StartNew();
        while (sw.Elapsed < time) call();
    }

    /// <summary>Runs the call for the warm-up time, doubling the batch until one batch lasts the round target. Returns that batch size.</summary>
    static long CallsFor(Action call, TimeSpan roundTarget)
    {
        long batch = 1;
        Stopwatch total = Stopwatch.StartNew();
        while (true)
        {
            Stopwatch one = Stopwatch.StartNew();
            for (long i = 0; i < batch; i++) call();
            bool longEnough = one.Elapsed >= roundTarget;
            if (longEnough && total.Elapsed >= WarmTarget) return batch;
            if (!longEnough) batch *= 2;
        }
    }

    static void TimeRound(Action call, long calls, Side side, int round)
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        int g0 = GC.CollectionCount(0), g1 = GC.CollectionCount(1), g2 = GC.CollectionCount(2);
        long before = Allocated.Now();
        Stopwatch sw = Stopwatch.StartNew();
        for (long i = 0; i < calls; i++) call();
        sw.Stop();
        side.BytesPerCall += Allocated.Now() - before;
        side.Gen0 += GC.CollectionCount(0) - g0;
        side.Gen1 += GC.CollectionCount(1) - g1;
        side.Gen2 += GC.CollectionCount(2) - g2;
        side.NsPerCall[round] = sw.Elapsed.TotalMilliseconds * 1e6 / calls;
    }

    static Side NewSide(int rounds) => new Side { NsPerCall = new double[rounds] };

    public static double Median(double[] values)
    {
        double[] s = values.OrderBy(v => v).ToArray();
        return s.Length % 2 == 1 ? s[s.Length / 2] : (s[s.Length / 2 - 1] + s[s.Length / 2]) / 2;
    }

    static long PeakWorkingSet()
    {
        using (Process p = Process.GetCurrentProcess()) return p.PeakWorkingSet64;
    }

    /// <summary>
    /// Raises this process and thread to High / Highest and pins the process to one logical processor, so the paired rounds always run on
    /// the same core and never migrate. The core is the last logical processor, or --core N. Returns what it set, for the report.
    /// <see cref="Unpin"/> gives the process every core back for the 25-thread run.
    /// </summary>
    public static string RaisePriority(int? core)
    {
        try
        {
            CoreMap.Pick fastest = core.HasValue ? null : CoreMap.Fastest();
            int pick = core ?? (fastest != null ? fastest.LogicalProcessor : 0);
            using (Process p = Process.GetCurrentProcess()) p.PriorityClass = ProcessPriorityClass.High;
            SetAffinity(1L << pick);
            Thread.CurrentThread.Priority = ThreadPriority.Highest;
            string why = core.HasValue ? "chosen by --core" : fastest == null ? "no CPU set information, so processor 0"
                : "core " + fastest.Core + ", efficiency class " + fastest.EfficiencyClass + " (the highest on this CPU; lowest is " + fastest.LowestClass + ")";
            return "process priority High, thread priority Highest, pinned to logical processor " + pick + " of " + Environment.ProcessorCount
                + ", " + why + ", for the paired rounds (all processors for the 25-thread run)";
        }
        catch (Exception e)
        {
            return "priority or affinity not set (" + e.GetType().Name + "): normal priority, no pin";
        }
    }

    public static void Unpin() => SetAffinity(Environment.ProcessorCount >= 64 ? -1L : (1L << Environment.ProcessorCount) - 1);

    /// <summary>Process affinity exists on Windows and Linux only; the bench runs on Windows, and the guard keeps the platform analyzer exact.</summary>
    static void SetAffinity(long mask)
    {
#if NET
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("the bench pins a core on Windows only");
#endif
        using (Process p = Process.GetCurrentProcess()) p.ProcessorAffinity = (IntPtr)mask;
    }
}

/// <summary>The runtime's own allocated-bytes counter. The two runtimes have different counters, so the report names the one it read.</summary>
static class Allocated
{
#if NET35
    // CLR 2.0 has no allocation counter. The CLR 2.0 host measures bytes in its own pass (GC.GetTotalMemory around a call count with no gen-0 collection).
    public const string Method = "none in the timed rounds on CLR 2.0; bytes come from a separate GC.GetTotalMemory pass";

    public static long Now() => 0;
#elif NETFRAMEWORK
    static Allocated() { AppDomain.MonitoringIsEnabled = true; }

    // The AppDomain counter moves in allocation-context steps of several KB, so a per-call value is an average over many calls.
    public const string Method = "AppDomain.MonitoringTotalAllocatedMemorySize (AppDomain total, moves in allocation-context steps)";

    public static long Now() => AppDomain.CurrentDomain.MonitoringTotalAllocatedMemorySize;
#else
    public const string Method = "GC.GetAllocatedBytesForCurrentThread";

    public static long Now() => GC.GetAllocatedBytesForCurrentThread();
#endif
}

/// <summary>
/// The same-code band. At S0 both copies are the 5c5d4a4 code, so every median ratio should sit near 1; the spread of those ratios is
/// the noise floor of this machine and harness. From S1 a ratio counts as a change only when it is outside the band an S0 run measured.
/// </summary>
static class NoiseBand
{
    public const double Low = 0.90, High = 1.10;   // the S0 same-code rule the lead set; the measured band is printed beside it

    public static string Describe(double[] ratios) => string.Format(System.Globalization.CultureInfo.InvariantCulture,
        "same-code band measured: {0:F3} to {1:F3} over {2} rows; target {3:F2} to {4:F2}; rows outside the target: {5}",
        ratios.Min(), ratios.Max(), ratios.Length, Low, High, ratios.Count(r => r < Low || r > High));

    public static bool Inside(double[] ratios) => ratios.All(r => r >= Low && r <= High);
}
