using System;
using System.Diagnostics;
using System.Linq;

namespace NetSec.Bench;

/// <summary>The numbers for one case: time for each operation in each round, and bytes allocated for each operation.</summary>
sealed class CaseResult
{
    public CaseResult(BenchCase c, double[] nsPerOpRounds, double bytesPerOp, long opsPerRound)
    {
        Case = c;
        NsPerOpRounds = nsPerOpRounds;
        BytesAllocatedPerOp = bytesPerOp;
        OpsPerRound = opsPerRound;
    }

    public BenchCase Case { get; }
    public double[] NsPerOpRounds { get; }
    public double BytesAllocatedPerOp { get; }
    public long OpsPerRound { get; }

    public double MedianNsPerOp => Median(NsPerOpRounds);
    public double MedianNsPerUnit => MedianNsPerOp / Case.UnitsPerOp;
    public double BytesAllocatedPerUnit => BytesAllocatedPerOp / Case.UnitsPerOp;
    public double MegabytesPerSecond => Case.BytesPerOp == 0 ? 0 : Case.BytesPerOp / MedianNsPerOp * 1e9 / (1024 * 1024);

    static double Median(double[] values)
    {
        double[] s = values.OrderBy(v => v).ToArray();
        return s.Length % 2 == 1 ? s[s.Length / 2] : (s[s.Length / 2 - 1] + s[s.Length / 2]) / 2;
    }
}

/// <summary>
/// A plain timing loop. Warm-up runs the operation until the JIT has settled and finds a batch size that lasts about <see cref="BatchTarget"/>.
/// Each round then times whole batches for about <see cref="RoundTarget"/>, and the report keeps every round so a reader sees the spread.
/// Allocation is a separate pass with no timer, read from <see cref="Allocated"/> before and after a fixed number of operations.
/// </summary>
static class Measure
{
    public static readonly TimeSpan BatchTarget = TimeSpan.FromMilliseconds(20);
    public static readonly TimeSpan WarmupTarget = TimeSpan.FromMilliseconds(500);
    public static readonly TimeSpan RoundTarget = TimeSpan.FromMilliseconds(400);
    public const int Rounds = 9;

    public static CaseResult Run(BenchCase c)
    {
        long batch = Warm(c.Op);
        long batchesPerRound = Math.Max(1, (long)(RoundTarget.Ticks / BatchTarget.Ticks));
        double[] rounds = new double[Rounds];
        for (int r = 0; r < Rounds; r++) rounds[r] = TimeRound(c.Op, batch, batchesPerRound);
        double bytesPerOp = AllocatedPerOp(c.Op, batch * batchesPerRound);
        return new CaseResult(c, rounds, bytesPerOp, batch * batchesPerRound);
    }

    /// <summary>Runs the operation for the warm-up time, doubling the batch until one batch lasts at least the batch target. Returns that batch size.</summary>
    static long Warm(Action op)
    {
        long batch = 1;
        Stopwatch total = Stopwatch.StartNew();
        while (true)
        {
            Stopwatch one = Stopwatch.StartNew();
            for (long i = 0; i < batch; i++) op();
            bool longEnough = one.Elapsed >= BatchTarget;
            if (longEnough && total.Elapsed >= WarmupTarget) return batch;
            if (!longEnough) batch *= 2;
        }
    }

    static double TimeRound(Action op, long batch, long batches)
    {
        long ops = batch * batches;
        Stopwatch sw = Stopwatch.StartNew();
        for (long i = 0; i < ops; i++) op();
        sw.Stop();
        return sw.Elapsed.TotalMilliseconds * 1e6 / ops;
    }

    static double AllocatedPerOp(Action op, long ops)
    {
        long before = Allocated.Now();
        for (long i = 0; i < ops; i++) op();
        long after = Allocated.Now();
        return (double)(after - before) / ops;
    }
}

/// <summary>The runtime's own allocated-bytes counter. The two runtimes have different counters, so the report names the one it read.</summary>
static class Allocated
{
#if NETFRAMEWORK
    static Allocated() { AppDomain.MonitoringIsEnabled = true; }

    // The AppDomain counter moves in allocation-context steps of several KB, so a per-operation value is an average over many operations.
    public const string Method = "AppDomain.MonitoringTotalAllocatedMemorySize (AppDomain total, moves in allocation-context steps)";

    public static long Now() => AppDomain.CurrentDomain.MonitoringTotalAllocatedMemorySize;
#else
    public const string Method = "GC.GetAllocatedBytesForCurrentThread";

    public static long Now() => GC.GetAllocatedBytesForCurrentThread();
#endif
}
