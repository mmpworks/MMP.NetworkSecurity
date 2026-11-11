using System;

namespace Acceptance
{
    /// <summary>
    /// The allocation meter of AO-5 (Jared on #405, B1: the suite measures, it does not read the builder's numbers).
    ///
    /// net10: GC.GetAllocatedBytesForCurrentThread is read before and after 400 calls, after 300 warm-up calls, in 5 rounds. A 0 B claim
    /// is judged on the highest round (Jared on #405, N2); the detail prints the lowest and the highest.
    ///
    /// cf (the CF binaries on the net48 desktop CLR): .NET Framework 4.8 has no per-thread counter. The meter reads
    /// AppDomain.CurrentDomain.MonitoringTotalAllocatedMemorySize over one long run on one thread. The counter moves in 8,192-byte steps
    /// (spike 2026-11-11: a byte[16] once per 1000 calls is unseen at 100,000 calls and seen at 300,000), so the cf rows judge zero against
    /// not zero only, and the detail states the limit: an allocation total under 8,192 B over the run is unseen. Budgets above 0 are judged
    /// on net10 only.
    ///
    /// An op that must return a new array has that array's own cost taken off: `new byte[len]` of the same length is measured the same way.
    /// </summary>
    public static class AoAllocMeter
    {
        public const int Warm = 300, Calls = 400, Rounds = 5;
        /// <summary>cf: the run covers this many block-sized units (1,000,000 calls of a one-block op).</summary>
        public const int CfUnits = 1000000;
        public const long CfStep = 8192;

        public struct PerUnitResult
        {
            public double Low, High;
            public bool Coarse;          // cf: the counter moves in CfStep steps
            public long CfCalls;         // cf: calls in the run
        }

        public static bool OnCf
        {
            get
            {
#if NET
                return false;
#else
                return true;
#endif
            }
        }

#if NET
        struct Rounds2 { public long Low, High; }

        static Rounds2 MeasureNet(Action op)
        {
            for (int i = 0; i < Warm; i++) op();
            Rounds2 r2 = new Rounds2 { Low = long.MaxValue, High = long.MinValue };
            for (int r = 0; r < Rounds; r++)
            {
                long before = GC.GetAllocatedBytesForCurrentThread();
                for (int i = 0; i < Calls; i++) op();
                long used = GC.GetAllocatedBytesForCurrentThread() - before;
                if (used < r2.Low) r2.Low = used;
                if (used > r2.High) r2.High = used;
            }
            return r2;
        }
#else
        static long MeasureCf(Action op, long calls)
        {
            AppDomain.MonitoringIsEnabled = true;
            for (int i = 0; i < 2000; i++) op();
            long before = AppDomain.CurrentDomain.MonitoringTotalAllocatedMemorySize;
            for (long i = 0; i < calls; i++) op();
            return AppDomain.CurrentDomain.MonitoringTotalAllocatedMemorySize - before;
        }
#endif

        /// <summary>(op - new byte[outLen]) per call, per unit. outLen below 0: no array. units: blocks (or 1) in one call.</summary>
        public static PerUnitResult PerUnit(Action op, int outLen, int units)
        {
#if NET
            Rounds2 a = MeasureNet(op);
            long inherent = outLen < 0 ? 0 : MeasureNet(delegate { GC.KeepAlive(new byte[outLen]); }).Low;
            return new PerUnitResult { Low = (double)(a.Low - inherent) / Calls / units, High = (double)(a.High - inherent) / Calls / units };
#else
            long calls = Math.Max(10000, CfUnits / Math.Max(1, units));
            long a = MeasureCf(op, calls);
            long inherent = outLen < 0 ? 0 : MeasureCf(delegate { GC.KeepAlive(new byte[outLen]); }, calls);
            // Two coarse readings: with a returned array, a difference within one counter step is the step, not the op.
            long excess = a - inherent, tolerance = outLen < 0 ? 0 : CfStep;
            double per = excess > tolerance ? (double)excess / calls / units : 0;
            return new PerUnitResult { Low = per, High = per, Coarse = true, CfCalls = calls };
#endif
        }

        public static PerUnitResult Max(PerUnitResult a, PerUnitResult b)
        {
            return new PerUnitResult { Low = Math.Max(a.Low, b.Low), High = Math.Max(a.High, b.High), Coarse = a.Coarse || b.Coarse, CfCalls = Math.Max(a.CfCalls, b.CfCalls) };
        }

        static string Both(PerUnitResult p, string unit)
        {
            if (p.Coarse)
                return string.Format("{0:0.###} B per {1}; one run of {2} calls, AppDomain.MonitoringTotalAllocatedMemorySize in {3} B steps, so a total under {3} B is unseen", p.High, unit, p.CfCalls, CfStep);
            return string.Format("lowest round {0:0.###}, highest round {1:0.###} B per {2}; {3} rounds x {4} calls, GC.GetAllocatedBytesForCurrentThread", p.Low, p.High, unit, Rounds, Calls);
        }

        /// <summary>
        /// Judged on the highest round against the budget (0 when acceptance/ao-budgets.tsv has no line). At or under: PASS. Over: FAIL
        /// AO5_ALLOCATES with both numbers (Jared's condition 2 for the budget file). On cf a budget above 0 is judged on net10 only.
        /// </summary>
        public static string Judge(string what, PerUnitResult p, string unit, double budget)
        {
            string both = Both(p, unit);
            if (p.Coarse && budget > 0) return what + ": budget " + budget + " B per " + unit + " is judged on net10 only; here " + both;
            if (p.High > budget)
                throw new FailException("AO5_ALLOCATES", what + ": " + p.High.ToString("0.###") + " B per " + unit + " beyond the returned array, budget " + budget + " B (" + both + ")");
            return what + ": " + (budget > 0 ? "within the budget of " + budget + " B per " + unit : "0 B per " + unit + " beyond the returned array") + " (" + both + ")";
        }

        public static string Judge(string what, PerUnitResult p, string unit) { return Judge(what, p, unit, 0); }
    }
}
