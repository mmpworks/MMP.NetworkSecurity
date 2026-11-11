#if NET
using System;

namespace Acceptance
{
    /// <summary>
    /// The allocation meter of AO-5 (Jared on #405, B1: the suite measures, it does not read the builder's numbers). After a warm-up,
    /// GC.GetAllocatedBytesForCurrentThread is read before and after N calls, and the lowest of 5 rounds counts. An op that must return a
    /// new array has that array's own cost taken off: `new byte[len]` of the same length is measured the same way.
    /// </summary>
    public static class AoAllocMeter
    {
        public const int Warm = 300, Calls = 400, Rounds = 5;

        /// <summary>The lowest and the highest round, each in bytes for Calls calls.</summary>
        public struct Rounds2 { public long Low, High; }

        public static Rounds2 Measure(Action op)
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

        /// <summary>Bytes per unit beyond the returned array, from the lowest and from the highest round.</summary>
        public struct PerUnitResult { public double Low, High; }

        /// <summary>(op - new byte[outLen]) / Calls / units, for the lowest and the highest round of op. outLen below 0: no array.</summary>
        public static PerUnitResult PerUnit(Action op, int outLen, int units)
        {
            Rounds2 a = Measure(op);
            long inherent = outLen < 0 ? 0 : Measure(delegate { GC.KeepAlive(new byte[outLen]); }).Low;
            return new PerUnitResult { Low = (double)(a.Low - inherent) / Calls / units, High = (double)(a.High - inherent) / Calls / units };
        }

        /// <summary>
        /// A 0 B claim is judged on the highest round (Jared on #405, N2): an allocation rarer than once in 400 calls can leave the lowest
        /// round at 0 B, and the highest round still sees it. The detail prints both.
        /// </summary>
        public static string Judge(string what, PerUnitResult p, string unit)
        {
            string both = string.Format("lowest round {0:0.###}, highest round {1:0.###} B per {2}; {3} rounds x {4} calls, GC.GetAllocatedBytesForCurrentThread", p.Low, p.High, unit, Rounds, Calls);
            if (p.High > 0) throw new FailException("AO5_ALLOCATES", what + ": allocates beyond the returned array (" + both + ")");
            return what + ": 0 B per " + unit + " beyond the returned array in every round (" + both + ")";
        }

        public static PerUnitResult Max(PerUnitResult a, PerUnitResult b) { return new PerUnitResult { Low = Math.Max(a.Low, b.Low), High = Math.Max(a.High, b.High) }; }
    }
}
#endif
