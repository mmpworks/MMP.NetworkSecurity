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

        public static long Measure(Action op)
        {
            for (int i = 0; i < Warm; i++) op();
            long best = long.MaxValue;
            for (int r = 0; r < Rounds; r++)
            {
                long before = GC.GetAllocatedBytesForCurrentThread();
                for (int i = 0; i < Calls; i++) op();
                long used = GC.GetAllocatedBytesForCurrentThread() - before;
                if (used < best) best = used;
            }
            return best;
        }

        /// <summary>Bytes per unit beyond the returned array: (op - new byte[outLen]) / units, both per call. outLen below 0: no array.</summary>
        public static double PerUnit(Action op, int outLen, int units)
        {
            long a = Measure(op);
            long inherent = outLen < 0 ? 0 : Measure(delegate { GC.KeepAlive(new byte[outLen]); });
            return (double)(a - inherent) / Calls / units;
        }

        public static string Judge(string what, double perUnit, string unit)
        {
            if (perUnit > 0) throw new FailException("AO5_ALLOCATES", string.Format("{0}: {1:0.###} B per {2} beyond the returned array (lowest of {3} rounds x {4} calls)", what, perUnit, unit, Rounds, Calls));
            return string.Format("{0}: 0 B per {1} beyond the returned array (lowest of {2} rounds x {3} calls, GC.GetAllocatedBytesForCurrentThread)", what, unit, Rounds, Calls);
        }
    }
}
#endif
