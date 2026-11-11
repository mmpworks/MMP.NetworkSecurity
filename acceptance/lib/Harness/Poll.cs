using System;
using System.Threading;

namespace Acceptance
{
    /// <summary>
    /// A wait that looks first and checks the limit second. A wait that checks the limit first misses a line that came in during its
    /// last sleep, when the thread wakes after the limit: it gives up with the answer already there (Richard on #367, the acceptance
    /// sweep after it). Every harness loop that waits for an answer goes through here. BridgeRun.SettleLogs waits for quiet logs and
    /// goes on after its limit, so it keeps its own loop (Jared on #396).
    /// </summary>
    public static class Poll
    {
        /// <summary>Calls look until it returns a value or the limit passes. The last call always comes after the limit, so a late wake still sees the answer.</summary>
        public static T Until<T>(Func<T> look, int timeoutMs, int stepMs) where T : class
        {
            DateTime end = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            while (true)
            {
                T found = look();
                if (found != null) return found;
                if (DateTime.UtcNow >= end) return null;
                Thread.Sleep(stepMs);
            }
        }

        /// <summary>The same wait for a yes or no look.</summary>
        public static bool Until(Func<bool> look, int timeoutMs, int stepMs)
        {
            return Until(delegate { return look() ? "yes" : null; }, timeoutMs, stepMs) != null;
        }
    }
}
