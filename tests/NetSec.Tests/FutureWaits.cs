using System;
using System.Threading.Tasks;
using MMP.AsyncProxy;

namespace NetSec.Tests
{
    /// <summary>
    /// Issue #308: a test that waits on a pump's future holds no thread-pool thread while it waits. A blocking Future.Wait parks a pool thread,
    /// and the pumps complete their futures on pool threads, so many parallel tests that block can starve the continuations they wait for.
    /// The Host tests made the same move in d58f4b7 (ProcessWaits.Within).
    /// </summary>
    internal static class FutureWaits
    {
        /// <summary>True when the future completed within the limit. It awaits; it never blocks the calling thread.</summary>
        public static async Task<bool> Within(IFuture future, TimeSpan limit)
        {
            IAwaiter awaiter = future.ContinueOnAnyThread();
            if (awaiter.IsCompleted) return true;
            TaskCompletionSource<bool> done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            awaiter.OnCompleted(() => done.TrySetResult(true));
            Task first = await Task.WhenAny(done.Task, Task.Delay(limit));
            return first == done.Task;
        }
    }
}
