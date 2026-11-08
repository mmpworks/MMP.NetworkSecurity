using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NetSec.Io;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// Runs alone, because it caps the process's thread pool for its duration (issue #308).
    /// </summary>
    [CollectionDefinition("Core starvation", DisableParallelization = true)]
    public class CoreStarvationCollection { }

    /// <summary>
    /// Issue #308. A test that blocks a pool thread in Future.Wait while a pump completes that future on another pool thread can starve when
    /// many such tests run at once: every pool thread waits, and no thread is left to run the continuations. This caps the pool at the core
    /// count and starts 2 more copies of the SSH factory test than that, all at once. They must all finish in 30 s, which they do only if no
    /// copy holds a pool thread while it waits.
    /// </summary>
    [Collection("Core starvation")]
    public class CoreStarvationTests
    {
        [Fact]
        public async Task Pump_tests_that_wait_hold_no_pool_thread_so_a_full_pool_still_finishes()
        {
            ThreadPool.GetMaxThreads(out int workers, out int io);
            ThreadPool.GetMinThreads(out int minWorkers, out int minIo);
            int cap = Environment.ProcessorCount;
            Assert.True(ThreadPool.SetMinThreads(Math.Min(minWorkers, cap), minIo), "the pool's minimum could not be lowered to the cap");
            Assert.True(ThreadPool.SetMaxThreads(cap, io), "the pool could not be capped");
            try
            {
                Task[] copies = Enumerable.Range(0, cap + 2).Select(i => Task.Run(() => SshTests.FactoryExec(i % 2 == 0 ? SshSuite.Modern : SshSuite.Legacy))).ToArray();
                Task all = Task.WhenAll(copies);
                Task first = await Task.WhenAny(all, Task.Delay(TimeSpan.FromSeconds(30)));
                if (first != all)
                {
                    // Tell starvation from a hang (the lead's question on #308): lift the cap, let the pool add threads fast, and wait 60 s more.
                    // If every copy then finishes, it was starvation: slow, but it heals. If some never finish with threads to spare, it is a hang.
                    int stuck = copies.Count(c => !c.IsCompleted);
                    ThreadPool.SetMaxThreads(workers, io);
                    ThreadPool.SetMinThreads(Math.Max(minWorkers, cap * 8), minIo);
                    Task after = await Task.WhenAny(all, Task.Delay(TimeSpan.FromSeconds(60)));
                    string shape = after == all
                        ? "STARVATION: all finished once the cap was lifted"
                        : $"HANG: {copies.Count(c => !c.IsCompleted)} still unfinished 60 s after the cap was lifted";
                    Assert.Fail($"{stuck} of {copies.Length} copies had not finished after 30 s on a pool capped at {cap} threads. {shape}.");
                }
                await all;
            }
            finally
            {
                ThreadPool.SetMaxThreads(workers, io);
                ThreadPool.SetMinThreads(minWorkers, minIo);
            }
        }
    }
}
