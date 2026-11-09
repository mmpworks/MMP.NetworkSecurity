using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>The limits in ProcessWaits hold against a child that runs past them, and the output of a child that ends in time is whole.</summary>
[Collection(BlockingProductCalls.Name)]
public class ProcessWaitsTests
{
    // ping -n 11 runs about 10 s, which is longer than every limit below.
    static Process LongChild() => Process.Start(new ProcessStartInfo("ping", "-n 11 127.0.0.1") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true })!;

    static Process EchoBoth() => Process.Start(new ProcessStartInfo("cmd", "/c echo to-out & echo to-err 1>&2") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true })!;

    [Fact]
    public void ReadAll_stops_at_its_limit_while_the_child_still_writes()
    {
        using Process p = LongChild();
        Stopwatch clock = Stopwatch.StartNew();
        (bool exited, _, _, _) = ProcessWaits.ReadAll(p, TimeSpan.FromSeconds(1));
        clock.Stop();
        Assert.False(exited, "ReadAll reported an exit for a child that runs about 10 s");
        // The guard is that ReadAll stops at its limit and kills the child: exited stays false, and the child is dead below. The wall-clock bound
        // only catches an unbounded wait, so it is the limit plus 9 s, a margin a saturated shared machine cannot cross (#318).
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1 + 9), "ReadAll took " + clock.Elapsed.TotalSeconds.ToString("0.0") + " s with a 1 s limit");
        Assert.True(p.WaitForExit(5000), "ReadAll did not kill the child at its limit");
    }

    [Fact]
    public void ReadAll_returns_both_streams_of_a_child_that_ends_in_time()
    {
        using Process p = EchoBoth();
        (bool exited, int code, string output, string errors) = ProcessWaits.ReadAll(p, TimeSpan.FromSeconds(30));
        Assert.True(exited);
        Assert.Equal(0, code);
        Assert.Contains("to-out", output);
        Assert.Contains("to-err", errors);
    }

    [Fact]
    public async Task Collect_stops_at_its_limit_and_kills_the_child()
    {
        using Process p = LongChild();
        Stopwatch clock = Stopwatch.StartNew();
        (bool exited, _, _, _) = await ProcessWaits.Collect(p, TimeSpan.FromSeconds(1));
        clock.Stop();
        Assert.False(exited);
        // The guard is that Collect stops at its limit and kills the child: exited stays false, and the child is dead below. The wall-clock bound
        // only catches an unbounded wait, so it is the limit plus 9 s, a margin a saturated shared machine cannot cross (#318).
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1 + 9), "Collect took " + clock.Elapsed.TotalSeconds.ToString("0.0") + " s with a 1 s limit");
        Assert.True(p.HasExited || p.WaitForExit(5000), "Collect did not kill the child at its limit");
    }

    [Fact]
    public async Task Within_returns_a_ready_result_and_still_times_out_on_a_promise_nobody_sets()
    {
        TaskCompletionSource<int> set = new(TaskCreationOptions.RunContinuationsAsynchronously);
        _ = Task.Run(async () => { await Task.Delay(100); set.TrySetResult(7); });
        Assert.Equal(7, await ProcessWaits.Within(set.Task, TimeSpan.FromSeconds(10)));

        TaskCompletionSource<int> never = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Stopwatch clock = Stopwatch.StartNew();
        await Assert.ThrowsAsync<TimeoutException>(() => ProcessWaits.Within(never.Task, TimeSpan.FromMilliseconds(300)));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), "Within took " + clock.Elapsed.TotalSeconds.ToString("0.0") + " s with a 0.3 s limit");

        TaskCompletionSource noResult = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await Assert.ThrowsAsync<TimeoutException>(() => ProcessWaits.Within(noResult.Task, TimeSpan.FromMilliseconds(300)));
        noResult.SetResult();
        await ProcessWaits.Within(noResult.Task, TimeSpan.FromMilliseconds(300));
    }
}
